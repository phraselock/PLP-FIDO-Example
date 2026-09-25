#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shlobj.h>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>

#include "CredentialStore.h"

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

// File format (UTF-8 text, one [credential] block per entry, binary values as hex):
//
//   [credential]
//   rpId         = example.phraselock.com
//   userName     = alice
//   userId       = 3f2a1b9c...
//   credentialId = a17c55e0...
//   publicKey    = e1d2...
//   aaguid       = 2fc0579f811347eab116bb5a8db9202a
//   signCount    = 5
//   created      = 2026-09-25 14:32:10
//
// Lines starting with '#' are comments. Unknown keys are ignored, so the format can be extended.

namespace fs = std::filesystem;

namespace
{
  constexpr wchar_t STORE_DIR[] = L"PhraseLock\\PLP-FIDO-Example";
  constexpr wchar_t STORE_FILE[] = L"credentials.txt";

  const char FILE_HEADER[] =
    "# PLP FIDO Example - credential store\n"
    "#\n"
    "# One [credential] block per registered credential. Binary values are hex:\n"
    "#   userId       random user handle, sent to the authenticator as user.id\n"
    "#   credentialId chosen by the authenticator, sent back in the allow list on sign-in\n"
    "#   publicKey    ES256 (ECDSA P-256) public key, x || y (64 bytes) - verifies sign-in signatures\n"
    "#   aaguid       authenticator model id (16 bytes, all zero if not disclosed)\n"
    "# signCount is the last signature counter seen (decimal) - it must increase on every sign-in,\n"
    "# otherwise the authenticator may have been cloned.\n";

  std::string ToHex(const std::vector<uint8_t>& v)
  {
    static const char digits[] = "0123456789abcdef";
    std::string s;
    s.reserve(v.size() * 2);
    for (uint8_t b : v)
    {
      s += digits[b >> 4];
      s += digits[b & 0x0f];
    }
    return s;
  }

  bool FromHex(const std::string& s, std::vector<uint8_t>& out)
  {
    auto nibble = [](char c) -> int
    {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      if (c >= 'A' && c <= 'F') return c - 'A' + 10;
      return -1;
    };
    if (s.size() % 2 != 0)
      return false;
    out.clear();
    for (size_t i = 0; i < s.size(); i += 2)
    {
      int hi = nibble(s[i]), lo = nibble(s[i + 1]);
      if (hi < 0 || lo < 0)
        return false;
      out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
  }

  std::string Trim(const std::string& s)
  {
    size_t b = s.find_first_not_of(" \t\n");
    if (b == std::string::npos)
      return {};
    size_t e = s.find_last_not_of(" \t\n");
    return s.substr(b, e - b + 1);
  }

  std::wstring StorePath()
  {
    PWSTR appData = nullptr;
    std::wstring path;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appData)))
      path = std::wstring(appData) + L"\\" + STORE_DIR + L"\\" + STORE_FILE;
    CoTaskMemFree(appData);
    return path;
  }

  bool ParseUInt32(const std::string& s, uint32_t& out)
  {
    if (s.empty() || s.size() > 10 || !std::all_of(s.begin(), s.end(), [](unsigned char ch) { return std::isdigit(ch) != 0; }))
      return false;
    unsigned long long v = std::stoull(s);
    if (v > 0xFFFFFFFFull)
      return false;
    out = static_cast<uint32_t>(v);
    return true;
  }

  // Parses one [credential] block; returns false if a required field is missing or invalid
  bool ParseCredential(const std::vector<std::pair<std::string, std::string>>& fields, StoredCredential& c)
  {
    bool ok = true;
    for (const auto& [key, value] : fields)
    {
      if (key == "rpId") c.rpId = value;
      else if (key == "userName") c.userName = value;
      else if (key == "userId") ok &= FromHex(value, c.userId);
      else if (key == "credentialId") ok &= FromHex(value, c.credentialId);
      else if (key == "publicKey") ok &= FromHex(value, c.publicKey);
      else if (key == "aaguid") ok &= FromHex(value, c.aaguid);
      else if (key == "signCount") ok &= ParseUInt32(value, c.signCount);
      else if (key == "created") c.created = value;
    }
    return ok && !c.rpId.empty() && !c.credentialId.empty() && !c.publicKey.empty();
  }
}

CredentialStore::CredentialStore()
  : m_path(StorePath())
{
  Load();
}

std::string CredentialStore::Location() const
{
  std::u8string s = fs::path(m_path).u8string();
  return std::string(s.begin(), s.end());
}

size_t CredentialStore::Count() const
{
  return m_credentials.size();
}

size_t CredentialStore::SkippedOnLoad() const
{
  return m_skipped;
}

std::vector<StoredCredential> CredentialStore::FindByRpId(const std::string& rpId) const
{
  std::vector<StoredCredential> result;
  for (const auto& c : m_credentials)
    if (c.rpId == rpId)
      result.push_back(c);
  return result;
}

std::optional<StoredCredential> CredentialStore::FindById(const std::vector<uint8_t>& credentialId) const
{
  for (const auto& c : m_credentials)
    if (c.credentialId == credentialId)
      return c;
  return std::nullopt;
}

bool CredentialStore::Add(const StoredCredential& cred)
{
  auto it = std::find_if(m_credentials.begin(), m_credentials.end(),
    [&](const StoredCredential& c) { return c.credentialId == cred.credentialId; });
  if (it != m_credentials.end())
    *it = cred;
  else
    m_credentials.push_back(cred);
  return Save();
}

bool CredentialStore::UpdateSignCount(const std::vector<uint8_t>& credentialId, uint32_t signCount)
{
  for (auto& c : m_credentials)
    if (c.credentialId == credentialId)
      c.signCount = signCount;
  return Save();
}

bool CredentialStore::Remove(const std::vector<uint8_t>& credentialId)
{
  m_credentials.erase(std::remove_if(m_credentials.begin(), m_credentials.end(),
    [&](const StoredCredential& c) { return c.credentialId == credentialId; }), m_credentials.end());
  return Save();
}

void CredentialStore::Load()
{
  m_credentials.clear();
  m_skipped = 0;

  std::ifstream in{ fs::path(m_path) };
  if (!in)
    return;  // nothing saved yet

  std::vector<std::pair<std::string, std::string>> fields;
  bool inBlock = false;
  auto finishBlock = [&]()
  {
    if (inBlock)
    {
      StoredCredential c;
      if (ParseCredential(fields, c))
        m_credentials.push_back(std::move(c));
      else
        m_skipped++;
    }
    fields.clear();
  };

  std::string line;
  while (std::getline(in, line))
  {
    if (line.rfind("\xEF\xBB\xBF", 0) == 0)  // UTF-8 BOM, e.g. after editing with Notepad
      line.erase(0, 3);
    line = Trim(line);
    if (line.empty() || line[0] == '#')
      continue;
    if (line == "[credential]")
    {
      finishBlock();
      inBlock = true;
      continue;
    }
    size_t eq = line.find('=');
    if (inBlock && eq != std::string::npos)
      fields.emplace_back(Trim(line.substr(0, eq)), Trim(line.substr(eq + 1)));
  }
  finishBlock();
}

bool CredentialStore::Save() const
{
  if (m_path.empty())
    return false;

  // Write to a temporary file first and then replace the store, so a crash never leaves a half-written file
  fs::path target(m_path);
  fs::path temp = target;
  temp += L".tmp";

  std::error_code ec;
  fs::create_directories(target.parent_path(), ec);

  {
    std::ofstream out(temp, std::ios::trunc);  // text mode: "\n" is written as CRLF
    if (!out)
      return false;
    out << FILE_HEADER;
    for (const auto& c : m_credentials)
    {
      out << "\n[credential]\n"
        << "rpId         = " << c.rpId << "\n"
        << "userName     = " << c.userName << "\n"
        << "userId       = " << ToHex(c.userId) << "\n"
        << "credentialId = " << ToHex(c.credentialId) << "\n"
        << "publicKey    = " << ToHex(c.publicKey) << "\n"
        << "aaguid       = " << ToHex(c.aaguid) << "\n"
        << "signCount    = " << c.signCount << "\n"
        << "created      = " << c.created << "\n";
    }
    if (!out.flush())
      return false;
  }

  fs::rename(temp, target, ec);  // replaces an existing file
  return !ec;
}
