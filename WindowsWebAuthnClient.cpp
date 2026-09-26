#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <webauthn.h>

#include <cstdio>

#include "WindowsWebAuthnClient.h"

namespace
{
  constexpr DWORD TIMEOUT_MS = 60000;

  std::wstring ToWide(const std::string& s)
  {
    if (s.empty())
    {
      return {};
    }
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
  }

  std::string ToUtf8(PCWSTR w)
  {
    if (w == nullptr)
    {
      return {};
    }
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1)
    {
      return {};
    }
    std::string s(n - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
    return s;
  }

  std::string ErrorText(HRESULT hr)
  {
    char code[16];
    snprintf(code, sizeof(code), "0x%08lx", static_cast<unsigned long>(hr));
    std::string name = ToUtf8(WebAuthNGetErrorName(hr)) + ", " + code;

    // webauthn.dll maps most user-facing failures onto a few NTE_* codes
    switch (hr)
    {
    case NTE_USER_CANCELLED:  return "Cancelled by the user or timed out. (" + name + ")";
    case NTE_NOT_FOUND:       return "No matching credential on this authenticator. (" + name + ")";
    case NTE_EXISTS:          return "Credential already registered on this authenticator. (" + name + ")";
    case NTE_NOT_SUPPORTED:   return "Not supported by the authenticator. (" + name + ")";
    case NTE_TOKEN_KEYSET_STORAGE_FULL: return "Authenticator storage is full. (" + name + ")";
    default:                  return name;
    }
  }

  FidoError ApiError(const char* call, HRESULT hr)
  {
    std::string text = ErrorText(hr);
    return { std::string(call) + ": " + text, text, {} };
  }

  std::string TransportName(DWORD transport)
  {
    std::string s;
    auto add = [&s](const char* name) { s += s.empty() ? name : std::string(", ") + name; };
    if (transport & WEBAUTHN_CTAP_TRANSPORT_USB)
    {
      add("USB");
    }
    if (transport & WEBAUTHN_CTAP_TRANSPORT_NFC)
    {
      add("NFC");
    }
    if (transport & WEBAUTHN_CTAP_TRANSPORT_BLE)
    {
      add("BLE");
    }
    if (transport & WEBAUTHN_CTAP_TRANSPORT_TEST)
    {
      add("TEST");
    }
    if (transport & WEBAUTHN_CTAP_TRANSPORT_INTERNAL)
    {
      add("INTERNAL (platform)");
    }
    if (transport & WEBAUTHN_CTAP_TRANSPORT_HYBRID)
    {
      add("HYBRID (phone)");
    }
    return s.empty() ? "unknown" : s;
  }

  std::vector<uint8_t> Bytes(const BYTE* p, DWORD len)
  {
    return p ? std::vector<uint8_t>(p, p + len) : std::vector<uint8_t>{};
  }

  // webauthn.dll centers its dialog on this window (libfido2's winhello backend does the same)
  HWND OwnerWindow()
  {
    return GetForegroundWindow();
  }

  DWORD Attachment(bool roamingOnly)
  {
    return roamingOnly ? WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM : WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY;
  }

  DWORD UserVerification(bool requireUv)
  {
    return requireUv ? WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED : WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED;
  }
}

WindowsWebAuthnClient::WindowsWebAuthnClient(bool roamingOnly)
  : m_roamingOnly(roamingOnly)
{
}

uint32_t WindowsWebAuthnClient::ApiVersion()
{
  return WebAuthNGetApiVersionNumber();
}

std::string WindowsWebAuthnClient::Description() const
{
  return "windows://hello -> webauthn.dll directly (API v" + std::to_string(ApiVersion()) + ")" +
    (m_roamingOnly ? ", security keys only" : "");
}

bool WindowsWebAuthnClient::MakeCredential(const RegistrationOptions& options, const std::string& clientDataJson,
  RegistrationResponse& response, FidoError& error)
{
  std::wstring wRpId = ToWide(options.rpId);
  std::wstring wRpName = ToWide(options.rpName);
  std::wstring wUserName = ToWide(options.userName);
  std::vector<BYTE> uid(options.userId.begin(), options.userId.end());
  std::vector<BYTE> cd(clientDataJson.begin(), clientDataJson.end());

  WEBAUTHN_RP_ENTITY_INFORMATION rp{};
  rp.dwVersion = WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION;
  rp.pwszId = wRpId.c_str();
  rp.pwszName = wRpName.c_str();

  WEBAUTHN_USER_ENTITY_INFORMATION user{};
  user.dwVersion = WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION;
  user.cbId = static_cast<DWORD>(uid.size());
  user.pbId = uid.data();
  user.pwszName = wUserName.c_str();
  user.pwszDisplayName = wUserName.c_str();

  WEBAUTHN_COSE_CREDENTIAL_PARAMETER alg{};
  alg.dwVersion = WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION;
  alg.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
  alg.lAlg = WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256;
  WEBAUTHN_COSE_CREDENTIAL_PARAMETERS algs{};
  algs.cCredentialParameters = 1;
  algs.pCredentialParameters = &alg;

  WEBAUTHN_CLIENT_DATA clientData{};
  clientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
  clientData.cbClientDataJSON = static_cast<DWORD>(cd.size());
  clientData.pbClientDataJSON = cd.data();
  clientData.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;

  // Version 1 already has everything we need and works on every webauthn.dll (Windows 10 1903+)
  WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS opt{};
  opt.dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_1;
  opt.dwTimeoutMilliseconds = TIMEOUT_MS;
  opt.dwAuthenticatorAttachment = Attachment(m_roamingOnly);
  opt.bRequireResidentKey = options.residentKey;
  opt.dwUserVerificationRequirement = UserVerification(options.userVerification);
  opt.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT;

  PWEBAUTHN_CREDENTIAL_ATTESTATION att = nullptr;
  HRESULT hr = WebAuthNAuthenticatorMakeCredential(OwnerWindow(), &rp, &user, &algs, &clientData, &opt, &att);
  if (FAILED(hr))
  {
    error = ApiError("WebAuthNAuthenticatorMakeCredential", hr);
    return false;
  }

  response.clientDataJson = clientDataJson;
  response.format = ToUtf8(att->pwszFormatType);
  response.authData = Bytes(att->pbAuthenticatorData, att->cbAuthenticatorData);
  response.attStmt = Bytes(att->pbAttestation, att->cbAttestation);
  if (att->dwVersion >= WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_3 && att->dwUsedTransport != 0)
  {
    response.transport = TransportName(att->dwUsedTransport);
  }
  WebAuthNFreeCredentialAttestation(att);
  return true;
}

bool WindowsWebAuthnClient::GetAssertion(const AuthenticationOptions& options, const std::string& clientDataJson,
  std::vector<AssertionResponse>& responses, FidoError& error)
{
  std::wstring wRpId = ToWide(options.rpId);
  std::vector<BYTE> cd(clientDataJson.begin(), clientDataJson.end());

  WEBAUTHN_CLIENT_DATA clientData{};
  clientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
  clientData.cbClientDataJSON = static_cast<DWORD>(cd.size());
  clientData.pbClientDataJSON = cd.data();
  clientData.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;

  std::vector<WEBAUTHN_CREDENTIAL> creds;
  for (const auto& id : options.allowCredentials)
  {
    WEBAUTHN_CREDENTIAL c{};
    c.dwVersion = WEBAUTHN_CREDENTIAL_CURRENT_VERSION;
    c.cbId = static_cast<DWORD>(id.size());
    c.pbId = const_cast<PBYTE>(id.data());  // not modified by webauthn.dll
    c.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
    creds.push_back(c);
  }

  WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS opt{};
  opt.dwVersion = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_1;
  opt.dwTimeoutMilliseconds = TIMEOUT_MS;
  opt.CredentialList.cCredentials = static_cast<DWORD>(creds.size());
  opt.CredentialList.pCredentials = creds.empty() ? nullptr : creds.data();
  opt.dwAuthenticatorAttachment = Attachment(m_roamingOnly);
  opt.dwUserVerificationRequirement = UserVerification(options.userVerification);

  PWEBAUTHN_ASSERTION assertion = nullptr;
  HRESULT hr = WebAuthNAuthenticatorGetAssertion(OwnerWindow(), wRpId.c_str(), &clientData, &opt, &assertion);
  if (FAILED(hr))
  {
    error = ApiError("WebAuthNAuthenticatorGetAssertion", hr);
    return false;
  }

  // Windows lets the user pick one account, so there is always exactly one assertion
  AssertionResponse a;
  a.credentialId = Bytes(assertion->Credential.pbId, assertion->Credential.cbId);
  a.clientDataJson = clientDataJson;
  a.authData = Bytes(assertion->pbAuthenticatorData, assertion->cbAuthenticatorData);
  a.signature = Bytes(assertion->pbSignature, assertion->cbSignature);
  a.userHandle = Bytes(assertion->pbUserId, assertion->cbUserId);
  responses.push_back(std::move(a));
  WebAuthNFreeAssertion(assertion);
  return true;
}
