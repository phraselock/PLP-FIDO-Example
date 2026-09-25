#pragma once

// ICredentialStore implementation backed by a human readable text file in
// %APPDATA%\PhraseLock\PLP-FIDO-Example\credentials.txt (format: see CredentialStore.cpp).

#include "ICredentialStore.h"

class CredentialStore : public ICredentialStore
{
public:
  // Loads all credentials from the file (an empty store if nothing was saved yet)
  CredentialStore();

  std::string Location() const override;
  size_t Count() const override;

  std::vector<StoredCredential> FindByRpId(const std::string& rpId) const override;
  std::optional<StoredCredential> FindById(const std::vector<uint8_t>& credentialId) const override;

  // The in-memory state is updated even if persisting fails
  bool Add(const StoredCredential& cred) override;
  bool UpdateSignCount(const std::vector<uint8_t>& credentialId, uint32_t signCount) override;
  bool Remove(const std::vector<uint8_t>& credentialId) override;

  // Entries that could not be read on load (missing fields, invalid hex) and were skipped
  size_t SkippedOnLoad() const;

private:
  void Load();
  bool Save() const;

  std::wstring m_path;
  std::vector<StoredCredential> m_credentials;
  size_t m_skipped = 0;
};
