#pragma once

// Persistent store for registered FIDO2 credentials - the relying party's side of WebAuthn.
//
// A server needs exactly this per credential to verify later sign-ins: the credential id (to build
// the allow list and to find the entry again), the public key (to verify the signature) and the last
// signature counter (to detect cloned authenticators). Everything else is informational.
//
// FidoDemo only depends on this interface. CredentialStore implements it with a text file; a
// database or a REST backend would be another implementation without touching the FIDO code.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct StoredCredential
{
  std::string rpId;                  // relying party, e.g. "example.phraselock.com"
  std::string userName;
  std::vector<uint8_t> userId;       // random user handle sent to the authenticator as user.id
  std::vector<uint8_t> credentialId; // chosen by the authenticator
  std::vector<uint8_t> publicKey;    // ES256 (ECDSA P-256) public key, x || y (64 bytes)
  std::vector<uint8_t> aaguid;       // authenticator model id (16 bytes, zero if not disclosed)
  uint32_t signCount = 0;            // last seen signature counter (clone detection)
  std::string created;               // "YYYY-MM-DD HH:MM:SS", local time
};

class ICredentialStore
{
public:
  virtual ~ICredentialStore() = default;

  // Where the credentials are kept, for display (UTF-8)
  virtual std::string Location() const = 0;

  virtual size_t Count() const = 0;

  virtual std::vector<StoredCredential> FindByRpId(const std::string& rpId) const = 0;
  virtual std::optional<StoredCredential> FindById(const std::vector<uint8_t>& credentialId) const = 0;

  // The modifying methods persist immediately and return false if that failed.

  // Adds a credential; an existing entry with the same credential id is replaced
  virtual bool Add(const StoredCredential& cred) = 0;
  virtual bool UpdateSignCount(const std::vector<uint8_t>& credentialId, uint32_t signCount) = 0;
  virtual bool Remove(const std::vector<uint8_t>& credentialId) = 0;
};
