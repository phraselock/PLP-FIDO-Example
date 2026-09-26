#pragma once

// The relying party (server) side of WebAuthn: creates challenges, verifies what the client sends
// back and keeps the registered credentials in an ICredentialStore.
//
// Platform independent - only libfido2 (verification) and OpenSSL (random, certificates) are used,
// so this class can be lifted into a server. Every check is explained through the log callback.
//
// A real server keeps the options of Begin*() in the user's session until the matching
// Verify*() call; this demo simply passes them back in.

#include <cstdint>
#include <string>
#include <vector>

#include "ICredentialStore.h"
#include "WebAuthnTypes.h"

struct RegistrationResult
{
  StoredCredential credential;       // ready to be stored
  bool userVerified = false;         // UV flag
  std::string attestation;           // e.g. "packed - signature valid" or "none"
};

struct AuthenticationResult
{
  std::string userName;
  std::vector<uint8_t> credentialId;
  uint32_t signCount = 0;
  bool userVerified = false;         // UV flag
};

class RelyingParty
{
public:
  // The store must outlive this object
  RelyingParty(ICredentialStore& store, std::string rpName);

  // --- registration ---

  // Step 1: random challenge and user handle
  RegistrationOptions BeginRegistration(const std::string& rpId, const std::string& userName,
    bool residentKey, bool userVerification) const;

  // Step 4: clientDataJSON (type, challenge, origin), rpIdHash, flags, attestation signature
  bool VerifyRegistration(const RegistrationOptions& options, const RegistrationResponse& response,
    const LogFn& log, RegistrationResult& result, FidoError& error) const;

  // Step 5
  bool StoreCredential(StoredCredential& credential, FidoError& error);

  // --- authentication ---

  // The credentials registered for rpId - the allow list for a sign-in without discoverable credential
  std::vector<StoredCredential> CredentialsFor(const std::string& rpId) const;

  // Step 1: random challenge; allow list from the store unless a discoverable credential is requested
  AuthenticationOptions BeginAuthentication(const std::string& rpId, bool discoverable, bool userVerification) const;

  // Step 4 for one assertion: known credential, clientDataJSON, rpIdHash, flags, signature counter, signature.
  // Updates the stored signature counter on success.
  bool VerifyAssertion(const AuthenticationOptions& options, const AssertionResponse& response,
    const LogFn& log, AuthenticationResult& result, FidoError& error);

  // The origin clientDataJSON must contain. A web server knows its own origin; this demo acts as its
  // own website and derives it from the RP ID (the client side does the same, see FidoDemo).
  static std::string ExpectedOrigin(const std::string& rpId);

  std::string StoreLocation() const;
  size_t StoreCount() const;

private:
  ICredentialStore& m_store;
  std::string m_rpName;
};
