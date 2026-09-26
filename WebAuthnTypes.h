#pragma once

// Data exchanged between the relying party (server) and the client, modelled after the objects
// of the WebAuthn API. When the relying party is an application's backend they travel as JSON over
// the network; in this demo RelyingParty and the IAuthenticatorClient implementations run in the
// same process, but only talk to each other through these structs.

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

// Log callback - every component explains what it does through it
using LogFn = std::function<void(const std::string&)>;

// PublicKeyCredentialCreationOptions (server -> client)
struct RegistrationOptions
{
  std::string rpId;                  // e.g. "security.mycompany.com"
  std::string rpName;
  std::vector<uint8_t> userId;       // random user handle, becomes user.id on the authenticator
  std::string userName;
  std::vector<uint8_t> challenge;    // random, must come back signed inside clientDataJSON
  bool residentKey = false;          // true = discoverable credential required, false = discouraged
  bool userVerification = false;     // true = required (PIN / biometrics), false = discouraged
};

// AuthenticatorAttestationResponse (client -> server)
struct RegistrationResponse
{
  std::string clientDataJson;
  std::vector<uint8_t> authData;     // raw authenticatorData, see AuthData.h
  std::string format;                // attestation statement format: "packed", "fido-u2f", "none", ...
  std::vector<uint8_t> attStmt;      // CBOR encoded attestation statement
  std::string transport;             // how the authenticator was reached, if known (informational)
};

// PublicKeyCredentialRequestOptions (server -> client)
struct AuthenticationOptions
{
  std::string rpId;
  std::vector<uint8_t> challenge;
  std::vector<std::vector<uint8_t>> allowCredentials;  // empty = let the authenticator pick a discoverable credential
  bool userVerification = false;
};

// AuthenticatorAssertionResponse (client -> server). With an empty allow list an authenticator
// may return one assertion per matching discoverable credential.
struct AssertionResponse
{
  std::vector<uint8_t> credentialId;
  std::string clientDataJson;
  std::vector<uint8_t> authData;     // raw authenticatorData, see AuthData.h
  std::vector<uint8_t> signature;    // DER encoded ECDSA signature over authData || SHA-256(clientDataJSON)
  std::vector<uint8_t> userHandle;   // user.id - returned for discoverable credentials
  std::string userName;              // returned by some authenticators only (informational)
};

// Failure of a client or relying party step
struct FidoError
{
  std::string logText;               // technical, for the log
  std::string reason;                // human readable, for the result dialog
  std::string hint;                  // optional: what the user can do about it
};
