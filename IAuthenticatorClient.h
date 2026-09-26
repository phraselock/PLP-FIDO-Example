#pragma once

// The client side of WebAuthn: passes the server's options and the clientDataJSON to an
// authenticator and returns what the authenticator produced - without judging it. Verifying the
// result is the relying party's job (see RelyingParty).
//
// Implementations:
//   LibFido2Client         libfido2 - direct HID access (needs admin rights on Windows)
//                          or libfido2's Windows Hello backend ("windows://hello")
//   WindowsWebAuthnClient  Windows WebAuthn API (webauthn.dll) called directly

#include <string>
#include <vector>

#include "WebAuthnTypes.h"

class IAuthenticatorClient
{
public:
  virtual ~IAuthenticatorClient() = default;

  // One line for the log, e.g. "direct HID: \\?\hid#vid_1050..."
  virtual std::string Description() const = 0;

  // authenticatorMakeCredential - creates a new credential
  virtual bool MakeCredential(const RegistrationOptions& options, const std::string& clientDataJson,
    RegistrationResponse& response, FidoError& error) = 0;

  // authenticatorGetAssertion - signs the challenge with an existing credential
  virtual bool GetAssertion(const AuthenticationOptions& options, const std::string& clientDataJson,
    std::vector<AssertionResponse>& responses, FidoError& error) = 0;
};
