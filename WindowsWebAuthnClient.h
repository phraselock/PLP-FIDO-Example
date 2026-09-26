#pragma once

// IAuthenticatorClient implementation calling the Windows WebAuthn API (webauthn.dll, Windows 10 1903+)
// directly - the same API every browser on Windows uses.
//
// Works without admin rights: Windows talks to the authenticator and shows its own dialogs (PIN,
// touch, account selection). Unlike libfido2's Windows Hello backend, which always requests
// WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY, this client can restrict Windows to roaming authenticators
// (USB / NFC / BLE security keys) and hide the Windows Hello platform authenticator.

#include <cstdint>
#include <string>
#include <vector>

#include "IAuthenticatorClient.h"

class WindowsWebAuthnClient : public IAuthenticatorClient
{
public:
  // roamingOnly = true -> WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM (security keys only)
  explicit WindowsWebAuthnClient(bool roamingOnly);

  std::string Description() const override;

  bool MakeCredential(const RegistrationOptions& options, const std::string& clientDataJson,
    RegistrationResponse& response, FidoError& error) override;

  bool GetAssertion(const AuthenticationOptions& options, const std::string& clientDataJson,
    std::vector<AssertionResponse>& responses, FidoError& error) override;

  static uint32_t ApiVersion();

private:
  bool m_roamingOnly;
};
