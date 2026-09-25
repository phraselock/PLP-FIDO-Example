#pragma once

// Direct use of the Windows WebAuthn API (webauthn.dll, Windows 10 1903+).
//
// libfido2's own Windows Hello backend always requests WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY, so Windows
// offers Windows Hello (platform authenticator) alongside security keys. Calling webauthn.dll ourselves
// allows restricting the dialog to roaming authenticators (USB / NFC / BLE security keys) - without
// admin rights. The raw results are handed back to libfido2 for parsing and signature verification.

#include <cstdint>
#include <string>
#include <vector>

namespace WinWebAuthn
{
  struct Attestation
  {
    std::string format;                 // "packed", "fido-u2f", "none", ...
    std::vector<uint8_t> authData;      // raw authenticatorData
    std::vector<uint8_t> attStmt;       // CBOR encoded attestation statement
    std::vector<uint8_t> credentialId;
    uint32_t usedTransport = 0;         // WEBAUTHN_CTAP_TRANSPORT_* (API v3+, else 0)
  };

  struct Assertion
  {
    std::vector<uint8_t> authData;      // raw authenticatorData
    std::vector<uint8_t> signature;
    std::vector<uint8_t> credentialId;
    std::vector<uint8_t> userId;        // only returned for discoverable credentials
  };

  uint32_t ApiVersion();
  std::string TransportName(uint32_t transport);

  // roamingOnly=true -> WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM (no Windows Hello)
  // requireUv=true -> WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED (PIN / biometrics), else DISCOURAGED
  bool MakeCredential(const std::string& rpId, const std::string& rpName, const std::vector<uint8_t>& userId,
    const std::string& userName, const std::string& clientDataJson, bool discoverable, bool roamingOnly,
    bool requireUv, Attestation& out, std::string& error);

  // An empty allowList requests a discoverable credential
  bool GetAssertion(const std::string& rpId, const std::string& clientDataJson,
    const std::vector<std::vector<uint8_t>>& allowList, bool roamingOnly, bool requireUv, Assertion& out, std::string& error);
}
