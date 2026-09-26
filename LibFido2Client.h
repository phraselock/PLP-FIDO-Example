#pragma once

// IAuthenticatorClient implementation based on libfido2 (https://developers.yubico.com/libfido2/).
//
// Two ways to reach an authenticator:
//   - a HID device path: libfido2 speaks CTAP2 directly with the key. On Windows this needs an
//     elevated process - since Windows 10 1903 only administrators may talk to FIDO HID devices.
//   - "windows://hello": libfido2's Windows Hello backend forwards to webauthn.dll. Windows then
//     offers Windows Hello *and* security keys and collects the PIN itself.

#include <string>
#include <vector>

#include "IAuthenticatorClient.h"

struct FidoDevice
{
  std::string path;   // e.g. "\\?\hid#vid_1050&pid_0407..." or "windows://hello"
  std::string label;  // human readable, for the device combo box
};

class LibFido2Client : public IAuthenticatorClient
{
public:
  static constexpr char WINHELLO_PATH[] = "windows://hello";

  // pin is only used for direct HID access with user verification required
  LibFido2Client(std::string path, std::string pin);

  std::string Description() const override;

  bool MakeCredential(const RegistrationOptions& options, const std::string& clientDataJson,
    RegistrationResponse& response, FidoError& error) override;

  bool GetAssertion(const AuthenticationOptions& options, const std::string& clientDataJson,
    std::vector<AssertionResponse>& responses, FidoError& error) override;

  // --- device helpers ---

  // Wraps fido_init(); call once at startup
  static void Init();

  // Enumerates HID authenticators plus the Windows Hello (webauthn.dll) pseudo device
  static std::vector<FidoDevice> ListDevices(const LogFn& log);

  // authenticatorGetInfo (versions, extensions, AAGUID, options, ...)
  static bool DeviceInfo(const std::string& path, const LogFn& log);

  // Windows only lets elevated processes talk to FIDO HID devices directly
  static bool IsElevated();

private:
  std::string m_path;
  std::string m_pin;
};
