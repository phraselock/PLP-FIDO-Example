#pragma once

// Thin demo wrapper around libfido2 (https://developers.yubico.com/libfido2/).
// Deliberately MFC-free: all strings are UTF-8 std::string, output goes through a log callback,
// so every method can run on a worker thread.

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

struct FidoDevice
{
  std::string path;   // e.g. "\\?\hid#vid_1050&pid_0407..." or "windows://hello"
  std::string label;  // human readable, for the device combo box
};

struct StoredCredential
{
  std::string rpId;
  std::string userName;
  std::vector<uint8_t> userId;
  std::vector<uint8_t> credentialId;
  std::vector<uint8_t> publicKey;  // raw COSE_ES256 public key as returned by fido_cred_pubkey_ptr()
};

class FidoDemo
{
public:
  using LogFn = std::function<void(const std::string&)>;

  // Wraps fido_init(); call once at startup
  static void Init();

  // Enumerates HID authenticators plus the Windows Hello (webauthn.dll) pseudo device
  static std::vector<FidoDevice> ListDevices(const LogFn& log);

  // Windows only lets elevated processes talk to FIDO HID devices directly
  static bool IsElevated();

  static bool DeviceInfo(const std::string& path, const LogFn& log);

  // roamingOnly only matters for "windows://hello": then webauthn.dll is called directly (WinWebAuthn)
  // so that Windows offers security keys only, no Windows Hello platform authenticator.
  // requireUv: user verification (PIN / biometrics) required; otherwise touch only. The PIN argument is
  // only used for direct HID access - Windows collects the PIN in its own dialog.

  // makeCredential: creates an ES256 credential and keeps it in memory (m_credentials)
  bool Register(const std::string& path, const std::string& rpId, const std::string& userName,
    const std::string& pin, bool discoverable, bool roamingOnly, bool requireUv, const LogFn& log);

  // getAssertion: with discoverable=false the stored credentials for rpId are sent as allow list,
  // with discoverable=true the allow list is empty and the authenticator picks the resident key
  bool SignIn(const std::string& path, const std::string& rpId, const std::string& pin,
    bool discoverable, bool roamingOnly, bool requireUv, const LogFn& log);

private:
  std::vector<StoredCredential> m_credentials;
};
