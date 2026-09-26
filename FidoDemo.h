#pragma once

// Runs the two WebAuthn ceremonies step by step and narrates them in the log:
//
//   Register:  [1] RelyingParty::BeginRegistration   server creates challenge + user handle
//              [2] ClientData::Build                 client builds clientDataJSON
//              [3] IAuthenticatorClient::MakeCredential  authenticator creates the credential
//              [4] RelyingParty::VerifyRegistration  server checks the response
//              [5] RelyingParty::StoreCredential     server saves the credential
//
//   Sign In:   the same with BeginAuthentication / GetAssertion / VerifyAssertion
//
// This class only wires the parts together - the WebAuthn logic lives in RelyingParty and the
// IAuthenticatorClient implementations. MFC-free: UTF-8 strings, output through a log callback,
// so every method can run on a worker thread.

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "ICredentialStore.h"
#include "LibFido2Client.h"
#include "RelyingParty.h"

// Outcome of Register / SignIn, shown in the result dialog
struct FidoResult
{
  bool ok = false;
  std::string title;    // e.g. "Signed in as alice" or "Registration failed"
  std::string details;  // multi-line summary or error reason
};

class FidoDemo
{
public:
  using LogFn = ::LogFn;

  // Registered credentials are kept in (and read from) the given store; it must outlive this object
  explicit FidoDemo(ICredentialStore& store);

  // --- device helpers (libfido2) ---

  // Wraps fido_init(); call once at startup
  static void Init();

  // Enumerates HID authenticators plus the Windows Hello (webauthn.dll) pseudo device
  static std::vector<FidoDevice> ListDevices(const LogFn& log);

  // Windows only lets elevated processes talk to FIDO HID devices directly
  static bool IsElevated();

  static bool DeviceInfo(const std::string& path, const LogFn& log);

  // --- ceremonies ---
  //
  // roamingOnly only matters for "windows://hello": then webauthn.dll is called directly
  // (WindowsWebAuthnClient) so that Windows offers security keys only, no Windows Hello.
  // requireUv: user verification (PIN / biometrics) required; otherwise touch only. The PIN argument is
  // only used for direct HID access - Windows collects the PIN in its own dialog.

  // makeCredential: creates an ES256 credential and saves it in the credential store
  FidoResult Register(const std::string& path, const std::string& rpId, const std::string& userName,
    const std::string& pin, bool discoverable, bool roamingOnly, bool requireUv, const LogFn& log);

  // getAssertion: with discoverable=false the stored credentials for rpId are sent as allow list,
  // with discoverable=true the allow list is empty and the authenticator picks the resident key
  FidoResult SignIn(const std::string& path, const std::string& rpId, const std::string& pin,
    bool discoverable, bool roamingOnly, bool requireUv, const LogFn& log);

private:
  static std::unique_ptr<IAuthenticatorClient> CreateClient(const std::string& path, const std::string& pin, bool roamingOnly);

  RelyingParty m_rp;
};
