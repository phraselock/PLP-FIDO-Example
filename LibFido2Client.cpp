// libfido2 pulls in OpenSSL headers - include them before <windows.h> to avoid wincrypt macro clashes
#include "Fido2Handles.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstdio>

#include "Encoding.h"
#include "LibFido2Client.h"

using namespace Fido2;

namespace
{
  constexpr size_t MAX_DEVICES = 64;
  constexpr int    TIMEOUT_MS = 60000;

  // Human readable error for the result dialog
  std::string FriendlyErr(int r)
  {
    switch (r)
    {
    case FIDO_ERR_ACTION_TIMEOUT:
    case FIDO_ERR_USER_ACTION_TIMEOUT: return "Timed out waiting for the user.";
    case FIDO_ERR_KEEPALIVE_CANCEL:
    case FIDO_ERR_OPERATION_DENIED:    return "Cancelled or denied on the authenticator.";
    case FIDO_ERR_NO_CREDENTIALS:      return "No matching credential on this authenticator.";
    case FIDO_ERR_PIN_INVALID:         return "Wrong PIN.";
    case FIDO_ERR_PIN_BLOCKED:         return "PIN blocked - the authenticator must be reset.";
    case FIDO_ERR_PIN_AUTH_BLOCKED:    return "PIN temporarily blocked - re-insert the authenticator.";
    case FIDO_ERR_PIN_REQUIRED:        return "The authenticator requires its PIN.";
    case FIDO_ERR_PIN_NOT_SET:         return "No PIN set on the authenticator.";
    case FIDO_ERR_UV_BLOCKED:          return "User verification blocked.";
    case FIDO_ERR_UV_INVALID:          return "User verification failed.";
    case FIDO_ERR_CREDENTIAL_EXCLUDED: return "Credential already registered on this authenticator.";
    case FIDO_ERR_KEY_STORE_FULL:      return "Authenticator storage is full.";
    default:                           return ErrorText(r);
    }
  }

  std::string PinHint(int r, bool requireUv, const std::string& pin)
  {
    if (r == FIDO_ERR_PIN_REQUIRED)
    {
      return "The key has a PIN set - tick 'Require PIN' and enter it in the PIN field.";
    }
    if (requireUv && pin.empty() && (r == FIDO_ERR_UNSUPPORTED_OPTION || r == FIDO_ERR_PIN_NOT_SET))
    {
      return "User verification required - enter the key's PIN in the PIN field.";
    }
    return {};
  }

  FidoError LibError(const std::string& call, int r, bool requireUv = false, const std::string& pin = {})
  {
    return { call + ": " + ErrorText(r), FriendlyErr(r), PinHint(r, requireUv, pin) };
  }

  DevPtr OpenDevice(const std::string& path, FidoError& error)
  {
    if (path.empty())
    {
      error = { "no device selected", "No device selected.", {} };
      return nullptr;
    }
    DevPtr dev(fido_dev_new());
    if (!dev)
    {
      error = { "fido_dev_new failed", "fido_dev_new failed.", {} };
      return nullptr;
    }
    int r = fido_dev_open(dev.get(), path.c_str());
    if (r != FIDO_OK)
    {
      error = { "fido_dev_open(" + path + "): " + ErrorText(r), "Could not open the authenticator: " + ErrorText(r), {} };
      if (!LibFido2Client::IsElevated() && path != LibFido2Client::WINHELLO_PATH)
      {
        error.hint = "Windows blocks raw FIDO HID access for non-elevated processes."
          " Run as Administrator or use the 'windows://hello' device.";
      }
      // fido_dev_close() on a device that was never opened is harmless, but skip it anyway
      fido_dev_t* raw = dev.release();
      fido_dev_free(&raw);
      return nullptr;
    }
    fido_dev_set_timeout(dev.get(), TIMEOUT_MS);
    return dev;
  }

  // The PIN is only passed when user verification is required and we talk HID directly.
  // Windows Hello collects PIN / biometrics in its own UI - never pass a PIN there.
  const char* PinFor(fido_dev_t* dev, const std::string& pin, bool requireUv)
  {
    if (!requireUv || fido_dev_is_winhello(dev) || pin.empty())
    {
      return nullptr;
    }
    return pin.c_str();
  }

  // requireUv -> uv=true (PIN / biometrics required). Otherwise touch only: libfido2's winhello backend
  // needs an explicit uv=false for WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED, raw HID keys
  // get no uv option at all (CTAP 2.1: platforms should not send uv=false)
  fido_opt_t UvOption(bool requireUv, const std::string& path)
  {
    if (requireUv)
    {
      return FIDO_OPT_TRUE;
    }
    return path == LibFido2Client::WINHELLO_PATH ? FIDO_OPT_FALSE : FIDO_OPT_OMIT;
  }

  std::vector<uint8_t> Bytes(const unsigned char* p, size_t len)
  {
    return p ? std::vector<uint8_t>(p, p + len) : std::vector<uint8_t>{};
  }
}

LibFido2Client::LibFido2Client(std::string path, std::string pin)
  : m_path(std::move(path))
  , m_pin(std::move(pin))
{
}

std::string LibFido2Client::Description() const
{
  if (m_path == WINHELLO_PATH)
  {
    return "windows://hello -> libfido2 winhello backend (Windows Hello or security key)";
  }
  return "direct HID: " + m_path;
}

bool LibFido2Client::MakeCredential(const RegistrationOptions& options, const std::string& clientDataJson,
  RegistrationResponse& response, FidoError& error)
{
  DevPtr dev = OpenDevice(m_path, error);
  if (!dev)
  {
    return false;
  }

  CredPtr cred(fido_cred_new());
  int r;
  if ((r = fido_cred_set_type(cred.get(), COSE_ES256)) != FIDO_OK ||
    (r = fido_cred_set_clientdata(cred.get(), reinterpret_cast<const unsigned char*>(clientDataJson.data()), clientDataJson.size())) != FIDO_OK ||
    (r = fido_cred_set_rp(cred.get(), options.rpId.c_str(), options.rpName.c_str())) != FIDO_OK ||
    (r = fido_cred_set_user(cred.get(), options.userId.data(), options.userId.size(), options.userName.c_str(), options.userName.c_str(), nullptr)) != FIDO_OK ||
    (r = fido_cred_set_rk(cred.get(), options.residentKey ? FIDO_OPT_TRUE : FIDO_OPT_OMIT)) != FIDO_OK ||
    (r = fido_cred_set_uv(cred.get(), UvOption(options.userVerification, m_path))) != FIDO_OK)
  {
    error = { "setting up credential: " + ErrorText(r), "Setting up the credential failed: " + ErrorText(r), {} };
    return false;
  }

  r = fido_dev_make_cred(dev.get(), cred.get(), PinFor(dev.get(), m_pin, options.userVerification));
  if (r != FIDO_OK)
  {
    error = LibError("fido_dev_make_cred", r, options.userVerification, m_pin);
    return false;
  }

  const char* fmt = fido_cred_fmt(cred.get());
  response.clientDataJson = clientDataJson;
  response.authData = Bytes(fido_cred_authdata_raw_ptr(cred.get()), fido_cred_authdata_raw_len(cred.get()));
  response.format = fmt ? fmt : "none";
  response.attStmt = Bytes(fido_cred_attstmt_ptr(cred.get()), fido_cred_attstmt_len(cred.get()));
  return true;
}

bool LibFido2Client::GetAssertion(const AuthenticationOptions& options, const std::string& clientDataJson,
  std::vector<AssertionResponse>& responses, FidoError& error)
{
  DevPtr dev = OpenDevice(m_path, error);
  if (!dev)
  {
    return false;
  }

  AssertPtr assertion(fido_assert_new());
  int r;
  if ((r = fido_assert_set_clientdata(assertion.get(), reinterpret_cast<const unsigned char*>(clientDataJson.data()), clientDataJson.size())) != FIDO_OK ||
    (r = fido_assert_set_rp(assertion.get(), options.rpId.c_str())) != FIDO_OK ||
    (r = fido_assert_set_up(assertion.get(), FIDO_OPT_TRUE)) != FIDO_OK ||
    (r = fido_assert_set_uv(assertion.get(), UvOption(options.userVerification, m_path))) != FIDO_OK)
  {
    error = { "setting up assertion: " + ErrorText(r), "Setting up the assertion failed: " + ErrorText(r), {} };
    return false;
  }
  for (const auto& id : options.allowCredentials)
  {
    if ((r = fido_assert_allow_cred(assertion.get(), id.data(), id.size())) != FIDO_OK)
    {
      error = { "fido_assert_allow_cred: " + ErrorText(r), "Setting up the allow list failed: " + ErrorText(r), {} };
      return false;
    }
  }

  r = fido_dev_get_assert(dev.get(), assertion.get(), PinFor(dev.get(), m_pin, options.userVerification));
  if (r != FIDO_OK)
  {
    error = LibError("fido_dev_get_assert", r, options.userVerification, m_pin);
    return false;
  }

  for (size_t i = 0; i < fido_assert_count(assertion.get()); i++)
  {
    AssertionResponse a;
    a.credentialId = Bytes(fido_assert_id_ptr(assertion.get(), i), fido_assert_id_len(assertion.get(), i));
    // CTAP2.0 allows the authenticator to omit the credential id if the allow list had exactly one entry
    if (a.credentialId.empty() && options.allowCredentials.size() == 1)
    {
      a.credentialId = options.allowCredentials[0];
    }
    a.clientDataJson = clientDataJson;
    a.authData = Bytes(fido_assert_authdata_raw_ptr(assertion.get(), i), fido_assert_authdata_raw_len(assertion.get(), i));
    a.signature = Bytes(fido_assert_sig_ptr(assertion.get(), i), fido_assert_sig_len(assertion.get(), i));
    a.userHandle = Bytes(fido_assert_user_id_ptr(assertion.get(), i), fido_assert_user_id_len(assertion.get(), i));
    if (const char* name = fido_assert_user_name(assertion.get(), i))
    {
      a.userName = name;
    }
    responses.push_back(std::move(a));
  }
  return true;
}

void LibFido2Client::Init()
{
  fido_init(0);  // FIDO_DEBUG would log to stderr, which a GUI app does not have
}

bool LibFido2Client::IsElevated()
{
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
  {
    return false;
  }
  TOKEN_ELEVATION elevation{};
  DWORD size = 0;
  BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size);
  CloseHandle(token);
  return ok && elevation.TokenIsElevated;
}

std::vector<FidoDevice> LibFido2Client::ListDevices(const LogFn& log)
{
  std::vector<FidoDevice> result;

  fido_dev_info_t* devlist = fido_dev_info_new(MAX_DEVICES);
  if (!devlist)
  {
    log("ERROR: fido_dev_info_new failed");
    return result;
  }

  size_t n = 0;
  int r = fido_dev_info_manifest(devlist, MAX_DEVICES, &n);
  if (r != FIDO_OK)
  {
    log("ERROR: fido_dev_info_manifest: " + ErrorText(r));
  }
  else
  {
    for (size_t i = 0; i < n; i++)
    {
      const fido_dev_info_t* di = fido_dev_info_ptr(devlist, i);
      FidoDevice d;
      d.path = fido_dev_info_path(di);
      const char* manufacturer = fido_dev_info_manufacturer_string(di);
      const char* product = fido_dev_info_product_string(di);
      char vidpid[32];
      snprintf(vidpid, sizeof(vidpid), "%04x:%04x",
        static_cast<uint16_t>(fido_dev_info_vendor(di)), static_cast<uint16_t>(fido_dev_info_product(di)));

      if (d.path == WINHELLO_PATH)
      {
        d.label = "Windows Hello / platform (windows://hello)";
      }
      else
      {
        d.label = std::string(manufacturer ? manufacturer : "") + " " + (product ? product : "") + " [" + vidpid + "]";
      }

      log("  found: " + d.label + "  path=" + d.path);
      result.push_back(std::move(d));
    }
  }
  fido_dev_info_free(&devlist, MAX_DEVICES);

  log("Devices found: " + std::to_string(result.size()));
  return result;
}

bool LibFido2Client::DeviceInfo(const std::string& path, const LogFn& log)
{
  log("=== Device Info ===");
  FidoError error;
  DevPtr dev = OpenDevice(path, error);
  if (!dev)
  {
    log("ERROR: " + error.logText);
    if (!error.hint.empty())
    {
      log("  Hint: " + error.hint);
    }
    return false;
  }

  fido_dev_t* d = dev.get();
  log("  winhello: " + std::string(fido_dev_is_winhello(d) ? "yes" : "no") +
    ", fido2: " + (fido_dev_is_fido2(d) ? "yes" : "no (U2F only)") +
    ", PIN set: " + (fido_dev_has_pin(d) ? "yes" : "no"));
  if (!fido_dev_is_winhello(d))
  {
    log("  firmware: " + std::to_string(fido_dev_major(d)) + "." + std::to_string(fido_dev_minor(d)) + "." +
      std::to_string(fido_dev_build(d)) + ", CTAPHID protocol " + std::to_string(fido_dev_protocol(d)));
  }

  InfoPtr ci(fido_cbor_info_new());
  int r = fido_dev_get_cbor_info(d, ci.get());
  if (r != FIDO_OK)
  {
    log("ERROR: fido_dev_get_cbor_info: " + ErrorText(r));
    return false;
  }

  std::string s;
  char** versions = fido_cbor_info_versions_ptr(ci.get());
  for (size_t i = 0; i < fido_cbor_info_versions_len(ci.get()); i++)
  {
    s += std::string(i ? ", " : "") + versions[i];
  }
  log("  versions: " + s);

  s.clear();
  char** ext = fido_cbor_info_extensions_ptr(ci.get());
  for (size_t i = 0; i < fido_cbor_info_extensions_len(ci.get()); i++)
  {
    s += std::string(i ? ", " : "") + ext[i];
  }
  log("  extensions: " + s);

  log("  aaguid: " + Encoding::Hex(fido_cbor_info_aaguid_ptr(ci.get()), fido_cbor_info_aaguid_len(ci.get())));

  s.clear();
  char** optNames = fido_cbor_info_options_name_ptr(ci.get());
  const bool* optValues = fido_cbor_info_options_value_ptr(ci.get());
  for (size_t i = 0; i < fido_cbor_info_options_len(ci.get()); i++)
  {
    s += std::string(i ? ", " : "") + optNames[i] + "=" + (optValues[i] ? "true" : "false");
  }
  log("  options: " + s);

  s.clear();
  const uint8_t* protocols = fido_cbor_info_protocols_ptr(ci.get());
  for (size_t i = 0; i < fido_cbor_info_protocols_len(ci.get()); i++)
  {
    s += std::string(i ? ", " : "") + std::to_string(protocols[i]);
  }
  log("  pin protocols: " + s);

  log("  max msg size: " + std::to_string(fido_cbor_info_maxmsgsiz(ci.get())));
  return true;
}
