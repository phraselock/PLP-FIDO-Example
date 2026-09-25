// libfido2 pulls in OpenSSL headers - include them before <windows.h> to avoid wincrypt macro clashes
#include <fido.h>
#include <fido/es256.h>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

#include <cstdio>
#include <cstring>
#include <memory>

#include "FidoDemo.h"
#include "WinWebAuthn.h"

namespace
{
  constexpr size_t MAX_DEVICES = 64;
  constexpr int    TIMEOUT_MS = 60000;
  constexpr char   WINHELLO_PATH[] = "windows://hello";
  constexpr char   RP_NAME[] = "PLP FIDO Example";

  // --- RAII helpers for libfido2 handles (the *_free functions take a pointer-to-pointer) ---

  struct DevDeleter { void operator()(fido_dev_t* d) const { fido_dev_close(d); fido_dev_free(&d); } };
  struct CredDeleter { void operator()(fido_cred_t* c) const { fido_cred_free(&c); } };
  struct AssertDeleter { void operator()(fido_assert_t* a) const { fido_assert_free(&a); } };
  struct InfoDeleter { void operator()(fido_cbor_info_t* i) const { fido_cbor_info_free(&i); } };
  struct Es256Deleter { void operator()(es256_pk_t* pk) const { es256_pk_free(&pk); } };

  using DevPtr = std::unique_ptr<fido_dev_t, DevDeleter>;
  using CredPtr = std::unique_ptr<fido_cred_t, CredDeleter>;
  using AssertPtr = std::unique_ptr<fido_assert_t, AssertDeleter>;
  using InfoPtr = std::unique_ptr<fido_cbor_info_t, InfoDeleter>;
  using Es256Ptr = std::unique_ptr<es256_pk_t, Es256Deleter>;

  // --- small formatting helpers ---

  std::string Hex(const unsigned char* p, size_t len)
  {
    static const char digits[] = "0123456789abcdef";
    std::string s;
    s.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
      s += digits[p[i] >> 4];
      s += digits[p[i] & 0x0f];
    }
    return s;
  }

  std::string Hex(const std::vector<uint8_t>& v) { return Hex(v.data(), v.size()); }

  std::string Base64Url(const std::vector<uint8_t>& data)
  {
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    size_t i = 0;
    for (; i + 2 < data.size(); i += 3) {
      uint32_t n = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
      out += tbl[(n >> 18) & 63]; out += tbl[(n >> 12) & 63]; out += tbl[(n >> 6) & 63]; out += tbl[n & 63];
    }
    if (data.size() - i == 1) {
      uint32_t n = data[i] << 16;
      out += tbl[(n >> 18) & 63]; out += tbl[(n >> 12) & 63];
    } else if (data.size() - i == 2) {
      uint32_t n = (data[i] << 16) | (data[i + 1] << 8);
      out += tbl[(n >> 18) & 63]; out += tbl[(n >> 12) & 63]; out += tbl[(n >> 6) & 63];
    }
    return out;  // no padding, as required by WebAuthn
  }

  std::vector<uint8_t> RandomBytes(size_t len)
  {
    std::vector<uint8_t> buf(len);
    BCryptGenRandom(nullptr, buf.data(), static_cast<ULONG>(len), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return buf;
  }

  std::string Err(int r)
  {
    return std::string(fido_strerr(r)) + " (" + std::to_string(r) + ")";
  }

  // Builds a WebAuthn clientDataJSON. libfido2 hashes it (SHA-256 -> clientDataHash) itself;
  // the Windows Hello backend (webauthn.dll) needs the JSON, a bare hash is not enough.
  std::string ClientDataJson(const char* type, const std::string& rpId, const std::vector<uint8_t>& challenge)
  {
    return std::string("{\"type\":\"") + type +
      "\",\"challenge\":\"" + Base64Url(challenge) +
      "\",\"origin\":\"https://" + rpId +
      "\",\"crossOrigin\":false}";
  }

  DevPtr OpenDevice(const std::string& path, const FidoDemo::LogFn& log)
  {
    if (path.empty()) {
      log("ERROR: no device selected");
      return nullptr;
    }
    DevPtr dev(fido_dev_new());
    if (!dev) {
      log("ERROR: fido_dev_new failed");
      return nullptr;
    }
    int r = fido_dev_open(dev.get(), path.c_str());
    if (r != FIDO_OK) {
      log("ERROR: fido_dev_open(" + path + "): " + Err(r));
      if (!FidoDemo::IsElevated() && path != WINHELLO_PATH)
        log("  Hint: Windows blocks raw FIDO HID access for non-elevated processes."
          " Run as Administrator or use the 'windows://hello' device.");
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
      return nullptr;
    return pin.c_str();
  }

  // requireUv -> uv=true (PIN / biometrics required). Otherwise touch only: libfido2's winhello backend
  // needs an explicit uv=false for WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED, raw HID keys
  // get no uv option at all (CTAP 2.1: platforms should not send uv=false)
  fido_opt_t UvOption(bool requireUv, const std::string& path)
  {
    if (requireUv)
      return FIDO_OPT_TRUE;
    return path == WINHELLO_PATH ? FIDO_OPT_FALSE : FIDO_OPT_OMIT;
  }

  // authenticatorData flags: UP = user present (touch), UV = user verified (PIN / biometrics)
  std::string FlagsText(uint8_t flags)
  {
    char buf[64];
    snprintf(buf, sizeof(buf), "0x%02x (UP: %s, UV: %s)", flags,
      (flags & 0x01) ? "yes" : "no", (flags & 0x04) ? "yes" : "no");
    return buf;
  }

  void LogPinHint(int r, bool requireUv, const std::string& pin, const FidoDemo::LogFn& log)
  {
    if (r == FIDO_ERR_PIN_REQUIRED)
      log("  Hint: the key has a PIN set - tick 'Require PIN' and enter it in the PIN field.");
    else if (requireUv && pin.empty() && (r == FIDO_ERR_UNSUPPORTED_OPTION || r == FIDO_ERR_PIN_NOT_SET))
      log("  Hint: user verification required - enter the key's PIN in the PIN field.");
  }
}

void FidoDemo::Init()
{
  fido_init(0);  // FIDO_DEBUG would log to stderr, which a GUI app does not have
}

bool FidoDemo::IsElevated()
{
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    return false;
  TOKEN_ELEVATION elevation{};
  DWORD size = 0;
  BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size);
  CloseHandle(token);
  return ok && elevation.TokenIsElevated;
}

std::vector<FidoDevice> FidoDemo::ListDevices(const LogFn& log)
{
  std::vector<FidoDevice> result;

  fido_dev_info_t* devlist = fido_dev_info_new(MAX_DEVICES);
  if (!devlist) {
    log("ERROR: fido_dev_info_new failed");
    return result;
  }

  size_t n = 0;
  int r = fido_dev_info_manifest(devlist, MAX_DEVICES, &n);
  if (r != FIDO_OK) {
    log("ERROR: fido_dev_info_manifest: " + Err(r));
  } else {
    for (size_t i = 0; i < n; i++) {
      const fido_dev_info_t* di = fido_dev_info_ptr(devlist, i);
      FidoDevice d;
      d.path = fido_dev_info_path(di);
      const char* manufacturer = fido_dev_info_manufacturer_string(di);
      const char* product = fido_dev_info_product_string(di);
      char vidpid[32];
      snprintf(vidpid, sizeof(vidpid), "%04x:%04x",
        static_cast<uint16_t>(fido_dev_info_vendor(di)), static_cast<uint16_t>(fido_dev_info_product(di)));

      if (d.path == WINHELLO_PATH)
        d.label = "Windows Hello / platform (windows://hello)";
      else
        d.label = std::string(manufacturer ? manufacturer : "") + " " + (product ? product : "") + " [" + vidpid + "]";

      log("  found: " + d.label + "  path=" + d.path);
      result.push_back(std::move(d));
    }
  }
  fido_dev_info_free(&devlist, MAX_DEVICES);

  log("Devices found: " + std::to_string(result.size()));
  return result;
}

bool FidoDemo::DeviceInfo(const std::string& path, const LogFn& log)
{
  log("=== Device Info ===");
  DevPtr dev = OpenDevice(path, log);
  if (!dev)
    return false;

  fido_dev_t* d = dev.get();
  log("  winhello: " + std::string(fido_dev_is_winhello(d) ? "yes" : "no") +
    ", fido2: " + (fido_dev_is_fido2(d) ? "yes" : "no (U2F only)") +
    ", PIN set: " + (fido_dev_has_pin(d) ? "yes" : "no"));
  if (!fido_dev_is_winhello(d))
    log("  firmware: " + std::to_string(fido_dev_major(d)) + "." + std::to_string(fido_dev_minor(d)) + "." +
      std::to_string(fido_dev_build(d)) + ", CTAPHID protocol " + std::to_string(fido_dev_protocol(d)));

  InfoPtr ci(fido_cbor_info_new());
  int r = fido_dev_get_cbor_info(d, ci.get());
  if (r != FIDO_OK) {
    log("ERROR: fido_dev_get_cbor_info: " + Err(r));
    return false;
  }

  std::string s;
  char** versions = fido_cbor_info_versions_ptr(ci.get());
  for (size_t i = 0; i < fido_cbor_info_versions_len(ci.get()); i++)
    s += std::string(i ? ", " : "") + versions[i];
  log("  versions: " + s);

  s.clear();
  char** ext = fido_cbor_info_extensions_ptr(ci.get());
  for (size_t i = 0; i < fido_cbor_info_extensions_len(ci.get()); i++)
    s += std::string(i ? ", " : "") + ext[i];
  log("  extensions: " + s);

  log("  aaguid: " + Hex(fido_cbor_info_aaguid_ptr(ci.get()), fido_cbor_info_aaguid_len(ci.get())));

  s.clear();
  char** optNames = fido_cbor_info_options_name_ptr(ci.get());
  const bool* optValues = fido_cbor_info_options_value_ptr(ci.get());
  for (size_t i = 0; i < fido_cbor_info_options_len(ci.get()); i++)
    s += std::string(i ? ", " : "") + optNames[i] + "=" + (optValues[i] ? "true" : "false");
  log("  options: " + s);

  s.clear();
  const uint8_t* protocols = fido_cbor_info_protocols_ptr(ci.get());
  for (size_t i = 0; i < fido_cbor_info_protocols_len(ci.get()); i++)
    s += std::string(i ? ", " : "") + std::to_string(protocols[i]);
  log("  pin protocols: " + s);

  log("  max msg size: " + std::to_string(fido_cbor_info_maxmsgsiz(ci.get())));
  return true;
}

bool FidoDemo::Register(const std::string& path, const std::string& rpId, const std::string& userName,
  const std::string& pin, bool discoverable, bool roamingOnly, bool requireUv, const LogFn& log)
{
  log("=== Register (makeCredential) ===");
  log(std::string("  user verification: ") + (requireUv ? "required (PIN)" : "discouraged (touch only)"));
  if (rpId.empty() || userName.empty()) {
    log("ERROR: RP ID and user name are required");
    return false;
  }

  // libfido2's winhello backend can't restrict Windows to security keys -> talk to webauthn.dll ourselves
  bool viaWebAuthn = roamingOnly && path == WINHELLO_PATH;
  DevPtr dev;
  if (!viaWebAuthn && !(dev = OpenDevice(path, log)))
    return false;

  // In a real deployment the challenge comes from the server (e.g. plp-fido2 /register/start)
  std::vector<uint8_t> challenge = RandomBytes(32);
  std::vector<uint8_t> userId = RandomBytes(32);
  std::string clientData = ClientDataJson("webauthn.create", rpId, challenge);
  log("  clientDataJSON: " + clientData);
  log("  user.id: " + Hex(userId));

  CredPtr cred(fido_cred_new());
  int r;
  if ((r = fido_cred_set_type(cred.get(), COSE_ES256)) != FIDO_OK ||
    (r = fido_cred_set_clientdata(cred.get(), reinterpret_cast<const unsigned char*>(clientData.data()), clientData.size())) != FIDO_OK ||
    (r = fido_cred_set_rp(cred.get(), rpId.c_str(), RP_NAME)) != FIDO_OK ||
    (r = fido_cred_set_user(cred.get(), userId.data(), userId.size(), userName.c_str(), userName.c_str(), nullptr)) != FIDO_OK ||
    (r = fido_cred_set_rk(cred.get(), discoverable ? FIDO_OPT_TRUE : FIDO_OPT_OMIT)) != FIDO_OK ||
    (r = fido_cred_set_uv(cred.get(), UvOption(requireUv, path))) != FIDO_OK) {
    log("ERROR: setting up credential: " + Err(r));
    return false;
  }

  if (viaWebAuthn) {
    log("  via webauthn.dll (API v" + std::to_string(WinWebAuthn::ApiVersion()) + "), security keys only");
    log(">>> Insert / touch your security key ...");
    WinWebAuthn::Attestation att;
    std::string error;
    if (!WinWebAuthn::MakeCredential(rpId, RP_NAME, userId, userName, clientData, discoverable, true, requireUv, att, error)) {
      log("ERROR: WebAuthNAuthenticatorMakeCredential: " + error);
      return false;
    }
    if (att.usedTransport)
      log("  transport: " + WinWebAuthn::TransportName(att.usedTransport));

    // Hand the raw result to libfido2: it parses authData (credential id, COSE public key)
    // and verifies the attestation below exactly as for the direct HID path
    if ((r = fido_cred_set_authdata_raw(cred.get(), att.authData.data(), att.authData.size())) != FIDO_OK ||
      (r = fido_cred_set_fmt(cred.get(), att.format.c_str())) != FIDO_OK ||
      (!att.attStmt.empty() && (r = fido_cred_set_attstmt(cred.get(), att.attStmt.data(), att.attStmt.size())) != FIDO_OK)) {
      log("ERROR: importing webauthn.dll result into libfido2: " + Err(r));
      return false;
    }
  } else {
    log(">>> Touch your authenticator / confirm the Windows Hello dialog ...");
    r = fido_dev_make_cred(dev.get(), cred.get(), PinFor(dev.get(), pin, requireUv));
    if (r != FIDO_OK) {
      log("ERROR: fido_dev_make_cred: " + Err(r));
      LogPinHint(r, requireUv, pin, log);
      return false;
    }
  }

  const char* fmt = fido_cred_fmt(cred.get());
  log("  attestation format: " + std::string(fmt ? fmt : "(null)"));
  log("  flags: " + FlagsText(fido_cred_flags(cred.get())) + ", sign count: " + std::to_string(fido_cred_sigcount(cred.get())));
  log("  aaguid: " + Hex(fido_cred_aaguid_ptr(cred.get()), fido_cred_aaguid_len(cred.get())));

  // Verify the attestation signature over authData || clientDataHash
  if (fmt == nullptr || strcmp(fmt, "none") == 0) {
    log("  attestation: none - nothing to verify");
  } else {
    r = fido_cred_x5c_len(cred.get()) > 0 ? fido_cred_verify(cred.get()) : fido_cred_verify_self(cred.get());
    log(std::string("  attestation signature: ") + (r == FIDO_OK ? "valid" : "INVALID - " + Err(r)));
  }

  StoredCredential sc;
  sc.rpId = rpId;
  sc.userName = userName;
  sc.userId = userId;
  sc.credentialId.assign(fido_cred_id_ptr(cred.get()), fido_cred_id_ptr(cred.get()) + fido_cred_id_len(cred.get()));
  sc.publicKey.assign(fido_cred_pubkey_ptr(cred.get()), fido_cred_pubkey_ptr(cred.get()) + fido_cred_pubkey_len(cred.get()));
  log("  credential id: " + Hex(sc.credentialId));
  log("  public key (ES256 x||y): " + Hex(sc.publicKey));

  m_credentials.push_back(std::move(sc));
  log("Registration OK - " + std::to_string(m_credentials.size()) + " credential(s) stored in memory.");
  return true;
}

bool FidoDemo::SignIn(const std::string& path, const std::string& rpId, const std::string& pin,
  bool discoverable, bool roamingOnly, bool requireUv, const LogFn& log)
{
  log("=== Sign In (getAssertion) ===");
  log(std::string("  user verification: ") + (requireUv ? "required (PIN)" : "discouraged (touch only)"));

  std::vector<const StoredCredential*> candidates;
  for (const auto& c : m_credentials)
    if (c.rpId == rpId)
      candidates.push_back(&c);

  if (!discoverable && candidates.empty()) {
    log("ERROR: no credential registered for RP '" + rpId + "' - register first"
      " (or tick 'Discoverable credential' to sign in without allow list)");
    return false;
  }

  bool viaWebAuthn = roamingOnly && path == WINHELLO_PATH;
  DevPtr dev;
  if (!viaWebAuthn && !(dev = OpenDevice(path, log)))
    return false;

  std::vector<uint8_t> challenge = RandomBytes(32);
  std::string clientData = ClientDataJson("webauthn.get", rpId, challenge);
  log("  clientDataJSON: " + clientData);

  AssertPtr assert(fido_assert_new());
  int r;
  if ((r = fido_assert_set_clientdata(assert.get(), reinterpret_cast<const unsigned char*>(clientData.data()), clientData.size())) != FIDO_OK ||
    (r = fido_assert_set_rp(assert.get(), rpId.c_str())) != FIDO_OK ||
    (r = fido_assert_set_up(assert.get(), FIDO_OPT_TRUE)) != FIDO_OK ||
    // uv=true also makes fido_assert_verify() reject assertions without the UV flag, as a server would
    (r = fido_assert_set_uv(assert.get(), UvOption(requireUv, path))) != FIDO_OK) {
    log("ERROR: setting up assertion: " + Err(r));
    return false;
  }

  if (discoverable) {
    log("  allow list: empty (discoverable credential)");
  } else {
    for (const StoredCredential* c : candidates) {
      if ((r = fido_assert_allow_cred(assert.get(), c->credentialId.data(), c->credentialId.size())) != FIDO_OK) {
        log("ERROR: fido_assert_allow_cred: " + Err(r));
        return false;
      }
      log("  allow: " + Hex(c->credentialId));
    }
  }

  // Credential id per returned assertion (libfido2 has no setter for it when importing webauthn.dll results)
  std::vector<std::vector<uint8_t>> ids;

  if (viaWebAuthn) {
    log("  via webauthn.dll (API v" + std::to_string(WinWebAuthn::ApiVersion()) + "), security keys only");
    log(">>> Insert / touch your security key ...");
    std::vector<std::vector<uint8_t>> allowList;
    if (!discoverable)
      for (const StoredCredential* c : candidates)
        allowList.push_back(c->credentialId);

    WinWebAuthn::Assertion wa;
    std::string error;
    if (!WinWebAuthn::GetAssertion(rpId, clientData, allowList, true, requireUv, wa, error)) {
      log("ERROR: WebAuthNAuthenticatorGetAssertion: " + error);
      return false;
    }
    if (!wa.userId.empty())
      log("  user.id: " + Hex(wa.userId));

    // Import into libfido2 so the signature check below is identical for both paths
    if ((r = fido_assert_set_count(assert.get(), 1)) != FIDO_OK ||
      (r = fido_assert_set_authdata_raw(assert.get(), 0, wa.authData.data(), wa.authData.size())) != FIDO_OK ||
      (r = fido_assert_set_sig(assert.get(), 0, wa.signature.data(), wa.signature.size())) != FIDO_OK) {
      log("ERROR: importing webauthn.dll result into libfido2: " + Err(r));
      return false;
    }
    ids.push_back(wa.credentialId);
  } else {
    log(">>> Touch your authenticator / confirm the Windows Hello dialog ...");
    r = fido_dev_get_assert(dev.get(), assert.get(), PinFor(dev.get(), pin, requireUv));
    if (r != FIDO_OK) {
      log("ERROR: fido_dev_get_assert: " + Err(r));
      if (r == FIDO_ERR_NO_CREDENTIALS)
        log("  Hint: this authenticator holds no matching credential for '" + rpId + "'.");
      LogPinHint(r, requireUv, pin, log);
      return false;
    }
    for (size_t i = 0; i < fido_assert_count(assert.get()); i++) {
      std::vector<uint8_t> id(fido_assert_id_ptr(assert.get(), i), fido_assert_id_ptr(assert.get(), i) + fido_assert_id_len(assert.get(), i));
      // CTAP2.0 allows the authenticator to omit the credential id if the allow list had exactly one entry
      if (id.empty() && !discoverable && candidates.size() == 1)
        id = candidates[0]->credentialId;
      ids.push_back(std::move(id));
    }
  }

  bool allOk = true;
  log("  assertions returned: " + std::to_string(ids.size()));

  for (size_t i = 0; i < ids.size(); i++) {
    const std::vector<uint8_t>& id = ids[i];

    const char* user = fido_assert_user_name(assert.get(), i);
    log("  [" + std::to_string(i) + "] credential id: " + Hex(id));
    log("      user: " + std::string(user ? user : "(not returned)") +
      ", flags: " + FlagsText(fido_assert_flags(assert.get(), i)) +
      ", sign count: " + std::to_string(fido_assert_sigcount(assert.get(), i)));

    const StoredCredential* match = nullptr;
    for (const auto& c : m_credentials)
      if (c.credentialId == id)
        match = &c;
    if (!match) {
      log("      unknown credential (not registered in this session) - cannot verify signature");
      allOk = false;
      continue;
    }

    // Server side step: verify the signature over authData || clientDataHash with the stored public key
    Es256Ptr pk(es256_pk_new());
    if ((r = es256_pk_from_ptr(pk.get(), match->publicKey.data(), match->publicKey.size())) != FIDO_OK ||
      (r = fido_assert_verify(assert.get(), i, COSE_ES256, pk.get())) != FIDO_OK) {
      log("      signature INVALID: " + Err(r));
      allOk = false;
      continue;
    }
    log("      signature valid -> signed in as '" + match->userName + "'");
  }

  log(allOk ? "Sign-in OK." : "Sign-in FAILED.");
  return allOk;
}
