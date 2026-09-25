// libfido2 pulls in OpenSSL headers - include them before <windows.h> to avoid wincrypt macro clashes
#include <fido.h>
#include <fido/es256.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

#include <chrono>
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

  using Clock = std::chrono::steady_clock;

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

  // Abbreviated hex for the result dialog: "3f2a1b9c...e0d1 (64 bytes)"
  std::string ShortHex(const std::vector<uint8_t>& v)
  {
    if (v.size() <= 12)
      return Hex(v);
    return Hex(v.data(), 8) + "..." + Hex(v.data() + v.size() - 2, 2) + " (" + std::to_string(v.size()) + " bytes)";
  }

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

  std::vector<uint8_t> Sha256(const std::string& s)
  {
    std::vector<uint8_t> out(SHA256_DIGEST_LENGTH);
    SHA256(reinterpret_cast<const unsigned char*>(s.data()), s.size(), out.data());
    return out;
  }

  std::string Seconds(Clock::time_point start)
  {
    char buf[32];
    snprintf(buf, sizeof(buf), "%.1f s", std::chrono::duration<double>(Clock::now() - start).count());
    return buf;
  }

  std::string Err(int r)
  {
    return std::string(fido_strerr(r)) + " (" + std::to_string(r) + ")";
  }

  // Human readable error for the result dialog
  std::string FriendlyErr(int r)
  {
    switch (r) {
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
    default:                           return Err(r);
    }
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

  DevPtr OpenDevice(const std::string& path, const FidoDemo::LogFn& log, std::string& error)
  {
    if (path.empty()) {
      error = "No device selected.";
      log("ERROR: no device selected");
      return nullptr;
    }
    DevPtr dev(fido_dev_new());
    if (!dev) {
      error = "fido_dev_new failed.";
      log("ERROR: fido_dev_new failed");
      return nullptr;
    }
    int r = fido_dev_open(dev.get(), path.c_str());
    if (r != FIDO_OK) {
      error = "Could not open the authenticator: " + Err(r);
      log("ERROR: fido_dev_open(" + path + "): " + Err(r));
      if (!FidoDemo::IsElevated() && path != WINHELLO_PATH) {
        error += "\n\nWindows blocks direct FIDO access for non-elevated processes."
          " Run as Administrator or use 'windows://hello'.";
        log("  Hint: Windows blocks raw FIDO HID access for non-elevated processes."
          " Run as Administrator or use the 'windows://hello' device.");
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

  // authenticatorData flags: UP = user present (touch), UV = user verified (PIN / biometrics),
  // BE/BS = backup eligible/state (synced passkeys), AT = attested credential data, ED = extensions
  std::string FlagsText(uint8_t flags)
  {
    char buf[80];
    snprintf(buf, sizeof(buf), "0x%02x  UP=%d UV=%d BE=%d BS=%d AT=%d ED=%d", flags,
      (flags & 0x01) != 0, (flags & 0x04) != 0, (flags & 0x08) != 0, (flags & 0x10) != 0,
      (flags & 0x40) != 0, (flags & 0x80) != 0);
    return buf;
  }

  std::string PinHint(int r, bool requireUv, const std::string& pin)
  {
    if (r == FIDO_ERR_PIN_REQUIRED)
      return "The key has a PIN set - tick 'Require PIN' and enter it in the PIN field.";
    if (requireUv && pin.empty() && (r == FIDO_ERR_UNSUPPORTED_OPTION || r == FIDO_ERR_PIN_NOT_SET))
      return "User verification required - enter the key's PIN in the PIN field.";
    return {};
  }

  std::string DeviceDescription(const std::string& path, bool viaWebAuthn)
  {
    if (viaWebAuthn)
      return "windows://hello -> webauthn.dll directly (API v" + std::to_string(WinWebAuthn::ApiVersion()) +
        "), security keys only";
    if (path == WINHELLO_PATH)
      return "windows://hello -> libfido2 winhello backend (Windows Hello or security key)";
    return "direct HID: " + path;
  }

  // Logs authenticatorData = rpIdHash(32) | flags(1) | signCount(4) | [attestedCredentialData] | [extensions]
  // and checks rpIdHash against SHA-256(rpId), as a relying party must
  bool LogAuthData(const unsigned char* ad, size_t len, const std::string& rpId, const FidoDemo::LogFn& log)
  {
    log("      authData       : " + std::to_string(len) + " bytes");
    if (ad == nullptr || len < 37) {
      log("      authData too short");
      return false;
    }
    std::vector<uint8_t> expected = Sha256(rpId);
    bool match = memcmp(ad, expected.data(), expected.size()) == 0;
    log("      rpIdHash       : " + Hex(ad, 32));
    log(std::string("                       ") + (match ? "== " : "!= ") + "SHA-256(\"" + rpId + "\")  -> " +
      (match ? "OK" : "MISMATCH"));
    log("      flags          : " + FlagsText(ad[32]));
    return match;
  }

  std::string CertName(const unsigned char* der, size_t len, bool issuer)
  {
    const unsigned char* p = der;
    X509* cert = d2i_X509(nullptr, &p, static_cast<long>(len));
    if (cert == nullptr)
      return "(unparseable certificate)";
    char buf[512];
    X509_NAME_oneline(issuer ? X509_get_issuer_name(cert) : X509_get_subject_name(cert), buf, sizeof(buf));
    X509_free(cert);
    return buf;
  }

  std::string YesNo(bool b) { return b ? "yes" : "no"; }
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
  std::string error;
  DevPtr dev = OpenDevice(path, log, error);
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

FidoResult FidoDemo::Register(const std::string& path, const std::string& rpId, const std::string& userName,
  const std::string& pin, bool discoverable, bool roamingOnly, bool requireUv, const LogFn& log)
{
  FidoResult result;
  result.title = "Registration failed";
  auto fail = [&](const std::string& logText, const std::string& reason, const std::string& hint = {}) {
    log("ERROR: " + logText);
    if (!hint.empty())
      log("  Hint: " + hint);
    log("Registration FAILED.");
    result.details = reason + (hint.empty() ? "" : "\n\n" + hint);
    return result;
  };

  // libfido2's winhello backend can't restrict Windows to security keys -> talk to webauthn.dll ourselves
  bool viaWebAuthn = roamingOnly && path == WINHELLO_PATH;

  log("=== Register (makeCredential) ===");
  log("  device            : " + DeviceDescription(path, viaWebAuthn));
  log(std::string("  user verification : ") + (requireUv ? "required (PIN)" : "discouraged (touch only)"));
  log("  discoverable      : " + YesNo(discoverable));
  if (rpId.empty() || userName.empty())
    return fail("RP ID and user name are required", "RP ID and user name are required.");

  std::string error;
  DevPtr dev;
  if (!viaWebAuthn && !(dev = OpenDevice(path, log, error))) {
    log("Registration FAILED.");
    result.details = error;
    return result;
  }

  // In a real deployment the challenge comes from the server (e.g. plp-fido2 /register/start)
  log("[1/5] Server: create challenge and user handle");
  std::vector<uint8_t> challenge = RandomBytes(32);
  std::vector<uint8_t> userId = RandomBytes(32);
  log("      rp.id          : " + rpId);
  log("      user.name      : " + userName);
  log("      user.id        : " + Hex(userId));
  log("      challenge      : " + Base64Url(challenge) + "  (32 random bytes)");

  log("[2/5] Client: build clientDataJSON and hash it");
  std::string clientData = ClientDataJson("webauthn.create", rpId, challenge);
  log("      clientDataJSON : " + clientData);

  CredPtr cred(fido_cred_new());
  int r;
  if ((r = fido_cred_set_type(cred.get(), COSE_ES256)) != FIDO_OK ||
    (r = fido_cred_set_clientdata(cred.get(), reinterpret_cast<const unsigned char*>(clientData.data()), clientData.size())) != FIDO_OK ||
    (r = fido_cred_set_rp(cred.get(), rpId.c_str(), RP_NAME)) != FIDO_OK ||
    (r = fido_cred_set_user(cred.get(), userId.data(), userId.size(), userName.c_str(), userName.c_str(), nullptr)) != FIDO_OK ||
    (r = fido_cred_set_rk(cred.get(), discoverable ? FIDO_OPT_TRUE : FIDO_OPT_OMIT)) != FIDO_OK ||
    (r = fido_cred_set_uv(cred.get(), UvOption(requireUv, path))) != FIDO_OK)
    return fail("setting up credential: " + Err(r), "Setting up the credential failed: " + Err(r));

  log("      clientDataHash : " + Hex(fido_cred_clientdata_hash_ptr(cred.get()), fido_cred_clientdata_hash_len(cred.get())) +
    "  (SHA-256)");

  log("[3/5] Authenticator: makeCredential");
  log(requireUv ? "      >>> Enter your PIN and touch your authenticator ..." : "      >>> Touch your authenticator ...");
  Clock::time_point start = Clock::now();
  if (viaWebAuthn) {
    WinWebAuthn::Attestation att;
    if (!WinWebAuthn::MakeCredential(rpId, RP_NAME, userId, userName, clientData, discoverable, true, requireUv, att, error))
      return fail("WebAuthNAuthenticatorMakeCredential: " + error, error);
    log("      done after " + Seconds(start) +
      (att.usedTransport ? ", transport: " + WinWebAuthn::TransportName(att.usedTransport) : std::string()));

    // Hand the raw result to libfido2: it parses authData (credential id, COSE public key)
    // and verifies the attestation below exactly as for the direct HID path
    if ((r = fido_cred_set_authdata_raw(cred.get(), att.authData.data(), att.authData.size())) != FIDO_OK ||
      (r = fido_cred_set_fmt(cred.get(), att.format.c_str())) != FIDO_OK ||
      (!att.attStmt.empty() && (r = fido_cred_set_attstmt(cred.get(), att.attStmt.data(), att.attStmt.size())) != FIDO_OK))
      return fail("importing webauthn.dll result into libfido2: " + Err(r), "Could not parse the authenticator response: " + Err(r));
  } else {
    r = fido_dev_make_cred(dev.get(), cred.get(), PinFor(dev.get(), pin, requireUv));
    if (r != FIDO_OK)
      return fail("fido_dev_make_cred: " + Err(r), FriendlyErr(r), PinHint(r, requireUv, pin));
    log("      done after " + Seconds(start));
  }

  log("[4/5] Server: parse and verify the response");
  bool rpOk = LogAuthData(fido_cred_authdata_raw_ptr(cred.get()), fido_cred_authdata_raw_len(cred.get()), rpId, log);
  uint8_t flags = fido_cred_flags(cred.get());
  log("      signCount      : " + std::to_string(fido_cred_sigcount(cred.get())));

  StoredCredential sc;
  sc.rpId = rpId;
  sc.userName = userName;
  sc.userId = userId;
  sc.credentialId.assign(fido_cred_id_ptr(cred.get()), fido_cred_id_ptr(cred.get()) + fido_cred_id_len(cred.get()));
  sc.publicKey.assign(fido_cred_pubkey_ptr(cred.get()), fido_cred_pubkey_ptr(cred.get()) + fido_cred_pubkey_len(cred.get()));
  sc.aaguid.assign(fido_cred_aaguid_ptr(cred.get()), fido_cred_aaguid_ptr(cred.get()) + fido_cred_aaguid_len(cred.get()));
  sc.signCount = fido_cred_sigcount(cred.get());

  log("      AAGUID         : " + Hex(sc.aaguid));
  log("      credential id  : " + std::to_string(sc.credentialId.size()) + " bytes  " + Hex(sc.credentialId));
  log("      public key     : ES256 (ECDSA P-256)");
  if (sc.publicKey.size() == 64) {
    log("                       x = " + Hex(sc.publicKey.data(), 32));
    log("                       y = " + Hex(sc.publicKey.data() + 32, 32));
  } else {
    log("                       " + Hex(sc.publicKey));
  }

  if (!rpOk)
    return fail("rpIdHash does not match SHA-256(rp.id)", "The response was created for a different relying party (rpIdHash mismatch).");
  if (requireUv && !(flags & 0x04))
    return fail("UV flag missing although user verification was required", "The authenticator did not verify the user (no PIN).");

  // Verify the attestation signature over authData || clientDataHash
  const char* fmt = fido_cred_fmt(cred.get());
  std::string attestation;
  if (fmt == nullptr || strcmp(fmt, "none") == 0) {
    log("      attestation    : none - no attestation statement provided, nothing to verify");
    attestation = "none";
  } else {
    size_t certs = fido_cred_x5c_list_count(cred.get());
    log("      attestation    : " + std::string(fmt) + ", " +
      (certs ? std::to_string(certs) + " certificate(s)" : std::string("self attestation (no certificate)")));
    for (size_t i = 0; i < certs; i++) {
      const unsigned char* der = fido_cred_x5c_list_ptr(cred.get(), i);
      size_t len = fido_cred_x5c_list_len(cred.get(), i);
      log("                       [" + std::to_string(i) + "] subject: " + CertName(der, len, false));
      log("                           issuer : " + CertName(der, len, true));
    }
    log("      attestation sig: " + std::to_string(fido_cred_sig_len(cred.get())) + " bytes over authData || clientDataHash");
    r = certs > 0 ? fido_cred_verify(cred.get()) : fido_cred_verify_self(cred.get());
    if (r != FIDO_OK)
      return fail("attestation signature INVALID: " + Err(r), "The attestation signature is invalid: " + Err(r));
    log(std::string("      verification   : VALID (") + (certs ? "attestation certificate" : "credential public key") + ")");
    attestation = std::string(fmt) + " - signature valid";
  }

  log("[5/5] Server: store credential for '" + userName + "'");
  result.ok = true;
  result.title = "Registration successful";
  result.details =
    "User: " + userName + "\n"
    "Relying party: " + rpId + "\n"
    "Credential ID: " + ShortHex(sc.credentialId) + "\n"
    "Authenticator AAGUID: " + Hex(sc.aaguid) + "\n"
    "User verified (PIN): " + YesNo(flags & 0x04) + "\n"
    "Discoverable (passkey): " + YesNo(discoverable) + "\n"
    "Attestation: " + attestation;

  m_credentials.push_back(std::move(sc));
  log("Registration OK - " + std::to_string(m_credentials.size()) + " credential(s) stored in memory.");
  return result;
}

FidoResult FidoDemo::SignIn(const std::string& path, const std::string& rpId, const std::string& pin,
  bool discoverable, bool roamingOnly, bool requireUv, const LogFn& log)
{
  FidoResult result;
  result.title = "Sign-in failed";
  auto fail = [&](const std::string& logText, const std::string& reason, const std::string& hint = {}) {
    log("ERROR: " + logText);
    if (!hint.empty())
      log("  Hint: " + hint);
    log("Sign-in FAILED.");
    result.details = reason + (hint.empty() ? "" : "\n\n" + hint);
    return result;
  };

  bool viaWebAuthn = roamingOnly && path == WINHELLO_PATH;

  log("=== Sign In (getAssertion) ===");
  log("  device            : " + DeviceDescription(path, viaWebAuthn));
  log(std::string("  user verification : ") + (requireUv ? "required (PIN)" : "discouraged (touch only)"));

  std::vector<StoredCredential*> candidates;
  for (auto& c : m_credentials)
    if (c.rpId == rpId)
      candidates.push_back(&c);

  if (!discoverable && candidates.empty())
    return fail("no credential registered for RP '" + rpId + "'",
      "No credential registered for '" + rpId + "' in this session.",
      "Register first, or tick 'Discoverable credential' to sign in without allow list.");

  std::string error;
  DevPtr dev;
  if (!viaWebAuthn && !(dev = OpenDevice(path, log, error))) {
    log("Sign-in FAILED.");
    result.details = error;
    return result;
  }

  log("[1/5] Server: create challenge");
  std::vector<uint8_t> challenge = RandomBytes(32);
  log("      rp.id          : " + rpId);
  log("      challenge      : " + Base64Url(challenge) + "  (32 random bytes)");
  if (discoverable) {
    log("      allowList      : empty -> the authenticator chooses the account (discoverable credential)");
  } else {
    log("      allowList      : " + std::to_string(candidates.size()) + " credential(s) registered for this RP");
    for (const StoredCredential* c : candidates)
      log("                       " + Hex(c->credentialId) + "  (" + c->userName + ")");
  }

  log("[2/5] Client: build clientDataJSON and hash it");
  std::string clientData = ClientDataJson("webauthn.get", rpId, challenge);
  log("      clientDataJSON : " + clientData);

  AssertPtr assert(fido_assert_new());
  int r;
  if ((r = fido_assert_set_clientdata(assert.get(), reinterpret_cast<const unsigned char*>(clientData.data()), clientData.size())) != FIDO_OK ||
    (r = fido_assert_set_rp(assert.get(), rpId.c_str())) != FIDO_OK ||
    (r = fido_assert_set_up(assert.get(), FIDO_OPT_TRUE)) != FIDO_OK ||
    // uv=true also makes fido_assert_verify() reject assertions without the UV flag, as a server would
    (r = fido_assert_set_uv(assert.get(), UvOption(requireUv, path))) != FIDO_OK)
    return fail("setting up assertion: " + Err(r), "Setting up the assertion failed: " + Err(r));

  if (!discoverable) {
    for (const StoredCredential* c : candidates)
      if ((r = fido_assert_allow_cred(assert.get(), c->credentialId.data(), c->credentialId.size())) != FIDO_OK)
        return fail("fido_assert_allow_cred: " + Err(r), "Setting up the allow list failed: " + Err(r));
  }

  const std::vector<uint8_t> clientDataHash(fido_assert_clientdata_hash_ptr(assert.get()),
    fido_assert_clientdata_hash_ptr(assert.get()) + fido_assert_clientdata_hash_len(assert.get()));
  log("      clientDataHash : " + Hex(clientDataHash) + "  (SHA-256)");

  // Credential id / user id per returned assertion (libfido2 has no setter for them when importing webauthn.dll results)
  std::vector<std::vector<uint8_t>> ids;
  std::vector<std::vector<uint8_t>> userIds;

  log("[3/5] Authenticator: getAssertion");
  log(requireUv ? "      >>> Enter your PIN and touch your authenticator ..." : "      >>> Touch your authenticator ...");
  Clock::time_point start = Clock::now();
  if (viaWebAuthn) {
    std::vector<std::vector<uint8_t>> allowList;
    if (!discoverable)
      for (const StoredCredential* c : candidates)
        allowList.push_back(c->credentialId);

    WinWebAuthn::Assertion wa;
    if (!WinWebAuthn::GetAssertion(rpId, clientData, allowList, true, requireUv, wa, error))
      return fail("WebAuthNAuthenticatorGetAssertion: " + error, error);

    // Import into libfido2 so the signature check below is identical for both paths
    if ((r = fido_assert_set_count(assert.get(), 1)) != FIDO_OK ||
      (r = fido_assert_set_authdata_raw(assert.get(), 0, wa.authData.data(), wa.authData.size())) != FIDO_OK ||
      (r = fido_assert_set_sig(assert.get(), 0, wa.signature.data(), wa.signature.size())) != FIDO_OK)
      return fail("importing webauthn.dll result into libfido2: " + Err(r), "Could not parse the authenticator response: " + Err(r));
    ids.push_back(wa.credentialId);
    userIds.push_back(wa.userId);
  } else {
    r = fido_dev_get_assert(dev.get(), assert.get(), PinFor(dev.get(), pin, requireUv));
    if (r != FIDO_OK)
      return fail("fido_dev_get_assert: " + Err(r), FriendlyErr(r), PinHint(r, requireUv, pin));
    for (size_t i = 0; i < fido_assert_count(assert.get()); i++) {
      std::vector<uint8_t> id(fido_assert_id_ptr(assert.get(), i), fido_assert_id_ptr(assert.get(), i) + fido_assert_id_len(assert.get(), i));
      // CTAP2.0 allows the authenticator to omit the credential id if the allow list had exactly one entry
      if (id.empty() && !discoverable && candidates.size() == 1)
        id = candidates[0]->credentialId;
      ids.push_back(std::move(id));
      userIds.emplace_back(fido_assert_user_id_ptr(assert.get(), i),
        fido_assert_user_id_ptr(assert.get(), i) + fido_assert_user_id_len(assert.get(), i));
    }
  }
  log("      done after " + Seconds(start) + ", " + std::to_string(ids.size()) + " assertion(s) returned");

  log("[4/5] Server: verify the assertion(s)");
  bool allOk = true;
  std::string failReason;
  std::vector<std::string> signedIn;
  std::string summary;

  for (size_t i = 0; i < ids.size(); i++) {
    const std::vector<uint8_t>& id = ids[i];
    log("    assertion [" + std::to_string(i) + "]");

    StoredCredential* match = nullptr;
    for (auto& c : m_credentials)
      if (c.credentialId == id)
        match = &c;

    log("      credential id  : " + Hex(id) + (match ? "  -> '" + match->userName + "'" : "  -> unknown"));
    if (!userIds[i].empty())
      log("      user.id        : " + Hex(userIds[i]));
    if (const char* name = fido_assert_user_name(assert.get(), i))
      log("      user.name      : " + std::string(name) + "  (returned by the authenticator)");

    size_t adLen = fido_assert_authdata_raw_len(assert.get(), i);
    bool rpOk = LogAuthData(fido_assert_authdata_raw_ptr(assert.get(), i), adLen, rpId, log);
    uint8_t flags = fido_assert_flags(assert.get(), i);
    uint32_t count = fido_assert_sigcount(assert.get(), i);

    if (!match) {
      log("      unknown credential (not registered in this session) - no public key to verify with");
      failReason = "The authenticator used a credential that was not registered in this session.";
      allOk = false;
      continue;
    }

    // Clone detection: a counter that does not increase hints at a cloned authenticator
    std::string counterText = std::to_string(count) + " (stored: " + std::to_string(match->signCount) + ")";
    if (count == 0 && match->signCount == 0)
      counterText += "  -> authenticator does not use a counter";
    else if (count > match->signCount)
      counterText += "  -> increased, OK";
    else
      counterText += "  -> WARNING: did not increase (cloned authenticator?)";
    log("      signCount      : " + counterText);

    log("      signed data    : authData (" + std::to_string(adLen) + " bytes) || clientDataHash (" +
      std::to_string(clientDataHash.size()) + " bytes)");
    log("      signature      : ECDSA P-256 / SHA-256, " + std::to_string(fido_assert_sig_len(assert.get(), i)) +
      " bytes DER  " + Hex(fido_assert_sig_ptr(assert.get(), i), fido_assert_sig_len(assert.get(), i)));

    if (!rpOk) {
      failReason = "The response was created for a different relying party (rpIdHash mismatch).";
      allOk = false;
      continue;
    }

    // Server side step: verify the signature over authData || clientDataHash with the stored public key
    Es256Ptr pk(es256_pk_new());
    if ((r = es256_pk_from_ptr(pk.get(), match->publicKey.data(), match->publicKey.size())) != FIDO_OK ||
      (r = fido_assert_verify(assert.get(), i, COSE_ES256, pk.get())) != FIDO_OK) {
      log("      verification   : INVALID - " + Err(r));
      failReason = (requireUv && !(flags & 0x04))
        ? "The authenticator did not verify the user (no PIN)."
        : "The signature is invalid: " + Err(r);
      allOk = false;
      continue;
    }
    log("      verification   : VALID with the public key stored at registration");

    match->signCount = count;
    signedIn.push_back(match->userName);
    summary +=
      "Relying party: " + rpId + "\n"
      "Signature: valid (ES256)\n"
      "User verified (PIN): " + YesNo(flags & 0x04) + "\n"
      "Signature counter: " + std::to_string(count) + "\n"
      "Credential ID: " + ShortHex(id) + "\n";
  }

  if (!allOk || signedIn.empty()) {
    log("Sign-in FAILED.");
    result.details = failReason.empty() ? "No valid assertion returned." : failReason;
    return result;
  }

  log("[5/5] Server: user authenticated");
  std::string users;
  for (const auto& u : signedIn)
    users += (users.empty() ? "" : ", ") + u;
  log("Sign-in OK - signed in as '" + users + "'.");

  result.ok = true;
  result.title = "Signed in as " + users;
  result.details = summary;
  return result;
}
