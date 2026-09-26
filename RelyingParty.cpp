// libfido2 pulls in OpenSSL headers - include them first
#include "Fido2Handles.h"
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <cstring>
#include <ctime>
#include <optional>

#include <nlohmann/json.hpp>

#include "AuthData.h"
#include "ClientData.h"
#include "Encoding.h"
#include "RelyingParty.h"

using namespace Fido2;
using Encoding::Hex;

namespace
{
  constexpr size_t CHALLENGE_LEN = 32;
  constexpr size_t USER_ID_LEN = 32;

  std::vector<uint8_t> RandomBytes(size_t len)
  {
    std::vector<uint8_t> buf(len);
    RAND_bytes(buf.data(), static_cast<int>(len));
    return buf;
  }

  std::string LocalTimestamp()
  {
    std::time_t now = std::time(nullptr);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &now);
#else
    localtime_r(&now, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    return buf;
  }

  // Logs authenticatorData and checks rpIdHash against SHA-256(rpId), as a relying party must
  bool LogAuthData(const std::vector<uint8_t>& data, const std::string& rpId, const LogFn& log)
  {
    log("      authData       : " + std::to_string(data.size()) + " bytes");
    std::optional<AuthData> ad = AuthData::Parse(data.data(), data.size());
    if (!ad)
    {
      log("      authData too short");
      return false;
    }
    bool match = ad->RpIdHashMatches(rpId);
    log("      rpIdHash       : " + Hex(ad->rpIdHash));
    log(std::string("                       ") + (match ? "== " : "!= ") + "SHA-256(\"" + rpId + "\")  -> " +
      (match ? "OK" : "MISMATCH"));
    log("      flags          : " + ad->FlagsText());
    return match;
  }

  std::string CertName(const unsigned char* der, size_t len, bool issuer)
  {
    const unsigned char* p = der;
    X509* cert = d2i_X509(nullptr, &p, static_cast<long>(len));
    if (cert == nullptr)
    {
      return "(unparseable certificate)";
    }
    char buf[512];
    X509_NAME_oneline(issuer ? X509_get_issuer_name(cert) : X509_get_subject_name(cert), buf, sizeof(buf));
    X509_free(cert);
    return buf;
  }

  FidoError ParseError(int r)
  {
    return { "parsing the authenticator response: " + ErrorText(r), "Could not parse the authenticator response: " + ErrorText(r), {} };
  }

  // The signatures only prove that clientDataJSON was not altered - what it says must be checked here:
  //   type      "webauthn.create" / "webauthn.get" - a sign-in response cannot pass as a registration
  //   challenge the one issued for *this* request   - an old, recorded response cannot be replayed
  //   origin    the site the user actually talked to - responses relayed from a phishing site fail
  bool CheckClientData(const std::string& clientDataJson, const char* expectedType, const std::vector<uint8_t>& challenge,
    const std::string& expectedOrigin, const LogFn& log, FidoError& error)
  {
    nlohmann::json cd = nlohmann::json::parse(clientDataJson, nullptr, false);  // false: no exceptions
    if (cd.is_discarded() || !cd.is_object())
    {
      error = { "clientDataJSON is not a JSON object", "The client data could not be read.", {} };
      return false;
    }
    auto field = [&cd](const char* key) -> std::string
    {
      auto it = cd.find(key);
      return (it != cd.end() && it->is_string()) ? it->get<std::string>() : std::string();
    };
    std::string type = field("type");
    std::string challengeB64 = field("challenge");
    std::string origin = field("origin");

    // base64url without padding is canonical, so comparing the encoded strings is sufficient
    bool typeOk = type == expectedType;
    bool challengeOk = challengeB64 == Encoding::Base64Url(challenge);
    bool originOk = origin == expectedOrigin;
    log("      clientData     : type " + type + (typeOk ? " OK" : " MISMATCH") +
      ", challenge " + (challengeOk ? "OK" : "MISMATCH") +
      ", origin " + origin + (originOk ? " OK" : " MISMATCH"));

    if (!typeOk)
    {
      error = { "clientDataJSON type is '" + type + "', expected '" + expectedType + "'",
        "The response is of the wrong type ('" + type + "' instead of '" + expectedType + "').", {} };
      return false;
    }
    if (!challengeOk)
    {
      error = { "challenge in clientDataJSON does not match the one issued for this request",
        "The response does not belong to this request (challenge mismatch) - possibly a replayed response.", {} };
      return false;
    }
    if (!originOk)
    {
      error = { "origin '" + origin + "' in clientDataJSON, expected '" + expectedOrigin + "'",
        "The response was created for a different origin (" + origin + ") - possibly a phishing site.", {} };
      return false;
    }
    return true;
  }
}

RelyingParty::RelyingParty(ICredentialStore& store, std::string rpName)
  : m_store(store)
  , m_rpName(std::move(rpName))
{
}

RegistrationOptions RelyingParty::BeginRegistration(const std::string& rpId, const std::string& userName,
  bool residentKey, bool userVerification) const
{
  RegistrationOptions options;
  options.rpId = rpId;
  options.rpName = m_rpName;
  options.userId = RandomBytes(USER_ID_LEN);
  options.userName = userName;
  options.challenge = RandomBytes(CHALLENGE_LEN);
  options.residentKey = residentKey;
  options.userVerification = userVerification;
  return options;
}

bool RelyingParty::VerifyRegistration(const RegistrationOptions& options, const RegistrationResponse& response,
  const LogFn& log, RegistrationResult& result, FidoError& error) const
{
  if (!CheckClientData(response.clientDataJson, ClientData::TYPE_CREATE, options.challenge, ExpectedOrigin(options.rpId), log, error))
  {
    return false;
  }

  // libfido2 does the parsing (COSE public key, attestation statement) and the signature check;
  // the expected values - RP ID, user verification - come from the options
  CredPtr cred(fido_cred_new());
  int r;
  if ((r = fido_cred_set_type(cred.get(), COSE_ES256)) != FIDO_OK ||
    (r = fido_cred_set_clientdata(cred.get(), reinterpret_cast<const unsigned char*>(response.clientDataJson.data()), response.clientDataJson.size())) != FIDO_OK ||
    (r = fido_cred_set_rp(cred.get(), options.rpId.c_str(), options.rpName.c_str())) != FIDO_OK ||
    (r = fido_cred_set_uv(cred.get(), options.userVerification ? FIDO_OPT_TRUE : FIDO_OPT_OMIT)) != FIDO_OK ||
    (r = fido_cred_set_authdata_raw(cred.get(), response.authData.data(), response.authData.size())) != FIDO_OK ||
    (r = fido_cred_set_fmt(cred.get(), response.format.c_str())) != FIDO_OK ||
    (!response.attStmt.empty() && (r = fido_cred_set_attstmt(cred.get(), response.attStmt.data(), response.attStmt.size())) != FIDO_OK))
  {
    error = ParseError(r);
    return false;
  }

  bool rpOk = LogAuthData(response.authData, options.rpId, log);
  uint8_t flags = fido_cred_flags(cred.get());
  log("      signCount      : " + std::to_string(fido_cred_sigcount(cred.get())));

  StoredCredential& sc = result.credential;
  sc.rpId = options.rpId;
  sc.userName = options.userName;
  sc.userId = options.userId;
  sc.credentialId.assign(fido_cred_id_ptr(cred.get()), fido_cred_id_ptr(cred.get()) + fido_cred_id_len(cred.get()));
  sc.publicKey.assign(fido_cred_pubkey_ptr(cred.get()), fido_cred_pubkey_ptr(cred.get()) + fido_cred_pubkey_len(cred.get()));
  sc.aaguid.assign(fido_cred_aaguid_ptr(cred.get()), fido_cred_aaguid_ptr(cred.get()) + fido_cred_aaguid_len(cred.get()));
  sc.signCount = fido_cred_sigcount(cred.get());
  result.userVerified = (flags & AuthData::FLAG_UV) != 0;

  log("      AAGUID         : " + Hex(sc.aaguid));
  log("      credential id  : " + std::to_string(sc.credentialId.size()) + " bytes  " + Hex(sc.credentialId));
  log("      public key     : ES256 (ECDSA P-256)");
  if (sc.publicKey.size() == 64)
  {
    log("                       x = " + Hex(sc.publicKey.data(), 32));
    log("                       y = " + Hex(sc.publicKey.data() + 32, 32));
  }
  else
  {
    log("                       " + Hex(sc.publicKey));
  }

  if (!rpOk)
  {
    error = { "rpIdHash does not match SHA-256(rp.id)", "The response was created for a different relying party (rpIdHash mismatch).", {} };
    return false;
  }
  if (options.userVerification && !result.userVerified)
  {
    error = { "UV flag missing although user verification was required", "The authenticator did not verify the user (no PIN).", {} };
    return false;
  }

  // Verify the attestation signature over authData || clientDataHash
  const char* fmt = fido_cred_fmt(cred.get());
  if (fmt == nullptr || strcmp(fmt, "none") == 0)
  {
    log("      attestation    : none - no attestation statement provided, nothing to verify");
    result.attestation = "none";
    return true;
  }

  size_t certs = fido_cred_x5c_list_count(cred.get());
  log("      attestation    : " + std::string(fmt) + ", " +
    (certs ? std::to_string(certs) + " certificate(s)" : std::string("self attestation (no certificate)")));
  for (size_t i = 0; i < certs; i++)
  {
    const unsigned char* der = fido_cred_x5c_list_ptr(cred.get(), i);
    size_t len = fido_cred_x5c_list_len(cred.get(), i);
    log("                       [" + std::to_string(i) + "] subject: " + CertName(der, len, false));
    log("                           issuer : " + CertName(der, len, true));
  }
  log("      attestation sig: " + std::to_string(fido_cred_sig_len(cred.get())) + " bytes over authData || clientDataHash");
  r = certs > 0 ? fido_cred_verify(cred.get()) : fido_cred_verify_self(cred.get());
  if (r != FIDO_OK)
  {
    error = { "attestation signature INVALID: " + ErrorText(r), "The attestation signature is invalid: " + ErrorText(r), {} };
    return false;
  }
  log(std::string("      verification   : VALID (") + (certs ? "attestation certificate" : "credential public key") + ")");
  result.attestation = std::string(fmt) + " - signature valid";
  return true;
}

bool RelyingParty::StoreCredential(StoredCredential& credential, FidoError& error)
{
  credential.created = LocalTimestamp();
  if (!m_store.Add(credential))
  {
    error = { "could not save the credential store: " + m_store.Location(),
      "The authenticator created the credential, but it could not be saved to\n" + m_store.Location(), {} };
    return false;
  }
  return true;
}

std::vector<StoredCredential> RelyingParty::CredentialsFor(const std::string& rpId) const
{
  return m_store.FindByRpId(rpId);
}

AuthenticationOptions RelyingParty::BeginAuthentication(const std::string& rpId, bool discoverable, bool userVerification) const
{
  AuthenticationOptions options;
  options.rpId = rpId;
  options.challenge = RandomBytes(CHALLENGE_LEN);
  options.userVerification = userVerification;
  if (!discoverable)
  {
    for (const StoredCredential& c : m_store.FindByRpId(rpId))
    {
      options.allowCredentials.push_back(c.credentialId);
    }
  }
  return options;
}

bool RelyingParty::VerifyAssertion(const AuthenticationOptions& options, const AssertionResponse& response,
  const LogFn& log, AuthenticationResult& result, FidoError& error)
{
  std::optional<StoredCredential> match = m_store.FindById(response.credentialId);

  log("      credential id  : " + Hex(response.credentialId) + (match ? "  -> '" + match->userName + "'" : "  -> unknown"));
  if (!response.userHandle.empty())
  {
    log("      user.id        : " + Hex(response.userHandle));
  }
  if (!response.userName.empty())
  {
    log("      user.name      : " + response.userName + "  (returned by the authenticator)");
  }

  if (!CheckClientData(response.clientDataJson, ClientData::TYPE_GET, options.challenge, ExpectedOrigin(options.rpId), log, error))
  {
    return false;
  }

  // libfido2 checks the signature (and the UP/UV flags requested here) against the stored public key
  AssertPtr assertion(fido_assert_new());
  int r;
  if ((r = fido_assert_set_clientdata(assertion.get(), reinterpret_cast<const unsigned char*>(response.clientDataJson.data()), response.clientDataJson.size())) != FIDO_OK ||
    (r = fido_assert_set_rp(assertion.get(), options.rpId.c_str())) != FIDO_OK ||
    (r = fido_assert_set_up(assertion.get(), FIDO_OPT_TRUE)) != FIDO_OK ||
    // uv=true also makes fido_assert_verify() reject assertions without the UV flag
    (r = fido_assert_set_uv(assertion.get(), options.userVerification ? FIDO_OPT_TRUE : FIDO_OPT_OMIT)) != FIDO_OK ||
    (r = fido_assert_set_count(assertion.get(), 1)) != FIDO_OK ||
    (r = fido_assert_set_authdata_raw(assertion.get(), 0, response.authData.data(), response.authData.size())) != FIDO_OK ||
    (r = fido_assert_set_sig(assertion.get(), 0, response.signature.data(), response.signature.size())) != FIDO_OK)
  {
    error = ParseError(r);
    return false;
  }

  bool rpOk = LogAuthData(response.authData, options.rpId, log);
  uint8_t flags = fido_assert_flags(assertion.get(), 0);
  uint32_t count = fido_assert_sigcount(assertion.get(), 0);

  if (!match)
  {
    log("      unknown credential (not in the credential store) - no public key to verify with");
    error = { {}, "The authenticator used a credential that is not in the credential store.", {} };
    return false;
  }

  // Clone detection: a counter that does not increase hints at a cloned authenticator
  std::string counterText = std::to_string(count) + " (stored: " + std::to_string(match->signCount) + ")";
  if (count == 0 && match->signCount == 0)
  {
    counterText += "  -> authenticator does not use a counter";
  }
  else if (count > match->signCount)
  {
    counterText += "  -> increased, OK";
  }
  else
  {
    counterText += "  -> WARNING: did not increase (cloned authenticator?)";
  }
  log("      signCount      : " + counterText);

  log("      signed data    : authData (" + std::to_string(response.authData.size()) + " bytes) || clientDataHash (" +
    std::to_string(ClientData::Hash(response.clientDataJson).size()) + " bytes)");
  log("      signature      : ECDSA P-256 / SHA-256, " + std::to_string(response.signature.size()) +
    " bytes DER  " + Hex(response.signature));

  if (!rpOk)
  {
    error = { {}, "The response was created for a different relying party (rpIdHash mismatch).", {} };
    return false;
  }

  // Verify the signature over authData || clientDataHash with the public key stored at registration
  Es256Ptr pk(es256_pk_new());
  if ((r = es256_pk_from_ptr(pk.get(), match->publicKey.data(), match->publicKey.size())) != FIDO_OK ||
    (r = fido_assert_verify(assertion.get(), 0, COSE_ES256, pk.get())) != FIDO_OK)
  {
    log("      verification   : INVALID - " + ErrorText(r));
    bool uvMissing = options.userVerification && !(flags & AuthData::FLAG_UV);
    error = { {}, uvMissing ? "The authenticator did not verify the user (no PIN)." : "The signature is invalid: " + ErrorText(r), {} };
    return false;
  }
  log("      verification   : VALID with the public key stored at registration");

  if (!m_store.UpdateSignCount(response.credentialId, count))
  {
    log("      WARNING: could not save the new signCount to " + m_store.Location());
  }

  result.userName = match->userName;
  result.credentialId = response.credentialId;
  result.signCount = count;
  result.userVerified = (flags & AuthData::FLAG_UV) != 0;
  return true;
}

std::string RelyingParty::ExpectedOrigin(const std::string& rpId)
{
  return "https://" + rpId;
}

std::string RelyingParty::StoreLocation() const
{
  return m_store.Location();
}

size_t RelyingParty::StoreCount() const
{
  return m_store.Count();
}
