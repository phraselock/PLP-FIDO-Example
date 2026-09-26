#include <chrono>
#include <cstdio>

#include "ClientData.h"
#include "Encoding.h"
#include "FidoDemo.h"
#include "WindowsWebAuthnClient.h"

using Encoding::Base64Url;
using Encoding::Hex;

namespace
{
  constexpr char RP_NAME[] = "PLP FIDO Example";

  using Clock = std::chrono::steady_clock;

  // Abbreviated hex for the result dialog: "3f2a1b9c...e0d1 (64 bytes)"
  std::string ShortHex(const std::vector<uint8_t>& v)
  {
    if (v.size() <= 12)
    {
      return Hex(v);
    }
    return Hex(v.data(), 8) + "..." + Hex(v.data() + v.size() - 2, 2) + " (" + std::to_string(v.size()) + " bytes)";
  }

  std::string Seconds(Clock::time_point start)
  {
    char buf[32];
    snprintf(buf, sizeof(buf), "%.1f s", std::chrono::duration<double>(Clock::now() - start).count());
    return buf;
  }

  std::string YesNo(bool b)
  {
    return b ? "yes" : "no";
  }

  // This demo acts as its own website: the origin a browser would put into clientDataJSON
  std::string Origin(const std::string& rpId)
  {
    return "https://" + rpId;
  }

  // Logs a failed step and turns it into the result shown in the dialog
  FidoResult Fail(const std::string& title, const std::string& ceremony, const FidoError& error, const LogFn& log)
  {
    if (!error.logText.empty())
    {
      log("ERROR: " + error.logText);
    }
    if (!error.hint.empty())
    {
      log("  Hint: " + error.hint);
    }
    log(ceremony + " FAILED.");

    FidoResult result;
    result.title = title;
    result.details = error.reason + (error.hint.empty() ? "" : "\n\n" + error.hint);
    return result;
  }
}

FidoDemo::FidoDemo(ICredentialStore& store)
  : m_rp(store, RP_NAME)
{
}

void FidoDemo::Init()
{
  LibFido2Client::Init();
}

std::vector<FidoDevice> FidoDemo::ListDevices(const LogFn& log)
{
  return LibFido2Client::ListDevices(log);
}

bool FidoDemo::IsElevated()
{
  return LibFido2Client::IsElevated();
}

bool FidoDemo::DeviceInfo(const std::string& path, const LogFn& log)
{
  return LibFido2Client::DeviceInfo(path, log);
}

std::unique_ptr<IAuthenticatorClient> FidoDemo::CreateClient(const std::string& path, const std::string& pin, bool roamingOnly)
{
  // libfido2's winhello backend can't restrict Windows to security keys -> talk to webauthn.dll ourselves
  if (roamingOnly && path == LibFido2Client::WINHELLO_PATH)
  {
    return std::make_unique<WindowsWebAuthnClient>(true);
  }
  return std::make_unique<LibFido2Client>(path, pin);
}

FidoResult FidoDemo::Register(const std::string& path, const std::string& rpId, const std::string& userName,
  const std::string& pin, bool discoverable, bool roamingOnly, bool requireUv, const LogFn& log)
{
  auto fail = [&](const FidoError& error)
  {
    return Fail("Registration failed", "Registration", error, log);
  };

  std::unique_ptr<IAuthenticatorClient> client = CreateClient(path, pin, roamingOnly);

  log("=== Register (makeCredential) ===");
  log("  device            : " + client->Description());
  log(std::string("  user verification : ") + (requireUv ? "required (PIN)" : "discouraged (touch only)"));
  log("  discoverable      : " + YesNo(discoverable));
  if (rpId.empty() || userName.empty())
  {
    return fail({ "RP ID and user name are required", "RP ID and user name are required.", {} });
  }

  // In a real deployment the options come from the server (e.g. plp-fido2 /register/start)
  log("[1/5] Server: create challenge and user handle");
  RegistrationOptions options = m_rp.BeginRegistration(rpId, userName, discoverable, requireUv);
  log("      rp.id          : " + options.rpId);
  log("      user.name      : " + options.userName);
  log("      user.id        : " + Hex(options.userId));
  log("      challenge      : " + Base64Url(options.challenge) + "  (" + std::to_string(options.challenge.size()) + " random bytes)");

  log("[2/5] Client: build clientDataJSON and hash it");
  std::string clientData = ClientData::Build(ClientData::TYPE_CREATE, options.challenge, Origin(rpId));
  log("      clientDataJSON : " + clientData);
  log("      clientDataHash : " + Hex(ClientData::Hash(clientData)) + "  (SHA-256)");

  log("[3/5] Authenticator: makeCredential");
  log(requireUv ? "      >>> Enter your PIN and touch your authenticator ..." : "      >>> Touch your authenticator ...");
  Clock::time_point start = Clock::now();
  RegistrationResponse response;
  FidoError error;
  if (!client->MakeCredential(options, clientData, response, error))
  {
    return fail(error);
  }
  log("      done after " + Seconds(start) + (response.transport.empty() ? "" : ", transport: " + response.transport));

  log("[4/5] Server: parse and verify the response");
  RegistrationResult registration;
  if (!m_rp.VerifyRegistration(options, response, log, registration, error))
  {
    return fail(error);
  }

  log("[5/5] Server: store credential for '" + userName + "'");
  if (!m_rp.StoreCredential(registration.credential, error))
  {
    return fail(error);
  }
  log("      saved to       : " + m_rp.StoreLocation() + "  (" + std::to_string(m_rp.StoreCount()) + " credential(s))");

  FidoResult result;
  result.ok = true;
  result.title = "Registration successful";
  result.details =
    "User: " + userName + "\n"
    "Relying party: " + rpId + "\n"
    "Credential ID: " + ShortHex(registration.credential.credentialId) + "\n"
    "Authenticator AAGUID: " + Hex(registration.credential.aaguid) + "\n"
    "User verified (PIN): " + YesNo(registration.userVerified) + "\n"
    "Discoverable (passkey): " + YesNo(discoverable) + "\n"
    "Attestation: " + registration.attestation;

  log("Registration OK.");
  return result;
}

FidoResult FidoDemo::SignIn(const std::string& path, const std::string& rpId, const std::string& pin,
  bool discoverable, bool roamingOnly, bool requireUv, const LogFn& log)
{
  auto fail = [&](const FidoError& error)
  {
    return Fail("Sign-in failed", "Sign-in", error, log);
  };

  std::unique_ptr<IAuthenticatorClient> client = CreateClient(path, pin, roamingOnly);

  log("=== Sign In (getAssertion) ===");
  log("  device            : " + client->Description());
  log(std::string("  user verification : ") + (requireUv ? "required (PIN)" : "discouraged (touch only)"));

  // The credentials the server knows for this relying party (loaded from the credential store)
  std::vector<StoredCredential> candidates = m_rp.CredentialsFor(rpId);
  if (!discoverable && candidates.empty())
  {
    return fail({ "no credential registered for RP '" + rpId + "'",
      "No credential registered for '" + rpId + "' in the credential store.",
      "Register first, or tick 'Discoverable credential' to sign in without allow list." });
  }

  // In a real deployment the options come from the server (e.g. plp-fido2 /login/start)
  log("[1/5] Server: create challenge");
  AuthenticationOptions options = m_rp.BeginAuthentication(rpId, discoverable, requireUv);
  log("      rp.id          : " + options.rpId);
  log("      challenge      : " + Base64Url(options.challenge) + "  (" + std::to_string(options.challenge.size()) + " random bytes)");
  if (discoverable)
  {
    log("      allowList      : empty -> the authenticator chooses the account (discoverable credential)");
  }
  else
  {
    log("      allowList      : " + std::to_string(candidates.size()) + " credential(s) registered for this RP");
    for (const StoredCredential& c : candidates)
    {
      log("                       " + Hex(c.credentialId) + "  (" + c.userName + ")");
    }
  }

  log("[2/5] Client: build clientDataJSON and hash it");
  std::string clientData = ClientData::Build(ClientData::TYPE_GET, options.challenge, Origin(rpId));
  log("      clientDataJSON : " + clientData);
  log("      clientDataHash : " + Hex(ClientData::Hash(clientData)) + "  (SHA-256)");

  log("[3/5] Authenticator: getAssertion");
  log(requireUv ? "      >>> Enter your PIN and touch your authenticator ..." : "      >>> Touch your authenticator ...");
  Clock::time_point start = Clock::now();
  std::vector<AssertionResponse> responses;
  FidoError error;
  if (!client->GetAssertion(options, clientData, responses, error))
  {
    return fail(error);
  }
  log("      done after " + Seconds(start) + ", " + std::to_string(responses.size()) + " assertion(s) returned");

  log("[4/5] Server: verify the assertion(s)");
  bool allOk = true;
  std::string failReason;
  std::vector<std::string> signedIn;
  std::string summary;

  for (size_t i = 0; i < responses.size(); i++)
  {
    log("    assertion [" + std::to_string(i) + "]");
    AuthenticationResult auth;
    if (!m_rp.VerifyAssertion(options, responses[i], log, auth, error))
    {
      if (!error.logText.empty())
      {
        log("ERROR: " + error.logText);
      }
      failReason = error.reason;
      allOk = false;
      continue;
    }

    signedIn.push_back(auth.userName);
    summary +=
      "Relying party: " + rpId + "\n"
      "Signature: valid (ES256)\n"
      "User verified (PIN): " + YesNo(auth.userVerified) + "\n"
      "Signature counter: " + std::to_string(auth.signCount) + "\n"
      "Credential ID: " + ShortHex(auth.credentialId) + "\n";
  }

  if (!allOk || signedIn.empty())
  {
    log("Sign-in FAILED.");
    FidoResult result;
    result.title = "Sign-in failed";
    result.details = failReason.empty() ? "No valid assertion returned." : failReason;
    return result;
  }

  log("[5/5] Server: user authenticated");
  std::string users;
  for (const auto& u : signedIn)
  {
    users += (users.empty() ? "" : ", ") + u;
  }
  log("Sign-in OK - signed in as '" + users + "'.");

  FidoResult result;
  result.ok = true;
  result.title = "Signed in as " + users;
  result.details = summary;
  return result;
}
