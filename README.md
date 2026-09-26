# PLP-FIDO-Example

Shows how an **application** can be secured with FIDO2 / WebAuthn: a small Windows desktop app
(MFC, C++20) registers a security key for a user and signs in with it - without a browser - and
explains every step in a log window. It is meant as a readable reference: each part of WebAuthn
lives in its own class and can be lifted out on its own.

Built on [libfido2](https://developers.yubico.com/libfido2/) and the Windows WebAuthn API
(`webauthn.dll`). Platforms: `ARM64` and `x64` (Visual Studio 2022, v143, static MFC).

---

## Contents

1. [What this project demonstrates](#what-this-project-demonstrates)
2. [The three roles of WebAuthn](#the-three-roles-of-webauthn)
3. [A registration and a sign-in, step by step](#a-registration-and-a-sign-in-step-by-step)
4. [Three ways to reach an authenticator on Windows](#three-ways-to-reach-an-authenticator-on-windows)
5. [What the relying party checks](#what-the-relying-party-checks)
6. [Architecture](#architecture)
7. [Credential store](#credential-store)
8. [Platform differences](#platform-differences)
9. [Limitations of the demo](#limitations-of-the-demo)
10. [Prerequisites and build](#prerequisites-and-build)
11. [Usage](#usage)
12. [Troubleshooting](#troubleshooting)
13. [Files](#files)

---

## What this project demonstrates

- **Both WebAuthn ceremonies end to end**: registration (*makeCredential*) and authentication
  (*getAssertion*), including the server side that is usually hidden behind a library.
- **Server and client strictly separated**: `RelyingParty` (server) and `IAuthenticatorClient`
  (client) only exchange the data structures WebAuthn defines - exactly what would travel over the
  network in a real deployment.
- **Every server check made visible**: rpIdHash, user presence / user verification flags,
  attestation certificate and signature, signature counter, assertion signature.
- **Three ways to talk to an authenticator on Windows**: libfido2 via HID, libfido2 via Windows
  Hello, and the Windows WebAuthn API called directly - with and without admin rights.
- **Security keys only**: how to keep Windows from offering Windows Hello when only a roaming
  authenticator (USB / NFC / BLE key) is wanted.
- **Discoverable credentials (passkeys)** vs. credentials that need an allow list.
- **User verification on demand**: touch only, or PIN required and enforced by the server.
- **Persisting credentials** behind an interface (`ICredentialStore`), in a human readable file.

---

## The three roles of WebAuthn

```
   +--------------------+        options / responses        +---------------------+        CTAP2        +-----------------+
   |  Relying Party     |  <------------------------------> |  Client             |  <----------------> |  Authenticator  |
   |  (server)          |    WebAuthnTypes.h (JSON in a     |  (browser / app,    |   USB / NFC / BLE   |  (security key, |
   |                    |    real deployment)               |   OS WebAuthn API)  |                     |   Windows Hello)|
   |  RelyingParty      |                                   |  IAuthenticatorClient                   |  e.g. PhraseLock|
   |  ICredentialStore  |                                   |  ClientData         |                     |                 |
   +--------------------+                                   +---------------------+                     +-----------------+
```

| Role | Responsibility | In this project |
|------|----------------|-----------------|
| **Relying Party (RP)** | Creates challenges, verifies responses, stores public keys. Never sees a private key. | `RelyingParty`, `ICredentialStore` / `CredentialStore` |
| **Client** | Builds `clientDataJSON` (challenge + origin), passes the request to the authenticator, returns the result unchanged. | `ClientData`, `LibFido2Client`, `WindowsWebAuthnClient` |
| **Authenticator** | Holds the private keys, asks for touch / PIN, signs. | Your security key or Windows Hello |

`FidoDemo` wires the three together and narrates what happens. In this demo all roles run in one
process. In a secured application the relying party is typically the application's backend - then
only `WebAuthnTypes.h` crosses the network - or, for a purely local application, the application
itself.

---

## A registration and a sign-in, step by step

The log below is a real run against a security key (`windows://hello`, *security keys only*,
touch only). Long hex values are shortened with `…`.

### Registration

```
=== Register (makeCredential) ===
  device            : windows://hello -> webauthn.dll directly (API v9), security keys only
  user verification : discouraged (touch only)
  discoverable      : no
[1/5] Server: create challenge and user handle
      rp.id          : security.mycompany.com
      user.name      : jane.dow@mycompany.com
      user.id        : 40fffb0f009b22851e4b1e36ae152239ee217b6d5bcf5e17a999ba998dff6050
      challenge      : FRysVE0akNehMZGuZAIwMP71SzF5mrxQqgfn6fPwxgM  (32 random bytes)
```
The server creates a random **challenge** and a random **user handle** (`user.id`). The user
handle is not the user name - it is an opaque identifier the authenticator stores with a
discoverable credential. A real server keeps both in the user's session.

```
[2/5] Client: build clientDataJSON and hash it
      clientDataJSON : {"type":"webauthn.create","challenge":"FRysVE0a…","origin":"https://security.mycompany.com","crossOrigin":false}
      clientDataHash : 67784737e77660460e8e5e4f26150cc6491d5537e30ad12241d97eb35ab6fd2b  (SHA-256)
```
The client wraps the challenge and the **origin** it is talking to into `clientDataJSON`. The
authenticator only ever sees its SHA-256 hash - but because it signs that hash, the response is
bound to this challenge and this origin (phishing protection).

```
[3/5] Authenticator: makeCredential
      >>> Touch your authenticator ...
      done after 5.4 s, transport: USB
```
The authenticator creates a new key pair for `security.mycompany.com` after the user touched it
(and entered the PIN if required).

```
[4/5] Server: parse and verify the response
      authData       : 202 bytes
      rpIdHash       : f6b7c2ceec588edd0f69e2ce394a2cfa87609f111001f7c2bf135ffd9e5507f4
                       == SHA-256("security.mycompany.com")  -> OK
      flags          : 0x45  UP=1 UV=1 BE=0 BS=0 AT=1 ED=0
      signCount      : 126
      AAGUID         : e86f75809198561be10b6e17443ec544
      credential id  : 70 bytes  b5505372c425fab3cfba7121eef8…7e000000
      public key     : ES256 (ECDSA P-256)
                       x = 4ddc6c1aa220eb433975f6460515c3ca9e1eb61fdfcd67811753e8d90b9f0b8a
                       y = b0ef00f5bfa5595b1f4f12746467f456e4773ad0ea988c84b7ac008f8b70dc68
      attestation    : packed, 1 certificate(s)
                       [0] subject: /C=AT/ST=SZG/L=Salzburg/OU=Authenticator Attestation/O=iPoxo IT GmbH/CN=PhraseLock Attestation v1.0
                           issuer : /C=AT/ST=SZG/L=Salzburg/OU=R&D/O=iPoxo IT GmbH/CN=PhraseLock Attestation CA v1.0/serialNumber=ca.0003-2026.03.14
      attestation sig: 71 bytes over authData || clientDataHash
      verification   : VALID (attestation certificate)
```
The response consists of **authenticatorData** (see [`AuthData.h`](AuthData.h) for the byte
layout) and an **attestation statement**:

- `rpIdHash` must equal SHA-256 of the RP ID - otherwise the credential was made for another site.
- `flags`: `UP` user present (touched), `UV` user verified (PIN / biometrics), `AT` attested
  credential data follows, `BE`/`BS` backup eligible / backed up (synced passkeys), `ED` extensions.
  `UV=1` here although only a touch was requested: Windows asked for the key's PIN anyway
  (see [Platform differences](#platform-differences)) - the sign-in below shows `UV=0`.
- `AAGUID` identifies the authenticator model, `credential id` is the handle the server will send
  back in the allow list, `public key` is what the server stores to verify future sign-ins.
- The **attestation** proves which kind of authenticator created the key: the authenticator signs
  `authData || clientDataHash` with its attestation key, the certificate identifies the vendor.

```
[5/5] Server: store credential for 'jane.dow@mycompany.com'
      saved to       : C:\Users\…\AppData\Roaming\PhraseLock\PLP-FIDO-Example\credentials.txt  (3 credential(s))
Registration OK.
```

### Sign-in

```
=== Sign In (getAssertion) ===
  device            : windows://hello -> webauthn.dll directly (API v9), security keys only
  user verification : discouraged (touch only)
[1/5] Server: create challenge
      rp.id          : security.mycompany.com
      challenge      : mqVyqfZnQEuxVKPXxtuGwzdihkHITghciWv1aJjs-gI  (32 random bytes)
      allowList      : 2 credential(s) registered for this RP
                       d9267bcdf406ffca73f376aba1f5…7b000000  (jane.dow@mycompany.com)
                       b5505372c425fab3cfba7121eef8…7e000000  (jane.dow@mycompany.com)
[2/5] Client: build clientDataJSON and hash it
      clientDataJSON : {"type":"webauthn.get","challenge":"mqVyqfZn…","origin":"https://security.mycompany.com","crossOrigin":false}
      clientDataHash : d1ac4dd7275f8ceb4030369d991492ea927dd20a91f3cb71268ad5d0ffdf54ba  (SHA-256)
[3/5] Authenticator: getAssertion
      >>> Touch your authenticator ...
      done after 2.7 s, 1 assertion(s) returned
```
The server sends a new challenge plus the **allow list** - the credential ids it knows for this
RP. With *Discoverable credential* ticked the allow list is empty and the authenticator picks the
account itself (passkey sign-in without a user name).

```
[4/5] Server: verify the assertion(s)
    assertion [0]
      credential id  : b5505372c425fab3cfba7121eef8…7e000000  -> 'jane.dow@mycompany.com'
      user.id        : 40fffb0f009b22851e4b1e36ae152239ee217b6d5bcf5e17a999ba998dff6050
      authData       : 37 bytes
      rpIdHash       : f6b7c2ceec588edd0f69e2ce394a2cfa87609f111001f7c2bf135ffd9e5507f4
                       == SHA-256("security.mycompany.com")  -> OK
      flags          : 0x01  UP=1 UV=0 BE=0 BS=0 AT=0 ED=0
      signCount      : 128 (stored: 126)  -> increased, OK
      signed data    : authData (37 bytes) || clientDataHash (32 bytes)
      signature      : ECDSA P-256 / SHA-256, 72 bytes DER  3046022100c6965e27…
      verification   : VALID with the public key stored at registration
[5/5] Server: user authenticated
Sign-in OK - signed in as 'jane.dow@mycompany.com'.
```
The server looks up the credential id, checks `rpIdHash` and the flags, compares the **signature
counter** with the stored value (a counter that does not increase hints at a cloned
authenticator) and finally verifies the **signature** over `authData || clientDataHash` with the
public key from the registration. That signature is the actual proof of possession of the
private key.

Both ceremonies end with a result dialog (`CTaskDialog`) summarising the outcome - handy for demos.

---

## Three ways to reach an authenticator on Windows

| Device in the list | Options | Client class | How it works | Admin rights |
|--------------------|---------|--------------|--------------|--------------|
| `windows://hello` | *security keys only* ticked (default) | `WindowsWebAuthnClient` | `webauthn.dll` called directly with `WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM`: Windows shows only the security key dialog | not needed |
| `windows://hello` | *security keys only* unticked | `LibFido2Client` | libfido2's Windows Hello backend, which forwards to `webauthn.dll`; Windows offers Windows Hello *and* security keys | not needed |
| HID device (e.g. `… [1050:0407]`) | - | `LibFido2Client` | libfido2 speaks CTAP2 over HID directly with the key, PIN from the PIN field | **required** |

Since Windows 10 1903 only elevated processes may talk to FIDO HID devices directly. Without admin
rights libfido2 does not list them at all; `windows://hello` covers security keys as well.

Why a direct `webauthn.dll` client: libfido2's Windows Hello backend always requests
`WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY` and has no option to change that, so Windows would always
offer Windows Hello. `WindowsWebAuthnClient` hands the raw authenticatorData, attestation statement
and signature back as `WebAuthnTypes`, and `RelyingParty` verifies them with libfido2 exactly like
the responses of the other two paths.

---

## What the relying party checks

| Check | Why | Where |
|-------|-----|-------|
| `rpIdHash == SHA-256(rpId)` | Response was made for this site, not for another one | `AuthData::RpIdHashMatches`, `RelyingParty` |
| `clientDataJSON` unchanged | The signatures cover `clientDataHash`, so the JSON cannot be altered | libfido2 (`fido_cred_verify` / `fido_assert_verify`) |
| Type, challenge, origin in `clientDataJSON` | Response belongs to this request and this site (no replay, no phishing) | **not implemented** - see [Limitations](#limitations-of-the-demo) |
| `UP` flag | User was present (touched the key) | libfido2 (`fido_assert_set_up`) |
| `UV` flag if user verification was required | PIN / biometrics were actually checked | `RelyingParty` + libfido2 (`fido_*_set_uv`) |
| Attestation signature | The key was created by a genuine authenticator of the stated model | `fido_cred_verify` / `fido_cred_verify_self` |
| Credential id is known | Only registered credentials can sign in | `ICredentialStore::FindById` |
| Signature counter increased | Hints at cloned authenticators | `RelyingParty::VerifyAssertion` |
| Assertion signature | Proof of possession of the private key | `fido_assert_verify` with the stored public key |

---

## Architecture

```
                    PLPFidoExampleDlg  (MFC dialog, worker thread, result dialog)
                            |
                        FidoDemo       (runs the ceremonies, narrates them in the log)
                     /      |       \
          RelyingParty  ClientData   IAuthenticatorClient
          (server)      (client)     (client -> authenticator)
             |                          /                \
      ICredentialStore       LibFido2Client      WindowsWebAuthnClient
             |               (libfido2)          (webauthn.dll)
      CredentialStore
      (%APPDATA% text file)

   shared: WebAuthnTypes.h (data between server and client), AuthData, Encoding, Fido2Handles.h
```

What to take for which purpose:

| You want to ... | Take |
|-----------------|------|
| verify WebAuthn responses on a server (C++) | `RelyingParty`, `AuthData`, `ClientData`, `Encoding`, `Fido2Handles.h`, `WebAuthnTypes.h`, `ICredentialStore.h` - platform independent (libfido2 + OpenSSL) |
| store credentials somewhere else (database, REST) | implement `ICredentialStore` |
| call security keys from a Windows app without admin rights | `WindowsWebAuthnClient` (+ `WebAuthnTypes.h`, `IAuthenticatorClient.h`) |
| talk CTAP2 to a key directly | `LibFido2Client` |
| understand the bytes | `AuthData.h` (authenticatorData layout), `ClientData.h` |

`FidoDemo` and everything below it is MFC-free (UTF-8 `std::string`, log callback), so all
operations run on a worker thread.

---

## Credential store

Registered credentials are kept behind the `ICredentialStore` interface - the relying party's side
of WebAuthn. `RelyingParty` only knows the interface; the implementation `CredentialStore` writes
`%APPDATA%\PhraseLock\PLP-FIDO-Example\credentials.txt`, a plain text file with one
`[credential]` block per entry. `rpId`, `userName`, `signCount` and `created` are plain text,
all binary values (`userId`, `credentialId`, `publicKey`, `aaguid`) are hex:

```
[credential]
rpId         = security.mycompany.com
userName     = jane.dow@mycompany.com
userId       = 40fffb0f009b22851e4b1e36ae152239ee217b6d5bcf5e17a999ba998dff6050
credentialId = b5505372c425fab3cfba7121eef8…7e000000
publicKey    = 4ddc6c1a…b70dc68           (ES256 x || y, 64 bytes)
aaguid       = e86f75809198561be10b6e17443ec544
signCount    = 128
created      = 2026-09-25 21:14:03
```

The file is written atomically (temp file + rename) after every change and can be inspected or
edited by hand. Unreadable entries are skipped with a warning on start, unknown keys are ignored.
Sign In with allow list therefore also works after a restart of the app.

---

## Platform differences

The same request can behave differently depending on the **client**, and the client is decided by
the operating system, not by the browser brand:

| Platform / browser | Who talks to the authenticator |
|--------------------|--------------------------------|
| Windows - every browser, and this app via `windows://hello` | `webauthn.dll` |
| macOS - Safari | Apple's platform FIDO stack |
| macOS / Linux - Chrome | Chrome's own CTAP implementation |
| macOS / Linux - Firefox | Mozilla's own CTAP implementation |

Observed with this project:

- **PIN on registration**: with a PIN set on the key, Windows (and Safari) ask for the PIN when
  registering, even with user verification *discouraged*; Chrome on macOS registered the same key
  without PIN. CTAP 2.0 requires the PIN for makeCredential once one is set; CTAP 2.1 relaxes that
  via the authenticator option `makeCredUvNotRqd`. Sign-in without PIN works everywhere.
- Other typical differences: Safari usually hides the attestation (`none`), `residentKey: preferred`
  is interpreted differently, Windows silently pre-checks allow list entries before asking for a
  touch, extension support (`prf` / `hmac-secret`, `largeBlob`, `credProps`) varies.

Consequences: test an authenticator with at least Windows, Chrome on macOS/Linux and Safari, and let
a server rely only on what it *requires* - and check it (as `RelyingParty` does).

---

## Limitations of the demo

- **No attestation trust**: the attestation signature and the certificate are checked, but the
  certificate is **not** validated against a trusted root or the
  [FIDO Metadata Service](https://fidoalliance.org/metadata/). Any self-made CA would pass.
- **ES256 only** (ECDSA P-256); no RS256 / EdDSA.
- **No real server and no real origin**: the RP runs in the same process, the origin is simulated as
  `https://<rp id>`, and `clientDataJSON` is not parsed by the server (its integrity is covered by
  the signatures, but a real server must also compare type, challenge and origin).
- **No session handling**: the options of *Begin* are passed back into *Verify* directly.
- The PIN field is only used for direct HID access.

---

## Prerequisites and build

- Visual Studio 2022 with
  - *Desktop development with C++*
  - *C++ MFC for latest v143 build tools* (for ARM64: the *ARM64/ARM64EC* variant)
  - *vcpkg package manager* (included in the C++ workload since VS 17.6)
- One-time vcpkg MSBuild integration (Developer PowerShell for VS 2022):

  ```
  vcpkg integrate install
  ```

Open `PLP-FIDO-Example.sln`, select `ARM64` (or `x64`) and build.

libfido2 and its dependencies are resolved from `vcpkg.json` (manifest mode, pinned by
`builtin-baseline`) on the first build and linked **statically** (`arm64-windows-static` /
`x64-windows-static`). The result is a single self-contained `PLP-FIDO-Example.exe`.

| Library | Version |
|---------|---------|
| libfido2 | 1.17.0 |
| OpenSSL | 3.6.3 |
| libcbor | 0.14.0 |
| zlib | 1.3.2 |

The first build per platform takes several minutes because OpenSSL is compiled from source; later
builds (also Debug/Release switches) reuse the installed packages in `vcpkg_installed\`. That
folder is not part of the repository; its `*\vcpkg\blds` and `*\vcpkg\pkgs` subfolders are
intermediate files and can be deleted without triggering a rebuild.

---

## Usage

1. **Device**: pick an authenticator. `windows://hello` uses the Windows WebAuthn API
   (`webauthn.dll`) and covers Windows Hello *and* USB/NFC security keys via the system dialog.
   HID devices only appear when the app runs as Administrator.
2. **Device Info**: prints CTAP versions, extensions, AAGUID, options (`authenticatorGetInfo`).
   For `windows://hello` libfido2 returns fixed placeholder values - Windows does not expose the
   real authenticator info; use a HID device (as Administrator) to see the key's actual data.
3. **Register**: creates an ES256 credential for *RP ID* / *User*, verifies the attestation
   and saves credential id + public key in the credential store.
4. **Sign In**: requests an assertion (allow list = credentials in the store for this RP)
   and verifies the signature with the stored public key - exactly what a relying party does.
5. **Discoverable credential**: on Register creates a resident key (passkey); on Sign In
   sends an empty allow list, so the authenticator chooses the account.
6. **windows://hello: security keys only** (default on): Windows shows only the security key
   dialog (USB / NFC / BLE), no Windows Hello. Unticked, libfido2's own Windows Hello backend is
   used and Windows offers both.
7. **Require PIN (user verification)**: ticked = `uv` required (PIN / biometrics), and the
   signature check additionally demands the UV flag - as a relying party would. Unticked = touch only
   (`discouraged`). Some keys / platforms still ask for the PIN on registration (see
   [Platform differences](#platform-differences)).

The PIN field is only used for direct HID access with *Require PIN* ticked (it is disabled
otherwise). With `windows://hello` Windows collects PIN / biometrics in its own dialog.

---

## Troubleshooting

| Symptom | Cause / solution |
|---------|------------------|
| Only `windows://hello` in the device list | The app is not elevated - Windows hides FIDO HID devices from normal processes. Run as Administrator, or use `windows://hello`. If the key still does not appear as Administrator, Windows does not see it as a HID device (e.g. connected through a different channel). |
| `fido_dev_open … Hint: Windows blocks raw FIDO HID access …` | Same cause, see above. |
| PIN is requested although *Require PIN* is unticked | Windows asks for the PIN on registration if the key has one (see [Platform differences](#platform-differences)). |
| App disappeared after confirming the Windows PIN dialog with Enter (older builds) | When elevated, the Enter key could reach the app's dialog as `IDOK` and close it. Fixed: `OnOK()` is ignored. |
| Sign In: *No credential registered …* | Register first, or tick *Discoverable credential* to sign in without allow list. |
| Device Info shows AAGUID `000…0` | `windows://hello` - libfido2 returns placeholder values there (see [Usage](#usage)). |

libfido2's Windows Hello backend needs the full `clientDataJSON`
(`fido_cred_set_clientdata` / `fido_assert_set_clientdata`), not just its hash - that is why
`ClientData` builds the JSON instead of only a hash.

---

## Files

| File | Purpose |
|------|---------|
| `RelyingParty.h/.cpp` | Server side: challenges, verification of registration and sign-in, platform independent |
| `IAuthenticatorClient.h` | Client side interface: MakeCredential / GetAssertion |
| `LibFido2Client.h/.cpp` | Client via libfido2 (direct HID or libfido2's Windows Hello backend), device list and info |
| `WindowsWebAuthnClient.h/.cpp` | Client via Windows WebAuthn API (`webauthn.dll`), security keys only |
| `WebAuthnTypes.h` | Data exchanged between server and client (options, responses) |
| `ClientData.h/.cpp` | Builds and hashes clientDataJSON |
| `AuthData.h/.cpp` | Parses authenticatorData (rpIdHash, flags, signCount, AAGUID, credential id) |
| `ICredentialStore.h` | Interface + `StoredCredential` for the relying party's credential storage |
| `CredentialStore.h/.cpp` | `ICredentialStore` implementation: text file in `%APPDATA%` |
| `Encoding.h/.cpp` | Hex and base64url |
| `Fido2Handles.h` | RAII wrappers for libfido2 handles |
| `FidoDemo.h/.cpp` | Runs the ceremonies step by step and narrates them in the log |
| `PLPFidoExampleDlg.h/.cpp` | Dialog, runs FIDO operations on a worker thread |
| `PLPFidoExample.h/.cpp` | `CWinApp`, calls `fido_init()` |
| `vcpkg.json` | libfido2 dependency (vcpkg manifest) |
