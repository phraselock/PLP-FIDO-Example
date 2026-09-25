# PLP-FIDO-Example

Minimal MFC dialog application demonstrating FIDO2 **Register** (makeCredential) and
**Sign In** (getAssertion) on Windows using [libfido2](https://developers.yubico.com/libfido2/).

Platforms: `ARM64` and `x64` (Visual Studio 2022, v143, static MFC).

## Prerequisites

- Visual Studio 2022 with
  - *Desktop development with C++*
  - *C++ MFC for latest v143 build tools* (for ARM64: the *ARM64/ARM64EC* variant)
  - *vcpkg package manager* (included in the C++ workload since VS 17.6)
- One-time vcpkg MSBuild integration (Developer PowerShell for VS 2022):

  ```
  vcpkg integrate install
  ```

## Build

Open `PLP-FIDO-Example.sln`, select `ARM64` (or `x64`) and build.

libfido2 and its dependencies (OpenSSL, libcbor, zlib) are resolved from `vcpkg.json`
(manifest mode) on the first build and linked **statically** (`arm64-windows-static` /
`x64-windows-static`). The result is a single self-contained `PLP-FIDO-Example.exe`.
The first build takes a few minutes because OpenSSL is compiled from source.

## Usage

1. **Device**: pick an authenticator. `windows://hello` uses the Windows WebAuthn API
   (`webauthn.dll`) and covers Windows Hello *and* USB/NFC security keys via the system dialog.
2. **Device Info**: prints CTAP versions, extensions, AAGUID, options (`authenticatorGetInfo`).
3. **Register**: creates an ES256 credential for *RP ID* / *User*, verifies the attestation
   and keeps credential ID + public key in memory.
4. **Sign In**: requests an assertion (allow list = credentials registered in this session)
   and verifies the signature with the stored public key - exactly what a relying party
   server (e.g. plp-fido2) does.
5. **Discoverable credential**: on Register creates a resident key (passkey); on Sign In
   sends an empty allow list, so the authenticator chooses the account.
6. **windows://hello: security keys only** (default on): Windows shows only the security key
   dialog (USB / NFC / BLE), no Windows Hello. Unticked, libfido2's own Windows Hello backend is
   used and Windows offers both.
7. **Require PIN (user verification)**: ticked = `uv` required (PIN / biometrics), and the
   signature check additionally demands the UV flag - as a relying party would. Unticked = touch only
   (`discouraged`). Some keys still ask for the PIN when creating a discoverable credential.

Register and Sign In log every step of the WebAuthn ceremony (server challenge, clientDataJSON and
its hash, authenticator call with duration, decoded authenticatorData incl. rpIdHash check, flags,
signature counter, attestation certificate chain, signature) and end with a result dialog
(`CTaskDialog`) summarising the outcome - handy for demos.

## Windows specifics

- Since Windows 10 1903, **non-elevated processes cannot talk to FIDO HID devices directly**.
  Raw HID devices appear in the list but `fido_dev_open`/transactions fail unless the app is
  run as Administrator. Use `windows://hello` otherwise.
- The PIN field is only used for direct HID access with *Require PIN* ticked (it is disabled
  otherwise). With `windows://hello` Windows collects PIN/biometrics in its own dialog.
- libfido2's Windows Hello backend always requests `WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY` and
  has no option to change that. For *security keys only* the app therefore calls `webauthn.dll`
  directly (`WinWebAuthn.cpp`, `WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM`) and hands the raw
  authenticatorData / attestation / signature to libfido2 for parsing and verification.
- libfido2's Windows Hello backend needs the full `clientDataJSON`
  (`fido_cred_set_clientdata` / `fido_assert_set_clientdata`), not just its hash.

## Credential store

Registered credentials are kept behind the `ICredentialStore` interface - the relying party's side
of WebAuthn. `FidoDemo` only knows the interface; the implementation `CredentialStore` writes
`%APPDATA%\PhraseLock\PLP-FIDO-Example\credentials.txt`, a plain text file with one
`[credential]` block per entry. `rpId`, `userName`, `signCount` and `created` are plain text,
all binary values (`userId`, `credentialId`, `publicKey`, `aaguid`) are hex:

```
[credential]
rpId         = example.phraselock.com
userName     = alice
userId       = 3f2a1b9c...
credentialId = a17c55e0...
publicKey    = e1d2...            (ES256 x || y, 64 bytes)
aaguid       = 2fc0579f811347eab116bb5a8db9202a
signCount    = 5
created      = 2026-09-25 14:32:10
```

The file is written atomically (temp file + rename) after every change and can be inspected or
edited by hand. Sign In with allow list therefore also works after a restart of the app.

## Files

| File | Purpose |
|------|---------|
| `FidoDemo.h/.cpp` | All libfido2 code (MFC-free, UTF-8, log callback) |
| `ICredentialStore.h` | Interface + `StoredCredential` for the relying party's credential storage |
| `CredentialStore.h/.cpp` | `ICredentialStore` implementation: text file in `%APPDATA%` |
| `WinWebAuthn.h/.cpp` | Direct `webauthn.dll` calls for the security-keys-only mode |
| `PLPFidoExampleDlg.h/.cpp` | Dialog, runs FIDO operations on a worker thread |
| `PLPFidoExample.h/.cpp` | `CWinApp`, calls `fido_init()` |
| `vcpkg.json` | libfido2 dependency (vcpkg manifest) |
