#pragma once

// authenticatorData - the part of every WebAuthn response that the authenticator itself signs.
//
//   offset  size  field
//        0    32  rpIdHash          SHA-256 of the RP ID the credential belongs to
//       32     1  flags             UP, UV, BE, BS, AT, ED (see below)
//       33     4  signCount         signature counter, big endian
//       37     -  attestedCredentialData   only if AT is set (registration):
//                   aaguid (16) | credentialIdLength (2, big endian) | credentialId | COSE public key (CBOR)
//        -     -  extensions        only if ED is set (CBOR map)
//
// A relying party must check rpIdHash and the UP/UV flags itself - the signature alone does not
// prove that the response was meant for this RP or that the user was verified.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct AuthData
{
  static constexpr uint8_t FLAG_UP = 0x01;  // user present (touch)
  static constexpr uint8_t FLAG_UV = 0x04;  // user verified (PIN / biometrics)
  static constexpr uint8_t FLAG_BE = 0x08;  // backup eligible (credential may be synced)
  static constexpr uint8_t FLAG_BS = 0x10;  // backup state (credential is synced)
  static constexpr uint8_t FLAG_AT = 0x40;  // attested credential data present
  static constexpr uint8_t FLAG_ED = 0x80;  // extension data present

  std::vector<uint8_t> rpIdHash;
  uint8_t flags = 0;
  uint32_t signCount = 0;

  // Attested credential data (registration only, FLAG_AT). The COSE public key that follows is
  // left to libfido2 - decoding it would need a CBOR parser.
  std::vector<uint8_t> aaguid;
  std::vector<uint8_t> credentialId;

  // Returns std::nullopt if the data is too short for the fields announced by the flags
  static std::optional<AuthData> Parse(const uint8_t* data, size_t len);

  bool Has(uint8_t flag) const
  {
    return (flags & flag) != 0;
  }

  // rpIdHash == SHA-256(rpId)
  bool RpIdHashMatches(const std::string& rpId) const;

  // e.g. "0x45  UP=1 UV=1 BE=0 BS=0 AT=1 ED=0"
  std::string FlagsText() const;
};
