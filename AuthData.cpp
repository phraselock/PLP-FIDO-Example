#include <openssl/sha.h>

#include <algorithm>
#include <cstdio>

#include "AuthData.h"

namespace
{
  constexpr size_t RPID_HASH_LEN = 32;
  constexpr size_t FIXED_LEN = RPID_HASH_LEN + 1 + 4;  // rpIdHash | flags | signCount
  constexpr size_t AAGUID_LEN = 16;

  uint32_t BigEndian32(const uint8_t* p)
  {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
      (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
  }
}

std::optional<AuthData> AuthData::Parse(const uint8_t* data, size_t len)
{
  if (data == nullptr || len < FIXED_LEN)
  {
    return std::nullopt;
  }

  AuthData ad;
  ad.rpIdHash.assign(data, data + RPID_HASH_LEN);
  ad.flags = data[RPID_HASH_LEN];
  ad.signCount = BigEndian32(data + RPID_HASH_LEN + 1);

  if (ad.Has(FLAG_AT))
  {
    size_t pos = FIXED_LEN;
    if (len < pos + AAGUID_LEN + 2)
    {
      return std::nullopt;
    }
    ad.aaguid.assign(data + pos, data + pos + AAGUID_LEN);
    pos += AAGUID_LEN;
    size_t idLen = (static_cast<size_t>(data[pos]) << 8) | data[pos + 1];
    pos += 2;
    if (len < pos + idLen)
    {
      return std::nullopt;
    }
    ad.credentialId.assign(data + pos, data + pos + idLen);
  }
  return ad;
}

bool AuthData::RpIdHashMatches(const std::string& rpId) const
{
  uint8_t expected[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(rpId.data()), rpId.size(), expected);
  return rpIdHash.size() == sizeof(expected) && std::equal(rpIdHash.begin(), rpIdHash.end(), expected);
}

std::string AuthData::FlagsText() const
{
  char buf[80];
  snprintf(buf, sizeof(buf), "0x%02x  UP=%d UV=%d BE=%d BS=%d AT=%d ED=%d", flags,
    Has(FLAG_UP), Has(FLAG_UV), Has(FLAG_BE), Has(FLAG_BS), Has(FLAG_AT), Has(FLAG_ED));
  return buf;
}
