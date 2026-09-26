#include <openssl/sha.h>

#include "ClientData.h"
#include "Encoding.h"

std::string ClientData::Build(const char* type, const std::vector<uint8_t>& challenge, const std::string& origin)
{
  return std::string("{\"type\":\"") + type +
    "\",\"challenge\":\"" + Encoding::Base64Url(challenge) +
    "\",\"origin\":\"" + origin +
    "\",\"crossOrigin\":false}";
}

std::vector<uint8_t> ClientData::Hash(const std::string& clientDataJson)
{
  std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
  SHA256(reinterpret_cast<const unsigned char*>(clientDataJson.data()), clientDataJson.size(), hash.data());
  return hash;
}
