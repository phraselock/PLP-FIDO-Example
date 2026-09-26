#pragma once

// Byte encodings used by WebAuthn and by this demo:
//   Hex       - human readable dumps (log, credential store)
//   Base64url - WebAuthn's text encoding for binary values (e.g. the challenge in clientDataJSON)

#include <cstdint>
#include <string>
#include <vector>

namespace Encoding
{
  // Lowercase hex, two characters per byte
  std::string Hex(const uint8_t* data, size_t len);
  std::string Hex(const std::vector<uint8_t>& data);

  // Accepts upper- and lowercase; returns false on odd length or non-hex characters
  bool FromHex(const std::string& hex, std::vector<uint8_t>& out);

  // RFC 4648 base64url without padding, as required by WebAuthn
  std::string Base64Url(const std::vector<uint8_t>& data);
}
