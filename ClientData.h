#pragma once

// clientDataJSON - built by the client (normally the browser), signed indirectly by the authenticator.
//
// The authenticator never sees the JSON itself, only its SHA-256 hash (clientDataHash). Its
// signature covers authenticatorData || clientDataHash, which binds the response to the server's
// challenge and to the origin the client was talking to.

#include <cstdint>
#include <string>
#include <vector>

namespace ClientData
{
  constexpr char TYPE_CREATE[] = "webauthn.create";  // registration
  constexpr char TYPE_GET[] = "webauthn.get";        // authentication

  // {"type":"...","challenge":"<base64url>","origin":"...","crossOrigin":false}
  std::string Build(const char* type, const std::vector<uint8_t>& challenge, const std::string& origin);

  // SHA-256(clientDataJSON) = clientDataHash
  std::vector<uint8_t> Hash(const std::string& clientDataJson);
}
