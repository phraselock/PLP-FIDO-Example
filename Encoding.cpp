#include "Encoding.h"

std::string Encoding::Hex(const uint8_t* data, size_t len)
{
  static const char digits[] = "0123456789abcdef";
  std::string s;
  s.reserve(len * 2);
  for (size_t i = 0; i < len; i++)
  {
    s += digits[data[i] >> 4];
    s += digits[data[i] & 0x0f];
  }
  return s;
}

std::string Encoding::Hex(const std::vector<uint8_t>& data)
{
  return Hex(data.data(), data.size());
}

bool Encoding::FromHex(const std::string& hex, std::vector<uint8_t>& out)
{
  auto nibble = [](char c) -> int
  {
    if (c >= '0' && c <= '9')
    {
      return c - '0';
    }
    if (c >= 'a' && c <= 'f')
    {
      return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F')
    {
      return c - 'A' + 10;
    }
    return -1;
  };

  if (hex.size() % 2 != 0)
  {
    return false;
  }
  out.clear();
  for (size_t i = 0; i < hex.size(); i += 2)
  {
    int hi = nibble(hex[i]);
    int lo = nibble(hex[i + 1]);
    if (hi < 0 || lo < 0)
    {
      return false;
    }
    out.push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return true;
}

std::string Encoding::Base64Url(const std::vector<uint8_t>& data)
{
  static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string out;
  size_t i = 0;
  for (; i + 2 < data.size(); i += 3)
  {
    uint32_t n = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
    out += tbl[(n >> 18) & 63];
    out += tbl[(n >> 12) & 63];
    out += tbl[(n >> 6) & 63];
    out += tbl[n & 63];
  }
  if (data.size() - i == 1)
  {
    uint32_t n = data[i] << 16;
    out += tbl[(n >> 18) & 63];
    out += tbl[(n >> 12) & 63];
  }
  else if (data.size() - i == 2)
  {
    uint32_t n = (data[i] << 16) | (data[i + 1] << 8);
    out += tbl[(n >> 18) & 63];
    out += tbl[(n >> 12) & 63];
    out += tbl[(n >> 6) & 63];
  }
  return out;  // no padding
}
