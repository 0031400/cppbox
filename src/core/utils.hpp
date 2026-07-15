#pragma once
#include "core/net.hpp"
#include <array>
#include <cctype>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace sbox {
inline void require(bool ok, std::string_view message) {
  if (!ok) {
    throw std::runtime_error(std::string(message));
  }
}
inline std::uint16_t read_be16(const unsigned char *p) {
  return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}
inline void write_be16(std::vector<unsigned char> &out, std::uint16_t value) {
  out.push_back(static_cast<unsigned char>((value >> 8) & 0xff));
  out.push_back(static_cast<unsigned char>(value & 0xff));
}
inline int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  return -1;
}
inline std::array<unsigned char, 16> parse_uuid(std::string_view uuid) {
  std::string hex;
  hex.reserve(32);
  for (char c : uuid) {
    if (c == '-') {
      continue;
    }
    require(hex_value(c) >= 0, "invalid uuid character");
    hex.push_back(c);
  }
  require(hex.size() == 32, "uuid must contain 32 hex digits");
  std::array<unsigned char, 16> bytes{};
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    int hi = hex_value(hex[i * 2]);
    int lo = hex_value(hex[i * 2 + 1]);
    bytes[i] = static_cast<unsigned char>((hi << 4) | lo);
  }
  return bytes;
}
inline std::string bytes_to_string(boost::asio::const_buffer buffer) {
  const auto *p = static_cast<const char *>(buffer.data());
  return {p, p + buffer.size()};
}
inline void close_socket(tcp::socket &socket) {
  error_code ignored;
  if (!socket.is_open()) {
    return;
  }
  ignored = socket.cancel(ignored);
  ignored = socket.shutdown(tcp::socket::shutdown_both, ignored);
  ignored = socket.close(ignored);
}
}; // namespace sbox