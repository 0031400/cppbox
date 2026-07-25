#include "protocol/tls_sniffer.hpp"
#include <cstddef>
#include <cstdint>

namespace sbox {
namespace {

std::uint16_t read_u16(std::span<const unsigned char> data, std::size_t pos) {
  return static_cast<std::uint16_t>((data[pos] << 8) | data[pos + 1]);
}

bool has_bytes(std::span<const unsigned char> data, std::size_t pos,
               std::size_t size) {
  return pos <= data.size() && size <= data.size() - pos;
}

} // namespace

std::optional<std::string> sniff_tls_sni(std::span<const unsigned char> data) {
  if (!has_bytes(data, 0, 5)) {
    return std::nullopt;
  }

  // TLS record: content_type = handshake(0x16)
  if (data[0] != 0x16) {
    return std::nullopt;
  }

  const auto record_len = read_u16(data, 3);
  if (!has_bytes(data, 5, record_len)) {
    return std::nullopt;
  }

  std::size_t pos = 5;

  // Handshake type: client_hello(0x01)
  if (!has_bytes(data, pos, 4) || data[pos] != 0x01) {
    return std::nullopt;
  }

  const std::size_t handshake_len =
      (static_cast<std::size_t>(data[pos + 1]) << 16) |
      (static_cast<std::size_t>(data[pos + 2]) << 8) |
      static_cast<std::size_t>(data[pos + 3]);

  pos += 4;
  if (!has_bytes(data, pos, handshake_len)) {
    return std::nullopt;
  }

  // legacy_version + random
  if (!has_bytes(data, pos, 2 + 32)) {
    return std::nullopt;
  }
  pos += 2 + 32;

  // session_id
  if (!has_bytes(data, pos, 1)) {
    return std::nullopt;
  }
  const auto session_id_len = data[pos];
  pos += 1;
  if (!has_bytes(data, pos, session_id_len)) {
    return std::nullopt;
  }
  pos += session_id_len;

  // cipher_suites
  if (!has_bytes(data, pos, 2)) {
    return std::nullopt;
  }
  const auto cipher_suites_len = read_u16(data, pos);
  pos += 2;
  if (!has_bytes(data, pos, cipher_suites_len)) {
    return std::nullopt;
  }
  pos += cipher_suites_len;

  // compression_methods
  if (!has_bytes(data, pos, 1)) {
    return std::nullopt;
  }
  const auto compression_methods_len = data[pos];
  pos += 1;
  if (!has_bytes(data, pos, compression_methods_len)) {
    return std::nullopt;
  }
  pos += compression_methods_len;

  // extensions
  if (!has_bytes(data, pos, 2)) {
    return std::nullopt;
  }
  const auto extensions_len = read_u16(data, pos);
  pos += 2;
  if (!has_bytes(data, pos, extensions_len)) {
    return std::nullopt;
  }

  const auto extensions_end = pos + extensions_len;

  while (pos < extensions_end) {
    if (!has_bytes(data, pos, 4)) {
      return std::nullopt;
    }

    const auto extension_type = read_u16(data, pos);
    const auto extension_len = read_u16(data, pos + 2);
    pos += 4;

    if (!has_bytes(data, pos, extension_len)) {
      return std::nullopt;
    }

    // server_name extension
    if (extension_type == 0x0000) {
      if (!has_bytes(data, pos, 2)) {
        return std::nullopt;
      }

      std::size_t name_pos = pos + 2;
      const auto name_list_len = read_u16(data, pos);
      const auto name_list_end = name_pos + name_list_len;

      if (!has_bytes(data, name_pos, name_list_len)) {
        return std::nullopt;
      }

      while (name_pos < name_list_end) {
        if (!has_bytes(data, name_pos, 3)) {
          return std::nullopt;
        }

        const auto name_type = data[name_pos];
        const auto name_len = read_u16(data, name_pos + 1);
        name_pos += 3;

        if (!has_bytes(data, name_pos, name_len)) {
          return std::nullopt;
        }

        // host_name
        if (name_type == 0x00) {
          return std::string(
              reinterpret_cast<const char *>(data.data() + name_pos),
              name_len);
        }

        name_pos += name_len;
      }
    }

    pos += extension_len;
  }

  return std::nullopt;
}

} // namespace sbox