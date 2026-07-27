#include "inbound/tun_checksum.hpp"

#include <vector>

namespace cppbox {

std::uint16_t checksum(std::span<const std::uint8_t> data) {
  std::uint32_t sum = 0;
  std::size_t i = 0;

  while (i + 1 < data.size()) {
    sum += static_cast<std::uint16_t>((data[i] << 8) | data[i + 1]);
    i += 2;
  }

  if (i < data.size()) {
    sum += static_cast<std::uint16_t>(data[i] << 8);
  }

  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  return static_cast<std::uint16_t>(~sum);
}

void recalc_ipv4_checksum(std::uint8_t *ip) {
  ip[10] = 0;
  ip[11] = 0;

  const auto ihl = static_cast<std::uint8_t>((ip[0] & 0x0f) * 4);
  const auto value = checksum({ip, ihl});

  ip[10] = static_cast<std::uint8_t>(value >> 8);
  ip[11] = static_cast<std::uint8_t>(value);
}

void recalc_tcp_checksum(std::uint8_t *ip, std::uint8_t *tcp,
                         std::size_t tcp_len) {
  tcp[16] = 0;
  tcp[17] = 0;

  std::vector<std::uint8_t> pseudo;
  pseudo.reserve(12 + tcp_len);

  pseudo.insert(pseudo.end(), ip + 12, ip + 20);
  pseudo.push_back(0);
  pseudo.push_back(6);
  pseudo.push_back(static_cast<std::uint8_t>(tcp_len >> 8));
  pseudo.push_back(static_cast<std::uint8_t>(tcp_len));

  pseudo.insert(pseudo.end(), tcp, tcp + tcp_len);

  const auto value = checksum(pseudo);

  tcp[16] = static_cast<std::uint8_t>(value >> 8);
  tcp[17] = static_cast<std::uint8_t>(value);
}

} // namespace cppbox