#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace sbox {

std::uint16_t checksum(std::span<const std::uint8_t> data);
void recalc_ipv4_checksum(std::uint8_t *ip);
void recalc_tcp_checksum(std::uint8_t *ip, std::uint8_t *tcp,
                         std::size_t tcp_len);

} // namespace sbox