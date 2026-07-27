#pragma once

#include "core/net.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace cppbox {

void require(bool ok, std::string_view message);
std::uint16_t read_be16(const unsigned char *p);
std::uint16_t read_be16(std::span<const std::uint8_t> data, std::size_t offset,
                        std::string_view message = "truncated packet");

std::uint32_t read_be32(std::span<const std::uint8_t> data, std::size_t offset,
                        std::string_view message = "truncated packet");

void write_be16(unsigned char *p, std::uint16_t value);
void write_be16(std::vector<unsigned char> &out, std::uint16_t value);
int hex_value(char c);

std::array<unsigned char, 16> parse_uuid(std::string_view uuid);
std::string bytes_to_string(asio::const_buffer buffer);
void close_socket(tcp::socket &socket);

} // namespace cppbox