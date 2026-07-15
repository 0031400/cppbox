#pragma once
#include <cstdint>
#include <string>
#include <vector>
namespace sbox {
enum class AddressType { IPv4, Domain, IPv6 };
struct Destination {
  AddressType type{};
  std::string host;
  std::uint16_t port{};
};
struct Session {
  Destination destination;
  std::vector<unsigned char> initial_payload;
};
}; // namespace sbox