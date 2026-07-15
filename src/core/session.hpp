#pragma once
#include <cstdint>
#include <string>
namespace sbox {
enum class AddressType { IPv4, Domain, IPv6 };
struct Destination {
  AddressType type{};
  std::string host;
  std::uint16_t port{};
};
struct Session{
    Destination destination;
};
}; // namespace sbox