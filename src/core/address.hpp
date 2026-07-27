#pragma once

#include "core/net.hpp"
#include <cstdint>
#include <string>
#include <variant>

namespace sbox {

enum class HostType {
  IPv4,
  IPv6,
  Domain,
};
bool is_ip_literal(std::string_view text);
class IPv4Address {
public:
  explicit IPv4Address(ip::address_v4 value) : value_(value) {}

  static bool is_valid(const std::string &text);

  static IPv4Address parse(const std::string &text);

  const ip::address_v4 &value() const;
  std::string to_string() const;

private:
  ip::address_v4 value_;
};

class IPv6Address {
public:
  explicit IPv6Address(ip::address_v6 value);

  static bool is_valid(const std::string &text);

  static IPv6Address parse(const std::string &text);

  const ip::address_v6 &value() const;
  std::string to_string() const;

private:
  ip::address_v6 value_;
};

class DomainName {
public:
  explicit DomainName(std::string value);

  const std::string &value() const;
  std::string to_string() const;

private:
  std::string value_;
};
std::uint32_t ipv4_to_net_order_u32(const std::string &text);

ip::address_v4 address_v4_from_net_order_u32(std::uint32_t value);
class Host {
public:
  using Value = std::variant<IPv4Address, IPv6Address, DomainName>;

  explicit Host(Value value);

  static Host parse(const std::string &text);

  static Host ipv4(const std::string &text);

  static Host ipv6(const std::string &text);

  static Host domain(std::string text);

  HostType type() const;

  bool is_ip() const;

  bool is_domain() const;

  std::string to_string() const;

  ip::address asio_address() const;

  const DomainName &domain() const;

private:
  Value value_;
};

struct Destination {
  Host host;
  std::uint16_t port;

  std::string to_string() const;
};

struct ResolvedEndpoint {
  ip::address address;
  std::uint16_t port;

  tcp::endpoint tcp_endpoint() const;
};

} // namespace sbox