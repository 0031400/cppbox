#include "core/address.hpp"
namespace sbox {
bool is_ip_literal(std::string_view text) {
  error_code ec;
  ip::make_address(text, ec);
  return !ec;
}
// IPv4Address
bool IPv4Address::is_valid(const std::string &text) {
  error_code ec;
  ip::make_address_v4(text, ec);
  return !ec;
}
IPv4Address IPv4Address::parse(const std::string &text) {
  error_code ec;
  auto value = ip::make_address_v4(text, ec);
  if (ec) {
    throw std::runtime_error("invalid IPv4 address: " + text);
  }
  return IPv4Address(value);
}
const ip::address_v4 &IPv4Address::value() const { return value_; }
std::string IPv4Address::to_string() const { return value_.to_string(); }

// IPv6Address
IPv6Address::IPv6Address(ip::address_v6 value) : value_(value) {}

bool IPv6Address::is_valid(const std::string &text) {
  error_code ec;
  ip::make_address_v6(text, ec);
  return !ec;
}
IPv6Address IPv6Address::parse(const std::string &text) {
  error_code ec;
  auto value = ip::make_address_v6(text, ec);
  if (ec) {
    throw std::runtime_error("invalid IPv6 address: " + text);
  }
  return IPv6Address(value);
}

const ip::address_v6 &IPv6Address::value() const { return value_; }
std::string IPv6Address::to_string() const { return value_.to_string(); }

DomainName::DomainName(std::string value) : value_(std::move(value)) {
  if (value_.empty()) {
    throw std::runtime_error("domain must not be empty");
  }
  if (value_.size() > 255) {
    throw std::runtime_error("domain too long: " + value_);
  }
}

const std::string &DomainName::value() const { return value_; }
std::string DomainName::to_string() const { return value_; }

std::uint32_t ipv4_to_net_order_u32(const std::string &text) {
  auto addr = ip::make_address_v4(text);
  auto bytes = addr.to_bytes();

  std::uint32_t value{};
  std::memcpy(&value, bytes.data(), sizeof(value));
  return value;
}

ip::address_v4 address_v4_from_net_order_u32(std::uint32_t value) {
  std::array<unsigned char, 4> bytes{};
  std::memcpy(bytes.data(), &value, sizeof(value));
  return ip::address_v4(bytes);
}

Host::Host(Value value) : value_(std::move(value)) {}

Host Host::parse(const std::string &text) {
  if (IPv4Address::is_valid(text)) {
    return Host(IPv4Address::parse(text));
  }
  if (IPv6Address::is_valid(text)) {
    return Host(IPv6Address::parse(text));
  }
  return Host(DomainName(text));
}

Host Host::ipv4(const std::string &text) {
  return Host(IPv4Address::parse(text));
}

Host Host::ipv6(const std::string &text) {
  return Host(IPv6Address::parse(text));
}

Host Host::domain(std::string text) {
  return Host(DomainName(std::move(text)));
}

HostType Host::type() const {
  if (std::holds_alternative<IPv4Address>(value_)) {
    return HostType::IPv4;
  }
  if (std::holds_alternative<IPv6Address>(value_)) {
    return HostType::IPv6;
  }
  return HostType::Domain;
}

bool Host::is_ip() const {
  return type() == HostType::IPv4 || type() == HostType::IPv6;
}

bool Host::is_domain() const { return type() == HostType::Domain; }

std::string Host::to_string() const {
  return std::visit([](const auto &item) { return item.to_string(); }, value_);
}

ip::address Host::asio_address() const {
  if (const auto *v4 = std::get_if<IPv4Address>(&value_)) {
    return v4->value();
  }
  if (const auto *v6 = std::get_if<IPv6Address>(&value_)) {
    return v6->value();
  }
  throw std::runtime_error("domain has no asio address before DNS resolve");
}

const DomainName &Host::domain() const {
  const auto *domain = std::get_if<DomainName>(&value_);
  if (!domain) {
    throw std::runtime_error("host is not domain");
  }
  return *domain;
}

std::string Destination::to_string() const {
  return host.to_string() + ":" + std::to_string(port);
}
tcp::endpoint ResolvedEndpoint::tcp_endpoint() const {
  return tcp::endpoint(address, port);
}
} // namespace sbox