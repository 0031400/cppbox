#pragma once

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>
#include <boost/asio.hpp>

namespace sbox {

enum class HostType {
  IPv4,
  IPv6,
  Domain,
};

class IPv4Address {
public:
  explicit IPv4Address(boost::asio::ip::address_v4 value) : value_(value) {}

  static bool is_valid(const std::string &text) {
    boost::system::error_code ec;
    boost::asio::ip::make_address_v4(text, ec);
    return !ec;
  }

  static IPv4Address parse(const std::string &text) {
    boost::system::error_code ec;
    auto value = boost::asio::ip::make_address_v4(text, ec);
    if (ec) {
      throw std::runtime_error("invalid IPv4 address: " + text);
    }
    return IPv4Address(value);
  }

  const boost::asio::ip::address_v4 &value() const { return value_; }
  std::string to_string() const { return value_.to_string(); }

private:
  boost::asio::ip::address_v4 value_;
};

class IPv6Address {
public:
  explicit IPv6Address(boost::asio::ip::address_v6 value) : value_(value) {}

  static bool is_valid(const std::string &text) {
    boost::system::error_code ec;
    boost::asio::ip::make_address_v6(text, ec);
    return !ec;
  }

  static IPv6Address parse(const std::string &text) {
    boost::system::error_code ec;
    auto value = boost::asio::ip::make_address_v6(text, ec);
    if (ec) {
      throw std::runtime_error("invalid IPv6 address: " + text);
    }
    return IPv6Address(value);
  }

  const boost::asio::ip::address_v6 &value() const { return value_; }
  std::string to_string() const { return value_.to_string(); }

private:
  boost::asio::ip::address_v6 value_;
};

class DomainName {
public:
  explicit DomainName(std::string value) : value_(std::move(value)) {
    if (value_.empty()) {
      throw std::runtime_error("domain must not be empty");
    }
    if (value_.size() > 255) {
      throw std::runtime_error("domain too long: " + value_);
    }
  }

  const std::string &value() const { return value_; }
  std::string to_string() const { return value_; }

private:
  std::string value_;
};

class Host {
public:
  using Value = std::variant<IPv4Address, IPv6Address, DomainName>;

  explicit Host(Value value) : value_(std::move(value)) {}

  static Host parse(const std::string &text) {
    if (IPv4Address::is_valid(text)) {
      return Host(IPv4Address::parse(text));
    }
    if (IPv6Address::is_valid(text)) {
      return Host(IPv6Address::parse(text));
    }
    return Host(DomainName(text));
  }

  static Host ipv4(const std::string &text) {
    return Host(IPv4Address::parse(text));
  }

  static Host ipv6(const std::string &text) {
    return Host(IPv6Address::parse(text));
  }

  static Host domain(std::string text) {
    return Host(DomainName(std::move(text)));
  }

  HostType type() const {
    if (std::holds_alternative<IPv4Address>(value_)) {
      return HostType::IPv4;
    }
    if (std::holds_alternative<IPv6Address>(value_)) {
      return HostType::IPv6;
    }
    return HostType::Domain;
  }

  bool is_ip() const {
    return type() == HostType::IPv4 || type() == HostType::IPv6;
  }

  bool is_domain() const { return type() == HostType::Domain; }

  std::string to_string() const {
    return std::visit([](const auto &item) { return item.to_string(); }, value_);
  }

  boost::asio::ip::address asio_address() const {
    if (const auto *v4 = std::get_if<IPv4Address>(&value_)) {
      return v4->value();
    }
    if (const auto *v6 = std::get_if<IPv6Address>(&value_)) {
      return v6->value();
    }
    throw std::runtime_error("domain has no asio address before DNS resolve");
  }

  const DomainName &domain() const {
    const auto *domain = std::get_if<DomainName>(&value_);
    if (!domain) {
      throw std::runtime_error("host is not domain");
    }
    return *domain;
  }

private:
  Value value_;
};

struct Destination {
  Host host;
  std::uint16_t port;

  std::string to_string() const {
    return host.to_string() + ":" + std::to_string(port);
  }
};

struct ResolvedEndpoint {
  boost::asio::ip::address address;
  std::uint16_t port;

  boost::asio::ip::tcp::endpoint tcp_endpoint() const {
    return boost::asio::ip::tcp::endpoint(address, port);
  }
};

} // namespace sbox