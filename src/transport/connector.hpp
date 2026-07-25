// src/transport/connector.hpp
#pragma once

#include "core/address.hpp"
#include "core/net.hpp"
#include "dns/dns.hpp"

namespace sbox {

class Connector {
public:
  explicit Connector(DnsServer &dns_server) : dns_server_(dns_server) {}

  asio::awaitable<void> connect(tcp::socket &socket,
                                const Destination &destination);

private:
  DnsServer &dns_server_;
};

} // namespace sbox