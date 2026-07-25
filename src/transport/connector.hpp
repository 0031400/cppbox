// src/transport/connector.hpp
#pragma once

#include "core/address.hpp"
#include "core/net.hpp"
#include "dns/dns.hpp"

namespace sbox {

class Connector {
public:
  explicit Connector(DnsServer &dns_server);

  void set_outbound_interface_index(std::uint32_t index);
  asio::awaitable<void> connect(tcp::socket &socket,
                                const Destination &destination);

private:
  DnsServer &dns_server_;
  std::uint32_t outbound_interface_index_{};
};

} // namespace sbox