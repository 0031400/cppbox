#pragma once

#include "core/address.hpp"
#include "core/net.hpp"
#include "dns/dns.hpp"

namespace cppbox {

class Connector {
public:
  explicit Connector(DnsServer &dns_server);

  void set_outbound_interface_index(std::uint32_t index);

  asio::awaitable<void> connect(tcp::socket &socket,
                                const Destination &destination);
  asio::awaitable<void> connect(udp::socket &socket,
                                const Destination &destination);

private:
  asio::awaitable<std::vector<ip::address>>
  resolve_destination(const Destination &destination);

  DnsServer &dns_server_;
  std::uint32_t outbound_interface_index_{};
};

} // namespace cppbox