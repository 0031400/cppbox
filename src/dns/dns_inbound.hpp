#pragma once

#include "dns/dns.hpp"
#include "inbound/inbound.hpp"
#include <atomic>
#include <string>
#include "core/net.hpp"
namespace sbox {

class DnsInbound final : public Inbound {
public:
  DnsInbound(asio::io_context &io, std::string listen, DnsServer &dns_server);

  asio::awaitable<void> start() override;
  void stop() noexcept override;

private:
  asio::awaitable<void> handle_request(Bytes request,
                                       udp::endpoint client);

  udp::endpoint endpoint_;
  udp::socket socket_;
  DnsServer &dns_server_;
  std::atomic_bool stopping_{false};
};

} // namespace sbox