#pragma once

#include "dns/dns.hpp"
#include "outbound/outbound.hpp"
#include "transport/connector.hpp"
namespace cppbox {

class DirectOutbound : public Outbound {
public:
  DirectOutbound(asio::io_context &io,  Connector &connector);

  asio::awaitable<void> handle(tcp::socket inbound, Session session) override;

private:
  asio::awaitable<void> relay(tcp::socket &from, tcp::socket &to);

  Connector &connector_;
};

} // namespace cppbox