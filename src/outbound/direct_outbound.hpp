#pragma once
#include "core/net.hpp"
#include "outbound.hpp"
#include <boost/asio/awaitable.hpp>

namespace sbox {
class DirectOutbound : public Outbound {
public:
  explicit DirectOutbound(asio::io_context &io);
  asio::awaitable<void> handle(tcp::socket inbound, Session session) override;

private:
  asio::awaitable<void> relay(tcp::socket &from, tcp::socket &to);
  tcp::resolver resolver_;
};
}; // namespace sbox