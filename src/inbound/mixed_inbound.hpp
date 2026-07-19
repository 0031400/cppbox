#pragma once
#include "core/net.hpp"
#include "core/session.hpp"
#include "inbound/inbound.hpp"
#include <boost/asio/awaitable.hpp>
#include <functional>

namespace sbox {
class MixedInbound : public Inbound {

public:
  using Handler = std::function<asio::awaitable<void>(tcp::socket, Session)>;
  MixedInbound(asio::io_context &io, tcp::endpoint endpoint, Handler handler);
  asio::awaitable<void> start() override;

private:
  asio::awaitable<void> handle_client(tcp::socket socket);
  tcp::acceptor acceptor_;
  Handler handler_;
};
}; // namespace sbox