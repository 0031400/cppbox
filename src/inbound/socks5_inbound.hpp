#pragma once
#include "core/session.hpp"
#include "core/utils.hpp"
#include "inbound/inbound.hpp"
#include <boost/asio.hpp>
#include <functional>

namespace cppbox {
class Socks5Inbound : public Inbound {
public:
  using Handler = std::function<asio::awaitable<void>(tcp::socket, Session)>;
  Socks5Inbound(asio::io_context &io, tcp::endpoint endpoint, Handler handler);
  asio::awaitable<void> start() override;
  void stop() noexcept override;
private:
  asio::awaitable<void> handle_client(tcp::socket socket);
  tcp::acceptor acceptor_;
  Handler handler_;
};
}; // namespace cppbox