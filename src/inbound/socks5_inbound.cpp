#include "inbound/socks5_inbound.hpp"
#include "core/session.hpp"
#include "core/utils.hpp"
#include "protocol/socks5.hpp"
#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <core/log.hpp>
#include <exception>
#include <functional>

namespace sbox {

Socks5Inbound::Socks5Inbound(asio::io_context &io, tcp::endpoint endpoint,
                             Handler handler)
    : acceptor_(io, endpoint), handler_(std::move(handler)) {}
asio::awaitable<void> Socks5Inbound::start() {
  for (;;) {
    tcp::socket socket = co_await acceptor_.async_accept(asio::use_awaitable);
    asio::co_spawn(acceptor_.get_executor(), handle_client(std::move(socket)),
                   asio::detached);
  }
}

asio::awaitable<void> Socks5Inbound::handle_client(tcp::socket socket) {
  try {
    auto session = co_await socks5::read_session(socket);
    co_await handler_(std::move(socket), std::move(session));
  } catch (const std::exception &e) {
    log_error(std::string("[socks5] ") + e.what());
    close_socket(socket);
  }
}
asio::awaitable<void> write_success_reply(tcp::socket &socket) {
  static constexpr std::string_view reply =
      "HTTP/1.1 200 Connection Established\r\n"
      "Proxy-Agent: sbox-cpp/0.1\r\n"
      "\r\n";
  co_await asio::async_write(socket, asio::buffer(reply), asio::use_awaitable);
}
}; // namespace sbox