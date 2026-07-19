#include "inbound/mixed_inbound.hpp"
#include "core/session.hpp"
#include "core/utils.hpp"
#include "protocol/http_proxy.hpp"
#include "protocol/socks5.hpp"
#include <array>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <core/log.hpp>
#include <exception>
#include <string>
#include <utility>

namespace sbox {
MixedInbound::MixedInbound(asio::io_context &io, tcp::endpoint endpoint,
                           Handler handler)
    : acceptor_(io, endpoint), handler_(std::move(handler)) {}
asio::awaitable<void> MixedInbound::start() {
  for (;;) {
    tcp::socket socket = co_await acceptor_.async_accept(asio::use_awaitable);
    asio::co_spawn(acceptor_.get_executor(), handle_client(std::move(socket)),
                   asio::detached);
  }
}
asio::awaitable<void> MixedInbound::handle_client(tcp::socket socket) {
  try {
    std::array<unsigned char, 1> first{};
    co_await socket.async_receive(
        asio::buffer(first), tcp::socket::message_peek, asio::use_awaitable);
    Session session;
    if (first[0] == 0x05) {
      session = co_await socks5::read_session(socket);
    } else {
      session = co_await http_proxy::read_session(socket);
    }
    co_await handler_(std::move(socket), std::move(session));
  } catch (const std::exception &e) {
    log_error(std::string("[mixed] ") + e.what());
    close_socket(socket);
  }
}
}; // namespace sbox