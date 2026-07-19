#include "inbound/http_inbound.hpp"
#include "core/log.hpp"
#include "core/utils.hpp"
#include "protocol/http_proxy.hpp"
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <exception>
#include <string>
#include <utility>

namespace sbox {

HttpInbound::HttpInbound(asio::io_context &io, tcp::endpoint endpoint,
                         Handler handler)
    : acceptor_(io, endpoint), handler_(std::move(handler)) {}
asio::awaitable<void> HttpInbound::start() {
  for (;;) {
    tcp::socket socket = co_await acceptor_.async_accept(asio::use_awaitable);
    asio::co_spawn(acceptor_.get_executor(), handle_client(std::move(socket)),
                   asio::detached);
  }
}
asio::awaitable<void> HttpInbound::handle_client(tcp::socket socket) {
  try {
    auto session = co_await http_proxy::read_session(socket);
    co_await handler_(std::move(socket), std::move(session));
  } catch (const std::exception &e) {
    log_error(std::string("[http] ") + e.what());
    close_socket(socket);
  }
}
} // namespace sbox