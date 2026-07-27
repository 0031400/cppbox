#include "outbound/direct_outbound.hpp"
#include "core/net.hpp"
#include "transport/stream_utils.hpp"
#include <boost/asio/buffer.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <core/log.hpp>
#include <exception>
#include <string>

namespace cppbox {

using asio::experimental::awaitable_operators::operator||;
DirectOutbound::DirectOutbound(asio::io_context &io, Connector &connector)
    : connector_(connector) {}
asio::awaitable<void> DirectOutbound::handle(tcp::socket inbound,
                                             Session session) {
  tcp::socket outbound(co_await asio::this_coro::executor);
  try {
    co_await connector_.connect(outbound, session.destination);
    if (!session.initial_payload.empty()) {
      co_await asio::async_write(
          outbound, asio::buffer(session.initial_payload), asio::use_awaitable);
    }
    co_await (relay(inbound, outbound) || relay(outbound, inbound));

  } catch (const std::exception &e) {
    log_error(std::string("[direct] ") + e.what());
  }
}
asio::awaitable<void> DirectOutbound::relay(tcp::socket &from,
                                            tcp::socket &to) {
  std::array<unsigned char, 16 * 1024> buffer{};
  for (;;) {
    error_code ec;
    auto n = co_await from.async_read_some(
        asio::buffer(buffer), asio::redirect_error(asio::use_awaitable, ec));

    if (is_stream_closed(ec)) {
      co_return;
    }

    if (ec) {
      throw boost::system::system_error(ec);
    }

    co_await asio::async_write(to, asio::buffer(buffer.data(), n),
                               asio::use_awaitable);
  }
}
}; // namespace cppbox