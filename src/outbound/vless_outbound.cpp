#include "outbound/vless_outbound.hpp"
#include "core/log.hpp"
#include "core/utils.hpp"
#include "transport/ws_client.hpp"
#include <array>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <boost/system/system_error.hpp>
#include <exception>
#include <memory>
#include <utility>
#include <vector>

namespace sbox {
using boost::asio::experimental::awaitable_operators::operator||;
VlessOutbound::VlessOutbound(asio::io_context &io, VlessOutboundConfig config)
    : protocol_(std::move(config.vless)),
      transport_(io, std::move(config.transport)) {}
asio::awaitable<void> VlessOutbound::handle(tcp::socket inbound,
                                            Session session) {
  std::unique_ptr<WsConnection> ws;
  try {
    ws = co_await transport_.connect();
    auto request = protocol_.build_request(session.destination);
    co_await ws->write(request);
    if (!session.initial_payload.empty()) {
      co_await ws->write(session.initial_payload);
    }
    co_await (relay_tcp_to_ws(inbound, *ws) || relay_ws_to_tcp(*ws, inbound));
  } catch (const std::exception &e) {
    log_error(std::string("[vless] ") + e.what());
  }
}
asio::awaitable<void> VlessOutbound::relay_tcp_to_ws(tcp::socket &tcp_socket,
                                                     WsConnection &ws) {
  std::array<unsigned char, 16 * 1024> buffer{};
  for (;;) {
    error_code ec;
    auto n = co_await tcp_socket.async_read_some(
        asio::buffer(buffer), asio::redirect_error(asio::use_awaitable, ec));
    if (ec == asio::error::eof || ec == asio::error::connection_reset ||
        ec == asio::error::operation_aborted) {
      co_return;
    }
    if (ec) {
      throw boost::system::system_error(ec);
    }
    std::vector<unsigned char> bytes(buffer.begin(), buffer.begin() + n);
    co_await ws.write(bytes);
  }
}
asio::awaitable<void> VlessOutbound::relay_ws_to_tcp(WsConnection &ws,
                                                     tcp::socket &tcp_socket) {
  bool first_message = true;
  for (;;) {

    auto bytes = co_await ws.read();
    if (bytes.empty()) {
      co_return;
    }

    if (first_message) {
      first_message = false;
      VlessProtocol::strip_response_header(bytes);
    }
    error_code ec;

    co_await asio::async_write(tcp_socket, asio::buffer(bytes),
                               asio::redirect_error(asio::use_awaitable, ec));

    if (ec == asio::error::eof || ec == asio::error::connection_reset ||
        ec == asio::error::operation_aborted) {
      co_return;
    }
    if (ec) {
      throw boost::system::system_error(ec);
    }
  }
}
} // namespace sbox