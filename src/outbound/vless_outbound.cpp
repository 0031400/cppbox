#include "outbound/vless_outbound.hpp"
#include "config/config.hpp"
#include "core/log.hpp"
#include "transport/tcp_client.hpp"
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
namespace {
TlsConfig normalize_tls(const std::optional<TlsConfig> &tls,
                        const std::string &server) {
  TlsConfig out;
  if (tls) {
    out = *tls;
  }
  if (out.enabled && out.server_name.empty()) {
    out.server_name = server;
  }
  return out;
}
}; // namespace
VlessOutbound::VlessOutbound(asio::io_context &io, VlessOutboundConfig config)
    : io_(io), config_(std::move(config)), protocol_(config_.vless) {}
asio::awaitable<std::unique_ptr<Stream>> VlessOutbound::connect_stream() {
  auto tls = normalize_tls(config_.tls, config_.server);
  if (!config_.transport || config_.transport->type.empty()) {
    TcpClient client(io_, TcpClientConfig{.server_host = config_.server,
                                          .server_port = config_.server_port,
                                          .tls = tls});
    co_return co_await client.connect();
  }
  if (config_.transport && config_.transport->type == "ws") {
    WsClientConfig ws_config;
    ws_config.server_host = config_.server;
    ws_config.server_port = config_.server_port;
    ws_config.path = config_.transport->path;
    ws_config.host_header = config_.server;
    ws_config.tls = tls;
    WsClient client(io_, std::move(ws_config));
    co_return co_await client.connect();
  }
  throw std::runtime_error("unsupported vless transport");
}
asio::awaitable<void> VlessOutbound::handle(tcp::socket inbound,
                                            Session session) {
  std::unique_ptr<Stream> stream;
  try {
    stream = co_await connect_stream();

    auto request = protocol_.build_request(session.destination);
    co_await stream->write(request);

    if (!session.initial_payload.empty()) {
      co_await stream->write(session.initial_payload);
    }

    co_await (relay_tcp_to_stream(inbound, *stream) ||
              relay_stream_to_tcp(*stream, inbound));
  } catch (const std::exception &e) {
    log_error(std::string("[vless] ") + e.what());
  }

  if (stream) {
    stream->close();
  }
  close_socket(inbound);
}

asio::awaitable<void>
VlessOutbound::relay_tcp_to_stream(tcp::socket &tcp_socket, Stream &stream) {
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
    co_await stream.write(bytes);
  }
}

asio::awaitable<void>
VlessOutbound::relay_stream_to_tcp(Stream &stream, tcp::socket &tcp_socket) {
  bool first_message = true;
  for (;;) {
    auto bytes = co_await stream.read();
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