#include "transport/ws_client.hpp"
#include "core/tls.hpp"
#include <boost/asio/buffer.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>
#include <boost/asio/ssl/stream_base.hpp>
#include <boost/asio/ssl/verify_mode.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/core/stream_traits.hpp>
#include <boost/beast/http/field.hpp>
#include <boost/system/system_error.hpp>
#include <memory>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <utility>
#include <vector>

namespace sbox {
namespace {

class PlainWsStream final : public Stream {
public:
  explicit PlainWsStream(websocket::stream<tcp::socket> ws)
      : ws_(std::move(ws)) {
    ws_.binary(true);
  }

  asio::awaitable<std::vector<unsigned char>> read() override {
    beast::flat_buffer buffer;
    error_code ec;

    co_await ws_.async_read(buffer,
                            asio::redirect_error(asio::use_awaitable, ec));

    if (ec == websocket::error::closed || ec == asio::error::eof ||
        ec == asio::error::connection_reset ||
        ec == asio::error::operation_aborted) {
      co_return std::vector<unsigned char>{};
    }

    if (ec) {
      throw boost::system::system_error(ec);
    }

    std::vector<unsigned char> bytes(buffer.size());
    asio::buffer_copy(asio::buffer(bytes), buffer.data());
    co_return bytes;
  }

  asio::awaitable<void>
  write(const std::vector<unsigned char> &bytes) override {
    error_code ec;

    co_await ws_.async_write(asio::buffer(bytes),
                             asio::redirect_error(asio::use_awaitable, ec));

    if (ec == websocket::error::closed || ec == asio::error::eof ||
        ec == asio::error::connection_reset ||
        ec == asio::error::operation_aborted) {
      co_return;
    }

    if (ec) {
      throw boost::system::system_error(ec);
    }
  }

  void close() override {
    error_code ignored;
    auto &socket = beast::get_lowest_layer(ws_);
    socket.cancel(ignored);
    socket.shutdown(tcp::socket::shutdown_both, ignored);
    socket.close(ignored);
  }

private:
  websocket::stream<tcp::socket> ws_;
};

class TlsWsStream final : public Stream {
public:
  using Socket = websocket::stream<beast::ssl_stream<tcp::socket>>;

  explicit TlsWsStream(Socket ws) : ws_(std::move(ws)) { ws_.binary(true); }

  asio::awaitable<std::vector<unsigned char>> read() override {
    beast::flat_buffer buffer;
    error_code ec;

    co_await ws_.async_read(buffer,
                            asio::redirect_error(asio::use_awaitable, ec));

    if (ec == websocket::error::closed || ec == asio::error::eof ||
        ec == asio::error::connection_reset ||
        ec == asio::error::operation_aborted) {
      co_return std::vector<unsigned char>{};
    }

    if (ec) {
      throw boost::system::system_error(ec);
    }

    std::vector<unsigned char> bytes(buffer.size());
    asio::buffer_copy(asio::buffer(bytes), buffer.data());
    co_return bytes;
  }

  asio::awaitable<void>
  write(const std::vector<unsigned char> &bytes) override {
    error_code ec;

    co_await ws_.async_write(asio::buffer(bytes),
                             asio::redirect_error(asio::use_awaitable, ec));

    if (ec == websocket::error::closed || ec == asio::error::eof ||
        ec == asio::error::connection_reset ||
        ec == asio::error::operation_aborted) {
      co_return;
    }

    if (ec) {
      throw boost::system::system_error(ec);
    }
  }

  void close() override {
    error_code ignored;
    auto &socket = beast::get_lowest_layer(ws_);
    socket.cancel(ignored);
    socket.shutdown(tcp::socket::shutdown_both, ignored);
    socket.close(ignored);
  }

private:
  Socket ws_;
};

} // namespace

WsClient::WsClient(asio::io_context &io, WsClientConfig config,
                   Connector &connector)
    : ssl_context_(ssl::context::tls_client), config_(std::move(config)),
      connector_(connector) {
  if (config_.host_header.empty()) {
    config_.host_header = config_.server.host.to_string();
  }

  if (config_.tls.enabled) {
    if (config_.tls.server_name.empty()) {
      config_.tls.server_name = config_.server.host.to_string();
    }
    tls::configure_client_context(ssl_context_, config_.tls.insecure);
  }
}

asio::awaitable<std::unique_ptr<Stream>> WsClient::connect() {
  if (!config_.tls.enabled) {
    websocket::stream<tcp::socket> ws(co_await asio::this_coro::executor);

    co_await connector_.connect(beast::get_lowest_layer(ws), config_.server);

    ws.set_option(
        websocket::stream_base::decorator([this](websocket::request_type &req) {
          req.set(beast::http::field::host, config_.host_header);
          req.set(beast::http::field::user_agent, "sbox-cpp/0.1");
        }));

    co_await ws.async_handshake(config_.host_header, config_.path,
                                asio::use_awaitable);

    co_return std::make_unique<PlainWsStream>(std::move(ws));
  }

  TlsWsStream::Socket ws(co_await asio::this_coro::executor, ssl_context_);

  co_await connector_.connect(beast::get_lowest_layer(ws), config_.server);

  tls::configure_server_identity(ws.next_layer(), config_.tls.server_name,
                                 config_.tls.insecure);
  co_await ws.next_layer().async_handshake(ssl::stream_base::client,
                                           asio::use_awaitable);

  ws.set_option(
      websocket::stream_base::decorator([this](websocket::request_type &req) {
        req.set(beast::http::field::host, config_.host_header);
        req.set(beast::http::field::user_agent, "sbox-cpp/0.1");
      }));

  co_await ws.async_handshake(config_.host_header, config_.path,
                              asio::use_awaitable);

  co_return std::make_unique<TlsWsStream>(std::move(ws));
}

} // namespace sbox