#include "transport/ws_client.hpp"
#include "core/utils.hpp"
#include <boost/asio/buffer.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>
#include <boost/asio/ssl/stream_base.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/core/stream_traits.hpp>
#include <boost/beast/http/field.hpp>
#include <boost/beast/websocket/stream.hpp>
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
    ignored = socket.cancel(ignored);
    ignored = socket.shutdown(tcp::socket::shutdown_both, ignored);
    ignored = socket.close(ignored);
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
    ignored = socket.cancel(ignored);
    ignored = socket.shutdown(tcp::socket::shutdown_both, ignored);
    ignored = socket.close(ignored);
  }

private:
  Socket ws_;
};

}; // namespace
WsClient::WsClient(asio::io_context &io, WsClientConfig config)
    : ssl_context_(ssl::context::tls_client), resolver_(io),
      config_(std::move(config)) {
  if (config_.host_header.empty()) {
    config_.host_header = config_.server_host;
  }
  if (config_.tls.enabled) {
    if (config_.tls.server_name.empty()) {
      config_.tls.server_name = config_.server_host;
    }
    ssl_context_.set_default_verify_paths();
    if (config_.tls.insecure) {
      ssl_context_.set_verify_mode(ssl::verify_none);
    } else {
      ssl_context_.set_verify_mode(ssl::verify_peer);
    }
  }
}

asio::awaitable<std::unique_ptr<Stream>> WsClient::connect() {
  auto port = std::to_string(config_.server_port);
  auto results = co_await resolver_.async_resolve(config_.server_host, port,
                                                  asio::use_awaitable);

  if (!config_.tls.enabled) {
    websocket::stream<tcp::socket> ws(co_await asio::this_coro::executor);
    co_await asio::async_connect(beast::get_lowest_layer(ws), results,
                                 asio::use_awaitable);
    ws.set_option(
        websocket::stream_base::decorator([this](websocket::request_type &req) {
          req.set(beast::http::field::host, config_.host_header);
          req.set(
              beast::http::field::user_agent,
              "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36");
        }));
    co_await ws.async_handshake(config_.host_header, config_.path,
                                asio::use_awaitable);
    co_return std::make_unique<PlainWsStream>(std::move(ws));
  }

  TlsWsStream::Socket ws(co_await asio::this_coro::executor, ssl_context_);
  co_await asio::async_connect(beast::get_lowest_layer(ws), results,
                               asio::use_awaitable);

  if (!SSL_set_tlsext_host_name(ws.next_layer().native_handle(),
                                config_.tls.server_name.c_str())) {
    throw beast::system_error(error_code(static_cast<int>(::ERR_get_error()),
                                         asio::error::get_ssl_category()),
                              "set tls sni");
  }

  if (!config_.tls.insecure) {
    ws.next_layer().set_verify_callback(
        ssl::host_name_verification(config_.tls.server_name));
  }

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

// #include "transport/ws_client.hpp"
// #include "core/utils.hpp"
// #include <boost/asio/buffer.hpp>
// #include <boost/asio/connect.hpp>
// #include <boost/asio/redirect_error.hpp>
// #include <boost/asio/ssl/context.hpp>
// #include <boost/asio/ssl/host_name_verification.hpp>
// #include <boost/asio/ssl/stream_base.hpp>
// #include <boost/asio/this_coro.hpp>
// #include <boost/asio/use_awaitable.hpp>
// #include <boost/beast/core/stream_traits.hpp>
// #include <boost/beast/http/field.hpp>
// #include <boost/system/system_error.hpp>
// #include <memory>
// #include <openssl/err.h>
// #include <openssl/ssl.h>
// #include <utility>
// #include <vector>

// namespace sbox {
// WsConnection::WsConnection(Stream stream) : ws_(std::move(stream)) {
//   ws_.binary(true);
// }

// asio::awaitable<void>
// WsConnection::write(const std::vector<unsigned char> &bytes) {
//   error_code ec;
//   co_await ws_.async_write(asio::buffer(bytes),
//                            asio::redirect_error(asio::use_awaitable, ec));
//   if (ec == asio::error::eof || ec == asio::error::connection_reset ||
//       ec == asio::error::operation_aborted || ec == websocket::error::closed)
//       {
//     co_return;
//   }
//   if (ec) {
//     throw boost::system::system_error(ec);
//   }
// }
// asio::awaitable<std::vector<unsigned char>> WsConnection::read() {
//   beast::flat_buffer buffer;
//   error_code ec;

//   co_await ws_.async_read(buffer,
//                           asio::redirect_error(asio::use_awaitable, ec));

//   if (ec == websocket::error::closed || ec == asio::error::eof ||
//       ec == asio::error::connection_reset ||
//       ec == asio::error::operation_aborted) {
//     co_return std::vector<unsigned char>{};
//   }
//   if (ec) {
//     throw boost::system::system_error(ec);
//   }
//   std::vector<unsigned char> bytes(buffer.size());
//   asio::buffer_copy(asio::buffer(bytes), buffer.data());
//   co_return bytes;
// }

// void WsConnection::close() {
//   error_code ignored;
//   auto &socket = beast::get_lowest_layer(ws_);
//   ignored = socket.cancel(ignored);
//   ignored = socket.shutdown(tcp::socket::shutdown_both, ignored);
//   ignored = socket.close(ignored);
// }
// WsClient::WsClient(asio::io_context &io, WsClientConfig config)
//     : io_(io), ssl_context_(ssl::context::tls_client), resolver_(io),
//       config_(std::move(config)) {
//   if (config_.host_header.empty()) {
//     config_.host_header = config_.server_host;
//   }
//   if (config_.tls.server_name.empty()) {
//     config_.tls.server_name = config_.server_host;
//   }
//   ssl_context_.set_default_verify_paths();
//   if (config_.tls.insecure) {
//     ssl_context_.set_verify_mode(ssl::verify_none);
//   } else {
//     ssl_context_.set_verify_mode(ssl::verify_peer);
//   }
// }
// asio::awaitable<std::unique_ptr<WsConnection>> WsClient::connect() {
//   WsConnection::Stream ws(co_await asio::this_coro::executor, ssl_context_);
//   auto port = std::to_string(config_.server_port);
//   auto results = co_await resolver_.async_resolve(config_.server_host, port,
//                                                   asio::use_awaitable);
//   co_await asio::async_connect(beast::get_lowest_layer(ws), results,
//                                asio::use_awaitable);
//   if (!SSL_set_tlsext_host_name(ws.next_layer().native_handle(),
//                                 config_.server_host.c_str())) {
//     throw beast::system_error(error_code(static_cast<int>(::ERR_get_error()),
//                                          asio::error::get_ssl_category()),
//                               "set tls sni");
//   }
//   if (!config_.tls.insecure) {
//     ws.next_layer().set_verify_callback(
//         ssl::host_name_verification(config_.server_host));
//   }
//   co_await ws.next_layer().async_handshake(ssl::stream_base::client,
//                                            asio::use_awaitable);
//   ws.set_option(
//       websocket::stream_base::decorator([this](websocket::request_type &req)
//       {
//         req.set(beast::http::field::host, config_.host_header);
//         req.set(beast::http::field::user_agent, "sbox-cpp/0.1");
//       }));
//   co_await ws.async_handshake(config_.host_header, config_.path,
//                               asio::use_awaitable);
//   co_return std::make_unique<WsConnection>(std::move(ws));
// }
// }; // namespace sbox