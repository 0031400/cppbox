#include "transport/tcp_client.hpp"
#include "core/log.hpp"
#include "core/net.hpp"
#include <array>
#include <boost/asio/buffer.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>
#include <boost/asio/ssl/stream_base.hpp>
#include <boost/asio/ssl/verify_mode.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/core/stream_traits.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/system/system_error.hpp>
#include <memory>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <string>
#include <utility>
#include <vector>

namespace sbox {
namespace {
class PlainTcpStream final : public Stream {
public:
  explicit PlainTcpStream(tcp::socket socket) : socket_(std::move(socket)) {}
  asio::awaitable<std::vector<unsigned char>> read() override {
    std::array<unsigned char, 16 * 1024> buffer{};
    error_code ec;
    auto n = co_await socket_.async_read_some(
        asio::buffer(buffer), asio::redirect_error(asio::use_awaitable, ec));
    if (ec == asio::error::eof || ec == asio::error::connection_reset ||
        ec == asio::error::operation_aborted) {
      co_return std::vector<unsigned char>{};
    }
    if (ec) {
      throw boost::system::system_error(ec);
    }
    co_return std::vector<unsigned char>(buffer.begin(), buffer.begin() + n);
  }
  asio::awaitable<void>
  write(const std::vector<unsigned char> &bytes) override {
    error_code ec;
    co_await asio::async_write(socket_, asio::buffer(bytes),
                               asio::redirect_error(asio::use_awaitable, ec));
    if (ec == asio::error::eof || ec == asio::error::connection_reset ||
        ec == asio::error::operation_aborted) {
      co_return;
    }
    if (ec) {
      throw boost::system::system_error(ec);
    }
  }
  void close() override {
    error_code ignored;
    ignored = socket_.cancel(ignored);
    ignored = socket_.shutdown(tcp::socket::shutdown_both, ignored);
    ignored = socket_.close(ignored);
  }

private:
  tcp::socket socket_;
};

class TlsTcpStream final : public Stream {
public:
  using Socket = beast::ssl_stream<tcp::socket>;

  explicit TlsTcpStream(Socket stream) : stream_(std::move(stream)) {}
  asio::awaitable<std::vector<unsigned char>> read() override {

    std::array<unsigned char, 16 * 1024> buffer{};
    error_code ec;
    auto n = co_await stream_.async_read_some(
        asio::buffer(buffer), asio::redirect_error(asio::use_awaitable, ec));
    if (ec == asio::error::eof || ec == asio::error::connection_reset ||
        ec == asio::error::operation_aborted) {
      co_return std::vector<unsigned char>{};
    }
    if (ec) {
      throw boost::system::system_error(ec);
    }
    co_return std::vector<unsigned char>(buffer.begin(), buffer.begin() + n);
  }
  asio::awaitable<void>
  write(const std::vector<unsigned char> &bytes) override {
    error_code ec;
    co_await asio::async_write(stream_, asio::buffer(bytes),
                               asio::redirect_error(asio::use_awaitable, ec));
    if (ec == asio::error::eof || ec == asio::error::connection_reset ||
        ec == asio::error::operation_aborted) {
      co_return;
    }
    if (ec) {
      throw boost::system::system_error(ec);
    }
  }
  void close() override {
    error_code ignored;
    auto &socket = beast::get_lowest_layer(stream_);
    ignored = socket.cancel(ignored);
    ignored = socket.shutdown(tcp::socket::shutdown_both, ignored);
    ignored = socket.close(ignored);
  }

private:
  Socket stream_;
};
}; // namespace
TcpClient::TcpClient(asio::io_context &io, TcpClientConfig config)
    : ssl_context_(ssl::context::tls_client), resolver_(io),
      config_(std::move(config)) { // namespace
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

asio::awaitable<std::unique_ptr<Stream>> TcpClient::connect() {
  auto port = std::to_string(config_.server_port);
  auto results = co_await resolver_.async_resolve(config_.server_host, port,
                                                  asio::use_awaitable);
  if (!config_.tls.enabled) {
    tcp::socket socket(co_await asio::this_coro::executor);
    co_await asio::async_connect(socket, results, asio::use_awaitable);
    co_return std::make_unique<PlainTcpStream>(std::move(socket));
  }
  TlsTcpStream::Socket stream(co_await asio::this_coro::executor, ssl_context_);
  co_await asio::async_connect(beast::get_lowest_layer(stream), results,
                               asio::use_awaitable);
  if (!SSL_set_tlsext_host_name(stream.native_handle(),
                                config_.tls.server_name.c_str())) {

    throw beast::system_error(error_code(static_cast<int>(::ERR_get_error()),
                                         asio::error::get_ssl_category()),
                              "set tls sni");
  }
  if (!config_.tls.insecure) {
    stream.set_verify_callback(
        ssl::host_name_verification(config_.tls.server_name));
  }
  co_await stream.async_handshake(ssl::stream_base::client,
                                  asio::use_awaitable);
  co_return std::make_unique<TlsTcpStream>(std::move(stream));
}
} // namespace sbox