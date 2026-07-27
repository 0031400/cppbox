#include "transport/tcp_client.hpp"
#include "core/log.hpp"
#include "core/net.hpp"
#include "core/tls.hpp"
#include "transport/stream_utils.hpp"
#include <array>
#include <boost/asio/buffer.hpp>
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

    if (is_stream_closed(ec)) {
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

    if (is_stream_closed(ec)) {
      co_return;
    }

    if (ec) {
      throw boost::system::system_error(ec);
    }
  }

  void close() override {
    error_code ignored;
    socket_.cancel(ignored);
    socket_.shutdown(tcp::socket::shutdown_both, ignored);
    socket_.close(ignored);
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

    if (is_stream_closed(ec)) {
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

    if (is_stream_closed(ec)) {
      co_return;
    }

    if (ec) {
      throw boost::system::system_error(ec);
    }
  }

  void close() override {
    error_code ignored;
    auto &socket = beast::get_lowest_layer(stream_);
    socket.cancel(ignored);
    socket.shutdown(tcp::socket::shutdown_both, ignored);
    socket.close(ignored);
  }

private:
  Socket stream_;
};

} // namespace
TcpClient::TcpClient(asio::io_context &io, TcpClientConfig config,
                     Connector &connector)
    : ssl_context_(ssl::context::tls_client), connector_(connector),
      config_(std::move(config)) {
  if (config_.tls.enabled) {
    if (config_.tls.server_name.empty()) {
      config_.tls.server_name = config_.server.host.to_string();
    }

    tls::configure_client_context(ssl_context_, config_.tls.insecure);
  }
}

asio::awaitable<std::unique_ptr<Stream>> TcpClient::connect() {
  if (!config_.tls.enabled) {
    tcp::socket socket(co_await asio::this_coro::executor);
    co_await connector_.connect(socket, config_.server);

    co_return std::make_unique<PlainTcpStream>(std::move(socket));
  }

  TlsTcpStream::Socket stream(co_await asio::this_coro::executor, ssl_context_);
  co_await connector_.connect(beast::get_lowest_layer(stream), config_.server);
  tls::configure_server_identity(stream, config_.tls.server_name,
                                 config_.tls.insecure);

  co_await stream.async_handshake(ssl::stream_base::client,
                                  asio::use_awaitable);

  co_return std::make_unique<TlsTcpStream>(std::move(stream));
}

} // namespace sbox