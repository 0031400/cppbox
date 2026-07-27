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

using PlainTcpStream = TcpStreamImpl<tcp::socket>;
using TlsTcpStream = TcpStreamImpl<beast::ssl_stream<tcp::socket>>;

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

  beast::ssl_stream<tcp::socket> stream(co_await asio::this_coro::executor,
                                        ssl_context_);
  co_await connector_.connect(beast::get_lowest_layer(stream), config_.server);
  tls::configure_server_identity(stream, config_.tls.server_name,
                                 config_.tls.insecure);

  co_await stream.async_handshake(ssl::stream_base::client,
                                  asio::use_awaitable);

  co_return std::make_unique<TlsTcpStream>(std::move(stream));
}

} // namespace sbox