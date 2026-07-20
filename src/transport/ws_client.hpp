#pragma once
#include "config/config.hpp"
#include "core/net.hpp"
#include "core/utils.hpp"
#include "stream.hpp"
#include "transport/stream.hpp"
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <memory>
#include <vector>

namespace sbox {

namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace ssl = boost::asio::ssl;

struct WsClientConfig {
  std::string server_host;
  std::uint16_t server_port = 443;
  std::string uuid;
  std::string path = "/";
  std::string host_header;
  TlsConfig tls;
};
class WsClient {
public:
  explicit WsClient(asio::io_context &io, WsClientConfig config);
  asio::awaitable<std::unique_ptr<Stream>> connect();

private:
  ssl::context ssl_context_;
  tcp::resolver resolver_;
  WsClientConfig config_;
};
}; // namespace sbox