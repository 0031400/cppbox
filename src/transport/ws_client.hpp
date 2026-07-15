#pragma once
#include "core/net.hpp"
#include "core/utils.hpp"
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
struct TlsClientConfig {
  bool enabled = true;
  std::string server_name;
  bool insecure = false;
};
struct WsClientConfig {
  std::string server_host;
  std::uint16_t server_port = 443;
  std::string uuid;
  std::string path = "/";
  std::string host_header;
  TlsClientConfig tls;
};
class WsConnection {
public:
  using Stream = websocket::stream<beast::ssl_stream<tcp::socket>>;
  explicit WsConnection(Stream stream);
  asio::awaitable<void> write(const std::vector<unsigned char> &bytes);
  asio::awaitable<std::vector<unsigned char>> read();
  void close();

private:
  Stream ws_;
};
class WsClient {
public:
  explicit WsClient(asio::io_context &io, WsClientConfig config);
  asio::awaitable<std::unique_ptr<WsConnection>> connect();

private:
  asio::io_context &io_;
  ssl::context ssl_context_;
  tcp::resolver resolver_;
  WsClientConfig config_;
};
}; // namespace sbox