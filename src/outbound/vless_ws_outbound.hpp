#pragma once

#include "core/session.hpp"
#include "core/utils.hpp"
#include "outbound.hpp"
#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/beast.hpp>
#include <boost/beast/core/error.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/core/stream_traits.hpp>
#include <boost/beast/http/field.hpp>
#include <boost/beast/http/fields_fwd.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/ssl/ssl_stream.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/rfc6455.hpp>
#include <boost/beast/websocket/stream.hpp>
#include <boost/beast/websocket/stream_base.hpp>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <string>
#include <vector>

namespace sbox {
namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace ssl = boost::asio::ssl;
using boost::asio::experimental::awaitable_operators::operator||;
struct VLessWsConfig {
  std::string server_host;
  std::uint16_t server_port = 443;
  std::string uuid;
  std::string ws_path = "/";
  std::string host_header;
  bool allow_insecure = false;
};
class VlessWsOutbound : public Outbound {
public:
  explicit VlessWsOutbound(asio::io_context &io, VLessWsConfig config);
  asio::awaitable<void> handle(tcp::socket inbound, Session session) override;

private:
  using WsTlsStream = websocket::stream<beast::ssl_stream<tcp::socket>>;
  asio::awaitable<void> connect_websocket(WsTlsStream &ws);
  std::vector<unsigned char> build_vless_request(const Destination &dst) const;
  asio::awaitable<void> relay_tcp_to_ws(tcp::socket &tcp_socket,
                                        WsTlsStream &ws);
  asio::awaitable<void> relay_ws_to_tcp(WsTlsStream &ws,
                                        tcp::socket &tcp_socket);
  static void strip_vless_response_header(std::vector<unsigned char> &bytes);
  asio::io_context &io_;
  ssl::context ssl_context_;
  tcp::resolver resolver_;
  VLessWsConfig config_;
};
}; // namespace sbox