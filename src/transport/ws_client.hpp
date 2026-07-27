#pragma once

#include "config/config.hpp"
#include "core/address.hpp"
#include "core/net.hpp"
#include "dns/dns.hpp"
#include "transport/connector.hpp"
#include "transport/stream.hpp"
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <memory>
#include <string>

namespace sbox {

struct WsClientConfig {
  Destination server;
  std::string path = "/";
  std::string host_header;
  TlsConfig tls;
};

class WsClient {
public:
  WsClient(asio::io_context &io, WsClientConfig config, Connector &connector);

  asio::awaitable<std::unique_ptr<Stream>> connect();

private:
  ssl::context ssl_context_;
  WsClientConfig config_;
  Connector &connector_;
};

} // namespace sbox