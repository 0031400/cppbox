#pragma once

#include "config/config.hpp"
#include "core/address.hpp"
#include "core/net.hpp"
#include "transport/connector.hpp"
#include "transport/stream.hpp"
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl/context.hpp>
#include <memory>

namespace cppbox {

struct TcpClientConfig {
  Destination server;
  TlsConfig tls;
};

class TcpClient {
public:
  TcpClient(asio::io_context &io, TcpClientConfig config, Connector &connector);

  asio::awaitable<std::unique_ptr<Stream>> connect();

private:
  ssl::context ssl_context_;
  Connector &connector_;
  TcpClientConfig config_;
};

} // namespace cppbox