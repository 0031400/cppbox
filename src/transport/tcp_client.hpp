#pragma once
#include "config/config.hpp"
#include "core/net.hpp"
#include "dns/dns.hpp"
#include "transport/stream.hpp"
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ssl/context.hpp>
#include <memory>
#include <string>
namespace sbox {
struct TcpClientConfig {
  std::string server_host;
  std::uint16_t server_port = 443;
  TlsConfig tls;
};
class TcpClient {
public:
  explicit TcpClient(asio::io_context &io, TcpClientConfig config,
                     DnsServer &dns_server);
  asio::awaitable<std::unique_ptr<Stream>> connect();

private:
  ssl::context ssl_context_;
  DnsServer &dns_server_;
  TcpClientConfig config_;
};
} // namespace sbox