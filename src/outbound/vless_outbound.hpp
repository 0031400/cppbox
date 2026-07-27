#pragma once
#include "config/config.hpp"
#include "dns/dns.hpp"
#include "outbound/outbound.hpp"
#include "protocol/vless.hpp"
#include "transport/ws_client.hpp"
#include <boost/asio/io_context.hpp>

namespace cppbox {
struct VlessOutboundConfig {
  Destination server;
  VlessConfig vless;
  std::optional<TlsConfig> tls;
  std::optional<TransportConfig> transport;
  bool override_address = false;
};
class VlessOutbound : public Outbound {
public:
  explicit VlessOutbound(asio::io_context &io, VlessOutboundConfig config,
                         Connector &connector);

  asio::awaitable<void> handle(tcp::socket socket, Session session) override;

private:
  asio::awaitable<std::unique_ptr<Stream>> connect_stream();
  asio::awaitable<void> relay_tcp_to_stream(tcp::socket &tcp_socket,
                                            Stream &stream);
  asio::awaitable<void> relay_stream_to_tcp(Stream &stream,
                                            tcp::socket &tcp_socket);
  asio::io_context &io_;
  VlessOutboundConfig config_;
  VlessProtocol protocol_;
  Connector &connector_;
  asio::awaitable<std::vector<unsigned char>>
  read_initial_payload(tcp::socket &tcp_socket);
};
}; // namespace cppbox