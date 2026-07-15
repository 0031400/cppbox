#pragma once
#include "outbound/outbound.hpp"
#include "protocol/vless.hpp"
#include "transport/ws_client.hpp"
#include <boost/asio/io_context.hpp>
namespace sbox {
struct VlessOutboundConfig {
  VlessConfig vless;
  WsClientConfig transport;
};
class VlessOutbound : public Outbound {
public:
  explicit VlessOutbound(asio::io_context &io, VlessOutboundConfig config);

  asio::awaitable<void> handle(tcp::socket socket, Session session) override;

private:
  asio::awaitable<void> relay_tcp_to_ws(tcp::socket &tcp_socket,
                                        WsConnection &ws);
  asio::awaitable<void> relay_ws_to_tcp(WsConnection &ws,
                                        tcp::socket &tcp_socket);
  VlessProtocol protocol_;
  WsClient transport_;
};
}; // namespace sbox