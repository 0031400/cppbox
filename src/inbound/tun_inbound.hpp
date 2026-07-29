#pragma once

#include "config/config.hpp"
#include "core/net.hpp"
#include "core/session.hpp"
#include "inbound/inbound.hpp"
#include "inbound/tun_nat.hpp"
#include "inbound/tun_wintun.hpp"
#include "transport/connector.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

namespace cppbox {

struct TunInboundConfig {
  std::string tun_ip;
  std::string tun_next_ip;
};

class TunInbound : public Inbound {
public:
  using Handler = std::function<asio::awaitable<void>(tcp::socket, Session)>;

  TunInbound(asio::io_context &io, TunInboundConfig config, Handler handler,
             Connector &connector);
  ~TunInbound() override;

  TunInbound(const TunInbound &) = delete;
  TunInbound &operator=(const TunInbound &) = delete;

  void stop() noexcept override;
  asio::awaitable<void> start() override;

private:
  struct TunUdpFlow;

  asio::awaitable<void> accept_loop();
  asio::awaitable<void> handle_client(tcp::socket socket);

  void packet_loop();
  bool handle_ipv4_packet(std::uint8_t *packet, std::uint32_t size);

  bool handle_tcp_packet(std::uint8_t *packet, std::uint32_t size);
  bool handle_tcp_from_local_relay(std::uint8_t *packet, std::uint8_t *tcp,
                                   std::size_t tcp_len,
                                   std::uint16_t nat_port);
  bool handle_tcp_from_stack(std::uint8_t *packet, std::uint8_t *tcp,
                             std::size_t tcp_len, std::uint32_t src_ip,
                             std::uint16_t src_port, std::uint32_t dst_ip,
                             std::uint16_t dst_port);

  bool handle_udp_packet(std::uint8_t *packet, std::uint32_t size);
  void write_udp_response(const TunNatSession &session, const std::uint8_t *data,
                          std::size_t size);
  void erase_udp_flow(std::uint16_t nat_port);

  asio::io_context &io_;
  TunInboundConfig config_;
  Handler handler_;
  Connector &connector_;

  WintunApi wintun_;
  TunNat tcp_nat_;
  TunNat udp_nat_;
  tcp::acceptor acceptor_;

  std::mutex udp_flows_mutex_;
  std::mutex wintun_write_mutex_;
  std::unordered_map<std::uint16_t, std::shared_ptr<TunUdpFlow>> udp_flows_;

  std::thread packet_thread_;
  std::atomic_bool stopping_{false};

  NET_LUID luid_{};
  bool routes_configured_{false};
  std::uint32_t tun_ip_{};
  std::uint32_t tun_next_ip_{};
  std::uint16_t tcp_listen_port_{};
};

} // namespace cppbox