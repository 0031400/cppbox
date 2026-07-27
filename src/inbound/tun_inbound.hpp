#pragma once

#include "config/config.hpp"
#include "core/net.hpp"
#include "core/session.hpp"
#include "inbound/inbound.hpp"
#include "inbound/tun_nat.hpp"
#include "inbound/tun_wintun.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>

namespace cppbox {

struct TunInboundConfig {
  std::string tun_ip;
  std::string tun_next_ip;
};

class TunInbound : public Inbound {
public:
  using Handler = std::function<asio::awaitable<void>(tcp::socket, Session)>;

  TunInbound(asio::io_context &io, TunInboundConfig config, Handler handler);
  ~TunInbound() override;

  TunInbound(const TunInbound &) = delete;
  TunInbound &operator=(const TunInbound &) = delete;
  void stop() noexcept override;
  asio::awaitable<void> start() override;

private:
  asio::awaitable<void> accept_loop();
  asio::awaitable<void> handle_client(tcp::socket socket);

  void packet_loop();
  bool process_tcp_packet(std::uint8_t *packet, std::uint32_t size);

  asio::io_context &io_;
  TunInboundConfig config_;
  Handler handler_;

  WintunApi wintun_;
  TunNat nat_;
  tcp::acceptor acceptor_;

  std::thread packet_thread_;
  std::atomic_bool stopping_{false};

  NET_LUID luid_{};
  bool routes_configured_{false};
  std::uint32_t tun_ip_{};
  std::uint32_t tun_next_ip_{};
  std::uint16_t tcp_listen_port_{};
};

} // namespace cppbox