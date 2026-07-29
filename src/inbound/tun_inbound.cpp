#include "inbound/tun_inbound.hpp"

#include "core/address.hpp"
#include "core/log.hpp"
#include "core/utils.hpp"
#include "inbound/tun_checksum.hpp"
#include "inbound/tun_route.hpp"

#include <array>
#include <boost/asio/buffer.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace cppbox {
namespace {

constexpr std::uint8_t tcp_protocol = 6;
constexpr std::uint8_t udp_protocol = 17;

bool is_ipv4_packet(const std::uint8_t *packet, std::uint32_t size) {
  return size >= 20 && (packet[0] >> 4) == 4;
}

std::string ipv4_to_string(std::uint32_t value) {
  return address_v4_from_net_order_u32(value).to_string();
}

} // namespace

TunInbound::TunInbound(asio::io_context &io, TunInboundConfig config,
                       Handler handler, Connector &connector)
    : io_(io), config_(std::move(config)), handler_(std::move(handler)),
      connector_(connector), acceptor_(io) {}

TunInbound::~TunInbound() { stop(); }

asio::awaitable<void> TunInbound::start() {
  tun_ip_ = ipv4_to_net_order_u32(config_.tun_ip);
  tun_next_ip_ = ipv4_to_net_order_u32(config_.tun_next_ip);

  if (!wintun_.load()) {
    throw std::runtime_error("failed to load wintun.dll");
  }

  if (!wintun_.open_adapter(L"cppboxTun")) {
    throw std::runtime_error("failed to open wintun adapter");
  }

  if (!wintun_.start_session(0x800000)) {
    throw std::runtime_error("failed to start wintun session");
  }

  if (!wintun_.adapter_luid(luid_)) {
    throw std::runtime_error("failed to get wintun adapter luid");
  }

  if (!configure_tun_routes(luid_, config_.tun_ip, config_.tun_next_ip)) {
    throw std::runtime_error("failed to configure tun routes");
  }

  routes_configured_ = true;

  boost::system::error_code ec;
  tcp::endpoint endpoint(address_v4_from_net_order_u32(tun_ip_), 0);

  acceptor_.open(endpoint.protocol(), ec);
  if (ec) {
    throw std::runtime_error("tun acceptor open failed: " + ec.message());
  }

  acceptor_.set_option(tcp::acceptor::reuse_address(true), ec);
  if (ec) {
    throw std::runtime_error("tun acceptor set_option failed: " + ec.message());
  }

  acceptor_.bind(endpoint, ec);
  if (ec) {
    throw std::runtime_error("tun acceptor bind failed: " + ec.message());
  }

  acceptor_.listen(asio::socket_base::max_listen_connections, ec);
  if (ec) {
    throw std::runtime_error("tun acceptor listen failed: " + ec.message());
  }

  tcp_listen_port_ = acceptor_.local_endpoint(ec).port();
  if (ec) {
    throw std::runtime_error("tun acceptor local_endpoint failed: " +
                             ec.message());
  }

  log_info("tun tcp relay listening on " + config_.tun_ip + ":" +
           std::to_string(tcp_listen_port_));

  packet_thread_ = std::thread([this] { packet_loop(); });

  co_await accept_loop();
}

asio::awaitable<void> TunInbound::accept_loop() {
  try {
    for (;;) {
      tcp::socket socket = co_await acceptor_.async_accept(asio::use_awaitable);
      asio::co_spawn(io_, handle_client(std::move(socket)), asio::detached);
    }
  } catch (const boost::system::system_error &e) {
    if (e.code() != asio::error::operation_aborted) {
      log_error(std::string("[tun] accept failed: ") + e.what());
    }
  }
}

asio::awaitable<void> TunInbound::handle_client(tcp::socket socket) {
  boost::system::error_code ec;
  auto peer = socket.remote_endpoint(ec);
  if (ec) {
    close_socket(socket);
    co_return;
  }

  const auto nat_port = peer.port();
  auto nat_session = tcp_nat_.lookup_back(nat_port);
  if (!nat_session) {
    log_error("[tun] unknown tcp nat port: " + std::to_string(nat_port));
    close_socket(socket);
    co_return;
  }

  Session session{
      .destination =
          Destination{
              .host = Host::ipv4(ipv4_to_string(nat_session->dest_ip)),
              .port = nat_session->dest_port,
          },
  };

  try {
    co_await handler_(std::move(socket), std::move(session));
  } catch (const std::exception &e) {
    log_error(std::string("[tun] handler failed: ") + e.what());
  }

  tcp_nat_.erase(nat_port);
}

void TunInbound::packet_loop() {
  while (!stopping_.load()) {
    TunPacket packet = wintun_.receive();

    if (packet.data) {
      if (handle_ipv4_packet(packet.data, packet.size)) {
        std::lock_guard lock(wintun_write_mutex_);
        wintun_.write(packet.data, packet.size);
      }

      wintun_.release(packet);
      continue;
    }

    DWORD err = GetLastError();
    if (err == ERROR_NO_MORE_ITEMS) {
      HANDLE wait_event = wintun_.read_wait_event();
      WaitForSingleObject(wait_event, 100);
      continue;
    }

    if (err == ERROR_HANDLE_EOF || stopping_.load()) {
      break;
    }

    log_error("[tun] wintun receive failed: " + std::to_string(err));
    break;
  }
}

bool TunInbound::handle_ipv4_packet(std::uint8_t *packet, std::uint32_t size) {
  if (!is_ipv4_packet(packet, size)) {
    return false;
  }

  if (packet[9] == tcp_protocol) {
    return handle_tcp_packet(packet, size);
  }

  if (packet[9] == udp_protocol) {
    return handle_udp_packet(packet, size);
  }

  return false;
}

bool TunInbound::handle_tcp_packet(std::uint8_t *packet, std::uint32_t size) {
  if (size < 20 || (packet[0] >> 4) != 4 || packet[9] != tcp_protocol) {
    return false;
  }

  const auto ip_header_len = static_cast<std::uint8_t>((packet[0] & 0x0f) * 4);
  if (size < ip_header_len + 20u) {
    return false;
  }

  const auto total_len = read_be16(packet + 2);
  if (total_len > size || total_len < ip_header_len + 20) {
    return false;
  }

  std::uint8_t *tcp = packet + ip_header_len;
  const auto tcp_len = static_cast<std::size_t>(total_len - ip_header_len);

  std::uint32_t src_ip{};
  std::uint32_t dst_ip{};
  std::memcpy(&src_ip, packet + 12, sizeof(src_ip));
  std::memcpy(&dst_ip, packet + 16, sizeof(dst_ip));

  const auto src_port = read_be16(tcp);
  const auto dst_port = read_be16(tcp + 2);

  if (src_ip == tun_ip_ && src_port == tcp_listen_port_) {
    return handle_tcp_from_local_relay(packet, tcp, tcp_len, dst_port);
  }

  return handle_tcp_from_stack(packet, tcp, tcp_len, src_ip, src_port, dst_ip,
                               dst_port);
}

bool TunInbound::handle_tcp_from_local_relay(std::uint8_t *packet,
                                             std::uint8_t *tcp,
                                             std::size_t tcp_len,
                                             std::uint16_t nat_port) {
  auto nat_session = tcp_nat_.lookup_back(nat_port);
  if (!nat_session) {
    return false;
  }

  std::memcpy(packet + 12, &nat_session->dest_ip,
              sizeof(nat_session->dest_ip));
  std::memcpy(packet + 16, &nat_session->source_ip,
              sizeof(nat_session->source_ip));

  write_be16(tcp, nat_session->dest_port);
  write_be16(tcp + 2, nat_session->source_port);

  recalc_ipv4_checksum(packet);
  recalc_tcp_checksum(packet, tcp, tcp_len);
  return true;
}

bool TunInbound::handle_tcp_from_stack(std::uint8_t *packet, std::uint8_t *tcp,
                                       std::size_t tcp_len,
                                       std::uint32_t src_ip,
                                       std::uint16_t src_port,
                                       std::uint32_t dst_ip,
                                       std::uint16_t dst_port) {
  const auto nat_port =
      tcp_nat_.lookup_or_create(src_ip, src_port, dst_ip, dst_port);

  std::memcpy(packet + 12, &tun_next_ip_, sizeof(tun_next_ip_));
  std::memcpy(packet + 16, &tun_ip_, sizeof(tun_ip_));

  write_be16(tcp, nat_port);
  write_be16(tcp + 2, tcp_listen_port_);

  recalc_ipv4_checksum(packet);
  recalc_tcp_checksum(packet, tcp, tcp_len);
  return true;
}

struct TunInbound::TunUdpFlow
    : public std::enable_shared_from_this<TunUdpFlow> {
  TunUdpFlow(TunInbound &owner, std::uint16_t nat_port, TunNatSession session)
      : owner(owner), nat_port(nat_port), session(session), socket(owner.io_) {}

  void enqueue(std::vector<std::uint8_t> payload) {
    bool should_start = false;
    bool should_send = false;

    {
      std::lock_guard lock(mutex);
      pending.push_back(std::move(payload));

      if (!connecting && !connected) {
        connecting = true;
        should_start = true;
      } else if (connected && !sending) {
        sending = true;
        should_send = true;
      }
    }

    auto self = shared_from_this();
    if (should_start) {
      asio::co_spawn(owner.io_, self->start(), asio::detached);
    } else if (should_send) {
      asio::co_spawn(owner.io_, self->send_loop(), asio::detached);
    }
  }

  asio::awaitable<void> start() {
    try {
      Destination destination{
          .host = Host::ipv4(ipv4_to_string(session.dest_ip)),
          .port = session.dest_port,
      };

      co_await owner.connector_.connect(socket, destination);

      bool should_send = false;
      {
        std::lock_guard lock(mutex);
        connected = true;
        connecting = false;
        if (!sending) {
          sending = true;
          should_send = true;
        }
      }

      if (should_send) {
        asio::co_spawn(owner.io_, shared_from_this()->send_loop(),
                       asio::detached);
      }

      asio::co_spawn(owner.io_, shared_from_this()->recv_loop(),
                     asio::detached);
    } catch (const std::exception &e) {
      log_error(std::string("[tun][udp] connect failed: ") + e.what());
      owner.erase_udp_flow(nat_port);
    }
  }

  asio::awaitable<void> send_loop() {
    try {
      for (;;) {
        std::vector<std::uint8_t> payload;
        bool should_return = false;

        {
          std::lock_guard lock(mutex);
          if (pending.empty()) {
            sending = false;
            should_return = true;
          } else {
            payload = std::move(pending.front());
            pending.pop_front();
          }
        }

        if (should_return) {
          co_return;
        }

        boost::system::error_code ec;
        co_await socket.async_send(
            asio::buffer(payload),
            asio::redirect_error(asio::use_awaitable, ec));

        if (ec) {
          throw boost::system::system_error(ec);
        }
      }
    } catch (const std::exception &e) {
      log_error(std::string("[tun][udp] send failed: ") + e.what());
      owner.erase_udp_flow(nat_port);
    }
  }

  asio::awaitable<void> recv_loop() {
    std::array<std::uint8_t, 65535> buffer{};

    try {
      for (;;) {
        boost::system::error_code ec;
        auto n = co_await socket.async_receive(
            asio::buffer(buffer),
            asio::redirect_error(asio::use_awaitable, ec));

        if (ec) {
          break;
        }

        owner.write_udp_response(session, buffer.data(), n);
      }
    } catch (const std::exception &e) {
      log_error(std::string("[tun][udp] recv failed: ") + e.what());
    }

    owner.erase_udp_flow(nat_port);
  }

  void close() {
    boost::system::error_code ignored;
    socket.close(ignored);
  }

  TunInbound &owner;
  std::uint16_t nat_port{};
  TunNatSession session;
  udp::socket socket;
  std::mutex mutex;
  std::deque<std::vector<std::uint8_t>> pending;
  bool connecting{false};
  bool connected{false};
  bool sending{false};
};

bool TunInbound::handle_udp_packet(std::uint8_t *packet, std::uint32_t size) {
  if (size < 20 || (packet[0] >> 4) != 4 || packet[9] != udp_protocol) {
    return false;
  }

  const auto ip_header_len = static_cast<std::uint8_t>((packet[0] & 0x0f) * 4);
  if (size < ip_header_len + 8u) {
    return false;
  }

  const auto total_len = read_be16(packet + 2);
  if (total_len > size || total_len < ip_header_len + 8) {
    return false;
  }

  const auto fragment = read_be16(packet + 6);
  if ((fragment & 0x3fff) != 0) {
    return false;
  }

  std::uint8_t *udp_header = packet + ip_header_len;
  const auto udp_len = read_be16(udp_header + 4);
  if (udp_len < 8 || ip_header_len + udp_len > total_len) {
    return false;
  }

  std::uint32_t src_ip{};
  std::uint32_t dst_ip{};
  std::memcpy(&src_ip, packet + 12, sizeof(src_ip));
  std::memcpy(&dst_ip, packet + 16, sizeof(dst_ip));

  const auto src_port = read_be16(udp_header);
  const auto dst_port = read_be16(udp_header + 2);
  const auto nat_port =
      udp_nat_.lookup_or_create(src_ip, src_port, dst_ip, dst_port);

  auto session = udp_nat_.lookup_back(nat_port);
  if (!session) {
    return false;
  }

  std::shared_ptr<TunUdpFlow> flow;
  {
    std::lock_guard lock(udp_flows_mutex_);
    auto it = udp_flows_.find(nat_port);
    if (it == udp_flows_.end()) {
      flow = std::make_shared<TunUdpFlow>(*this, nat_port, *session);
      udp_flows_[nat_port] = flow;
    } else {
      flow = it->second;
    }
  }

  const auto payload_len = static_cast<std::size_t>(udp_len - 8);
  std::vector<std::uint8_t> payload(payload_len);
  std::memcpy(payload.data(), udp_header + 8, payload_len);
  flow->enqueue(std::move(payload));

  return false;
}

void TunInbound::write_udp_response(const TunNatSession &session,
                                    const std::uint8_t *data,
                                    std::size_t size) {
  const auto ip_header_len = 20u;
  const auto udp_header_len = 8u;
  const auto udp_len = udp_header_len + size;
  const auto total_len = ip_header_len + udp_len;

  if (total_len > 65535) {
    return;
  }

  std::vector<std::uint8_t> packet(total_len);
  packet[0] = 0x45;
  packet[8] = 64;
  packet[9] = udp_protocol;

  write_be16(packet.data() + 2, static_cast<std::uint16_t>(total_len));
  write_be16(packet.data() + 6, 0x4000);

  std::memcpy(packet.data() + 12, &session.dest_ip, sizeof(session.dest_ip));
  std::memcpy(packet.data() + 16, &session.source_ip,
              sizeof(session.source_ip));

  auto *udp_header = packet.data() + ip_header_len;
  write_be16(udp_header, session.dest_port);
  write_be16(udp_header + 2, session.source_port);
  write_be16(udp_header + 4, static_cast<std::uint16_t>(udp_len));

  std::memcpy(udp_header + udp_header_len, data, size);

  recalc_ipv4_checksum(packet.data());
  recalc_udp_checksum(packet.data(), udp_header, udp_len);

  std::lock_guard lock(wintun_write_mutex_);
  wintun_.write(packet.data(), static_cast<std::uint32_t>(packet.size()));
}

void TunInbound::erase_udp_flow(std::uint16_t nat_port) {
  std::shared_ptr<TunUdpFlow> flow;
  {
    std::lock_guard lock(udp_flows_mutex_);
    auto it = udp_flows_.find(nat_port);
    if (it == udp_flows_.end()) {
      return;
    }
    flow = it->second;
    udp_flows_.erase(it);
  }

  udp_nat_.erase(nat_port);
  flow->close();
}

void TunInbound::stop() noexcept {
  if (stopping_.exchange(true)) {
    return;
  }

  boost::system::error_code ignored;
  acceptor_.close(ignored);

  {
    std::vector<std::shared_ptr<TunUdpFlow>> flows;
    {
      std::lock_guard lock(udp_flows_mutex_);
      for (auto &[_, flow] : udp_flows_) {
        flows.push_back(flow);
      }
      udp_flows_.clear();
    }

    for (auto &flow : flows) {
      flow->close();
    }
  }

  if (routes_configured_) {
    cleanup_tun_routes(luid_, config_.tun_ip, config_.tun_next_ip);
    routes_configured_ = false;
  }

  if (packet_thread_.joinable()) {
    packet_thread_.join();
  }
}

} // namespace cppbox