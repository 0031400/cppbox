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
#include <boost/asio/use_awaitable.hpp>
#include <cstring>
#include <stdexcept>
#include <utility>

#ifdef _WIN32
#include <windows.h>
#endif

namespace sbox {
namespace {

constexpr std::uint8_t tcp_protocol = 6;

void write_be16(std::uint8_t *p, std::uint16_t value) {
  p[0] = static_cast<std::uint8_t>(value >> 8);
  p[1] = static_cast<std::uint8_t>(value);
}

std::uint32_t ipv4_to_net_order_u32(const std::string &text) {
  auto addr = boost::asio::ip::make_address_v4(text);
  auto bytes = addr.to_bytes();

  std::uint32_t value{};
  std::memcpy(&value, bytes.data(), sizeof(value));
  return value;
}

boost::asio::ip::address_v4 address_from_net_u32(std::uint32_t value) {
  std::array<unsigned char, 4> bytes{};
  std::memcpy(bytes.data(), &value, sizeof(value));
  return boost::asio::ip::address_v4(bytes);
}

std::string ipv4_to_string(std::uint32_t value) {
  return address_from_net_u32(value).to_string();
}

} // namespace

TunInbound::TunInbound(asio::io_context &io, TunInboundConfig config,
                       Handler handler)
    : io_(io), config_(std::move(config)), handler_(std::move(handler)),
      acceptor_(io) {}

TunInbound::~TunInbound() { stop(); }

asio::awaitable<void> TunInbound::start() {

  tun_ip_ = ipv4_to_net_order_u32(config_.tun_ip);
  tun_next_ip_ = ipv4_to_net_order_u32(config_.tun_next_ip);

  if (!wintun_.load()) {
    throw std::runtime_error("failed to load wintun.dll");
  }

  if (!wintun_.open_adapter(L"SboxTun")) {
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

  boost::system::error_code ec;
  tcp::endpoint endpoint(address_from_net_u32(tun_ip_), 0);

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
  auto nat_session = nat_.lookup_back(nat_port);
  if (!nat_session) {
    log_error("[tun] unknown nat port: " + std::to_string(nat_port));
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
}

void TunInbound::packet_loop() {
  while (!stopping_.load()) {
    TunPacket packet = wintun_.receive();

    if (packet.data) {
      if (process_tcp_packet(packet.data, packet.size)) {
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

bool TunInbound::process_tcp_packet(std::uint8_t *packet, std::uint32_t size) {
  if (size < 20) {
    return false;
  }

  if ((packet[0] >> 4) != 4) {
    return false;
  }

  if (packet[9] != tcp_protocol) {
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
    auto nat_session = nat_.lookup_back(dst_port);
    if (!nat_session) {
      return false;
    }

    std::memcpy(packet + 12, &nat_session->dest_ip,
                sizeof(nat_session->dest_ip));
    std::memcpy(packet + 16, &nat_session->source_ip,
                sizeof(nat_session->source_ip));

    write_be16(tcp, nat_session->dest_port);
    write_be16(tcp + 2, nat_session->source_port);
  } else {
    const auto nat_port =
        nat_.lookup_or_create(src_ip, src_port, dst_ip, dst_port);

    std::memcpy(packet + 12, &tun_next_ip_, sizeof(tun_next_ip_));
    std::memcpy(packet + 16, &tun_ip_, sizeof(tun_ip_));

    write_be16(tcp, nat_port);
    write_be16(tcp + 2, tcp_listen_port_);
  }

  recalc_ipv4_checksum(packet);
  recalc_tcp_checksum(packet, tcp, tcp_len);
  return true;
}

void TunInbound::stop() {
  if (stopping_.exchange(true)) {
    return;
  }

  boost::system::error_code ignored;
  acceptor_.close(ignored);
  if (routes_configured_) {
    cleanup_tun_routes(luid_, config_.tun_ip, config_.tun_next_ip);
    routes_configured_ = false;
  }
  if (packet_thread_.joinable()) {
    packet_thread_.join();
  }
}

} // namespace sbox