#include "transport/connector.hpp"

#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <stdexcept>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

namespace cppbox {
namespace {

#ifdef _WIN32
template <typename Socket, typename Protocol>
bool bind_socket_to_interface(Socket &socket, const Protocol &protocol,
                              std::uint32_t index) {
  if (index == 0) {
    return true;
  }

  if (protocol == Protocol::v4()) {
    DWORD value = htonl(index);
    return setsockopt(socket.native_handle(), IPPROTO_IP, IP_UNICAST_IF,
                      reinterpret_cast<const char *>(&value),
                      sizeof(value)) == 0;
  }

  if (protocol == Protocol::v6()) {
    DWORD value = index;
    return setsockopt(socket.native_handle(), IPPROTO_IPV6, IPV6_UNICAST_IF,
                      reinterpret_cast<const char *>(&value),
                      sizeof(value)) == 0;
  }

  return false;
}
#else
template <typename Socket, typename Protocol>
bool bind_socket_to_interface(Socket &, const Protocol &, std::uint32_t index) {
  return index == 0;
}
#endif

} // namespace

Connector::Connector(DnsServer &dns_server) : dns_server_(dns_server) {}

void Connector::set_outbound_interface_index(std::uint32_t index) {
  outbound_interface_index_ = index;
}

asio::awaitable<std::vector<ip::address>>
Connector::resolve_destination(const Destination &destination) {
  if (destination.host.is_ip()) {
    co_return std::vector<ip::address>{destination.host.asio_address()};
  }

  co_return co_await dns_server_.resolve(destination.host.domain());
}

asio::awaitable<void> Connector::connect(tcp::socket &socket,
                                         const Destination &destination) {
  const auto addresses = co_await resolve_destination(destination);
  if (addresses.empty()) {
    throw std::runtime_error("no endpoint resolved for: " +
                             destination.to_string());
  }

  boost::system::error_code last_ec;

  for (const auto &address : addresses) {
    const tcp::endpoint endpoint(address, destination.port);
    boost::system::error_code ignored;

    socket.close(ignored);
    socket.open(endpoint.protocol(), last_ec);
    if (last_ec) {
      continue;
    }

    if (!bind_socket_to_interface(socket, endpoint.protocol(),
                                  outbound_interface_index_)) {
      socket.close(ignored);
      throw std::runtime_error("failed to bind outbound socket to interface");
    }

    co_await socket.async_connect(
        endpoint, asio::redirect_error(asio::use_awaitable, last_ec));

    if (!last_ec) {
      co_return;
    }
  }

  throw std::runtime_error("connect failed: " + last_ec.message());
}

asio::awaitable<void> Connector::connect(udp::socket &socket,
                                         const Destination &destination) {
  const auto addresses = co_await resolve_destination(destination);
  if (addresses.empty()) {
    throw std::runtime_error("no endpoint resolved for: " +
                             destination.to_string());
  }

  const udp::endpoint endpoint(addresses.front(), destination.port);
  boost::system::error_code ignored;
  boost::system::error_code ec;

  socket.close(ignored);
  socket.open(endpoint.protocol(), ec);
  if (ec) {
    throw std::runtime_error("udp open failed: " + ec.message());
  }

  if (!bind_socket_to_interface(socket, endpoint.protocol(),
                                outbound_interface_index_)) {
    socket.close(ignored);
    throw std::runtime_error("failed to bind outbound UDP socket to interface");
  }

  co_await socket.async_connect(endpoint,
                                asio::redirect_error(asio::use_awaitable, ec));
  if (ec) {
    throw std::runtime_error("udp connect failed: " + ec.message());
  }
}

} // namespace cppbox