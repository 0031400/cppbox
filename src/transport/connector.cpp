#include "transport/connector.hpp"
#include <boost/asio/connect.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <vector>

#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>

namespace sbox {

Connector::Connector(DnsServer &dns_server) : dns_server_(dns_server) {}
bool bind_socket_to_interface(tcp::socket &socket, const tcp &protocol,
                              std::uint32_t index) {
  if (index == 0) {
    return true;
  }
  if (!socket.is_open()) {
    socket.open(protocol);
  }

  if (protocol == tcp::v4()) {
    DWORD value = htonl(index);
    return setsockopt(socket.native_handle(), IPPROTO_IP, IP_UNICAST_IF,
                      reinterpret_cast<const char *>(&value),
                      sizeof(value)) == 0;
  }

  if (protocol == tcp::v6()) {

    DWORD value = index;
    return setsockopt(socket.native_handle(), IPPROTO_IPV6, IPV6_UNICAST_IF,
                      reinterpret_cast<const char *>(&value),
                      sizeof(value)) == 0;
  }

  return false;
}
void Connector::set_outbound_interface_index(std::uint32_t index) {
  outbound_interface_index_ = index;
}
asio::awaitable<void> Connector::connect(tcp::socket &socket,
                                         const Destination &destination) {
  std::vector<tcp::endpoint> endpoints;

  if (destination.host.is_ip()) {
    endpoints.emplace_back(destination.host.asio_address(), destination.port);
  } else {
    const auto addresses =
        co_await dns_server_.resolve(destination.host.domain());
    for (const auto &address : addresses) {
      endpoints.emplace_back(address, destination.port);
    }
  }
  if (endpoints.empty()) {
    throw std::runtime_error("no endpoint resolved for: " +
                             destination.to_string());
  }
  boost::system::error_code last_ec;
  for (const auto &endpoint : endpoints) {
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

} // namespace sbox