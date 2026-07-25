#include "transport/connector.hpp"
#include <boost/asio/connect.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <vector>

namespace sbox {

Connector::Connector(DnsServer &dns_server) : dns_server_(dns_server) {}

asio::awaitable<void> Connector::connect(tcp::socket &socket,
                                         const Destination &destination) {
  std::vector<tcp::endpoint> endpoints;

  if (destination.host.is_ip()) {
    endpoints.emplace_back(destination.host.asio_address(), destination.port);
  } else {
    const auto addresses = co_await dns_server_.resolve(destination.host.domain());
    for (const auto &address : addresses) {
      endpoints.emplace_back(address, destination.port);
    }
  }

  const auto results = tcp::resolver::results_type::create(
      endpoints.begin(), endpoints.end(), "", "");

  co_await asio::async_connect(socket, results, asio::use_awaitable);
}

} // namespace sbox