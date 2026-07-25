#include "dns/dns.hpp"
#include "dns/dns_message.hpp"
#include "dns/transport.hpp"
#include <boost/asio/connect.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <stdexcept>
#include <string>
#include <vector>

namespace sbox {
namespace asio = boost::asio;
namespace ip = asio::ip;
using tcp = ip::tcp;

namespace {

dns_one::Bytes query_dns(const DnsConfig &config, const std::string &name,
                         dns_one::QueryType query_type) {
  const auto &server = config.proxyServerNameserver.server;
  const auto &type = config.proxyServerNameserver.type;
  const auto port = config.proxyServerNameserver.server_port;
  const auto &bootstrap = config.defaultNameserver.server;
  const auto query = dns_one::build_query(name, query_type);

  if (type == "udp") {
    return dns_one::query_udp(query, server, port, bootstrap);
  }
  if (type == "tcp") {
    return dns_one::query_tcp(query, server, port, bootstrap);
  }
  if (type == "tls") {
    return dns_one::query_tls(query, server, port, bootstrap);
  }
  if (type == "https") {
    return dns_one::query_https(
        query, "https://" + server + ":" + std::to_string(port) +
                   config.proxyServerNameserver.path,
        bootstrap);
  }
  throw std::runtime_error("unsupported DNS type: " + type);
}

} // namespace

DnsServer::DnsServer(const DnsConfig &config) : config_(config) {}

std::vector<ip::address> DnsServer::resolve(const DomainName &domain) {
  std::vector<ip::address> output;

  for (const auto type : {dns_one::QueryType::A, dns_one::QueryType::AAAA}) {
    try {
      const auto response = query_dns(config_, domain.value(), type);

      for (const auto &record : dns_one::parse_response(response)) {
        if (record.type != dns_one::QueryType::A &&
            record.type != dns_one::QueryType::AAAA) {
          continue;
        }

        boost::system::error_code ec;
        const auto address = ip::make_address(record.value, ec);
        if (!ec) {
          output.push_back(address);
        }
      }
    } catch (...) {
      if (output.empty() && type == dns_one::QueryType::AAAA) {
        throw;
      }
    }
  }

  if (output.empty()) {
    throw std::runtime_error("DNS returned no address for " + domain.value());
  }
  return output;
}

asio::awaitable<void>
DnsServer::async_tcp_connect(tcp::socket &socket,
                             const Destination &destination) {
  std::vector<tcp::endpoint> endpoints;

  if (destination.host.is_ip()) {
    endpoints.emplace_back(destination.host.asio_address(), destination.port);
  } else {
    for (const auto &address : resolve(destination.host.domain())) {
      endpoints.emplace_back(address, destination.port);
    }
  }

  const auto results = tcp::resolver::results_type::create(
      endpoints.begin(), endpoints.end(), "", "");

  co_await asio::async_connect(socket, results, asio::use_awaitable);
}

} // namespace sbox