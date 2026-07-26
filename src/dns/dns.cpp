#include "dns/dns.hpp"

#include "dns/transport.hpp"
#include "transport/connector.hpp"
#include <boost/asio/use_awaitable.hpp>
#include <stdexcept>

namespace sbox {
namespace ip = asio::ip;

namespace {

bool is_ip_literal(const std::string &host) {
  boost::system::error_code ec;
  asio::ip::make_address(host, ec);
  return !ec;
}

asio::awaitable<Bytes> query_dns(Connector &connector, const DnsConfig &config,
                                 Bytes request) {
  const auto &server = config.proxyServerNameserver.server;
  const auto &type = config.proxyServerNameserver.type;
  const auto port = config.proxyServerNameserver.server_port;
  const auto &bootstrap = config.defaultNameserver.server;
  const auto bootstrap_port = config.defaultNameserver.server_port;

  if (type == "udp") {
    co_return co_await async_query_udp(connector, std::move(request), server,
                                       port, bootstrap, bootstrap_port);
  }

  if (type == "tcp") {
    co_return co_await async_query_tcp(connector, std::move(request), server,
                                       port, bootstrap, bootstrap_port);
  }

  if (type == "tls") {
    co_return co_await async_query_tls(connector, std::move(request), server,
                                       port, bootstrap, bootstrap_port);
  }

  if (type == "https") {
    co_return co_await async_query_https(
        connector, std::move(request),
        "https://" + server + ":" + std::to_string(port) +
            config.proxyServerNameserver.path,
        bootstrap, bootstrap_port);
  }

  throw std::runtime_error("unsupported DNS type: " + type);
}

} // namespace

DnsServer::DnsServer(const DnsConfig &config) : config_(config) {
  if (!is_ip_literal(config_.defaultNameserver.server)) {
    throw std::runtime_error("default DNS server must be an IP address");
  }
}

void DnsServer::set_connector(Connector &connector) { connector_ = &connector; }

asio::awaitable<Bytes> DnsServer::query(Bytes request) {
  if (!connector_) {
    throw std::runtime_error("DNS connector is not configured");
  }

  co_return co_await query_dns(*connector_, config_, std::move(request));
}

asio::awaitable<std::vector<ip::address>>
DnsServer::resolve(const DomainName &domain) {
  std::vector<ip::address> output;
  std::exception_ptr last_error;

  for (const auto type : {QueryType::A, QueryType::AAAA}) {
    try {
      const auto response = co_await query(build_query(domain.value(), type));

      for (const auto &record : parse_response(response)) {
        if (record.type != QueryType::A && record.type != QueryType::AAAA) {
          continue;
        }

        boost::system::error_code ec;
        auto address = ip::make_address(record.value, ec);
        if (!ec) {
          output.push_back(address);
        }
      }
    } catch (...) {
      last_error = std::current_exception();
    }
  }

  if (!output.empty()) {
    co_return output;
  }

  if (last_error) {
    std::rethrow_exception(last_error);
  }

  throw std::runtime_error("DNS returned no address for " + domain.value());
}

} // namespace sbox