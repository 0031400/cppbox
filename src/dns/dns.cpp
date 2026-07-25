#include "dns/dns.hpp"
#include "dns/dns_message.hpp"
#include "dns/transport.hpp"
#include <boost/asio/use_awaitable.hpp>
#include <stdexcept>

namespace sbox {
namespace asio = boost::asio;
namespace ip = asio::ip;

namespace {

asio::awaitable<dns_one::Bytes>
query_dns(const DnsConfig &config, const std::string &name,
          dns_one::QueryType query_type) {
  const auto &server = config.proxyServerNameserver.server;
  const auto &type = config.proxyServerNameserver.type;
  const auto port = config.proxyServerNameserver.server_port;
  const auto &bootstrap = config.defaultNameserver.server;
  const auto bootstrap_port = config.defaultNameserver.server_port;
  auto query = dns_one::build_query(name, query_type);

  if (type == "udp") {
    co_return co_await dns_one::async_query_udp(
        std::move(query), server, port, bootstrap, bootstrap_port);
  }
  if (type == "tcp") {
    co_return co_await dns_one::async_query_tcp(
        std::move(query), server, port, bootstrap, bootstrap_port);
  }
  if (type == "tls") {
    co_return co_await dns_one::async_query_tls(
        std::move(query), server, port, bootstrap, bootstrap_port);
  }
  if (type == "https") {
    co_return co_await dns_one::async_query_https(
        std::move(query),
        "https://" + server + ":" + std::to_string(port) +
            config.proxyServerNameserver.path,
        bootstrap, bootstrap_port);
  }

  throw std::runtime_error("unsupported DNS type: " + type);
}

} // namespace

DnsServer::DnsServer(const DnsConfig &config) : config_(config) {}

asio::awaitable<std::vector<ip::address>>
DnsServer::resolve(const DomainName &domain) {
  std::vector<ip::address> output;
  std::exception_ptr last_error;

  for (const auto type : {dns_one::QueryType::A, dns_one::QueryType::AAAA}) {
    try {
      const auto response = co_await query_dns(config_, domain.value(), type);

      for (const auto &record : dns_one::parse_response(response)) {
        if (record.type != dns_one::QueryType::A &&
            record.type != dns_one::QueryType::AAAA) {
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