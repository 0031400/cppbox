#include "dns/dns.hpp"
#include "dns/dns_message.hpp"
#include "dns/transport.hpp"
#include "dns_message.hpp"
#include "transport.hpp"
#include <boost/asio/ip/address_v6.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace asio = boost::asio;
namespace ip = asio::ip;
using tcp = ip::tcp;

namespace sbox {
DnsServer::DnsServer(DnsConfig &config_) : config(config_) {}
std::vector<std::string> DnsServer::resolve(std::string &name) {
  auto &server = config.proxyServerNameserver.server;
  auto &type = config.proxyServerNameserver.type;
  auto port = config.proxyServerNameserver.server_port;
  auto &bootstrap_server = config.defaultNameserver.server;
  dns_one::Bytes res;
  const auto query = dns_one::build_query(name, dns_one::QueryType::A);
  if (type == "udp") {
    res = dns_one::query_udp(query, server, port, bootstrap_server);
  } else if (type == "tcp") {
    res = dns_one::query_tcp(query, server, port, bootstrap_server);
  } else if (type == "tls") {
    res = dns_one::query_tls(query, server, port, bootstrap_server);
  } else if (type == "https") {
    res =
        dns_one::query_https(query,
                             "https://" + server + ":" + std::to_string(port) +
                                 config.proxyServerNameserver.path,
                             bootstrap_server);
  } else {
    throw std::runtime_error("unsupport dns type");
  }
  auto records = dns_one::parse_response(res);
  std::vector<std::string> output;
  for (auto &record : records) {
    output.push_back(record.value);
  }
  return output;
}
boost::asio::awaitable<void>
DnsServer::async_tcp_connect(boost::asio::ip::tcp::socket &socket, std::string &name,
                  std::uint16_t port) {
  boost::system::error_code ec;
  auto addr = ip::make_address(name, ec);
  tcp::resolver::results_type result;
  if (!ec) {
    result =
        tcp::resolver::results_type::create(tcp::endpoint(addr, port), "", "");
  } else {
    auto ips = resolve(name);
    std::vector<tcp::endpoint> endpoints;
    for (const auto &ip : ips) {
      endpoints.emplace_back(ip::make_address(ip), port);
    }
    result = tcp::resolver::results_type::create(endpoints.begin(),
                                                 endpoints.end(), "", "");
  }
  co_await asio::async_connect(socket, result, asio::use_awaitable);
  co_return;
}
} // namespace sbox