#pragma once

#include "config/config.hpp"
#include "core/address.hpp"
#include "dns/dns_message.hpp"
#include <boost/asio.hpp>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace sbox {

class Connector;
class Router;
class DnsServer {
public:
  explicit DnsServer(const DnsConfig &config, Router &router);

  void set_connector(Connector &connector);

  boost::asio::awaitable<std::vector<boost::asio::ip::address>>
  resolve(const DomainName &domain);

  boost::asio::awaitable<Bytes> query(Bytes request);
  std::string pick_nameserver_tag(std::string_view domain) const;

private:
  const DnsItemConfig &pick_nameserver(std::string_view domain) const;
  const DnsItemConfig &find_nameserver(std::string_view tag) const;

  boost::asio::awaitable<Bytes> query_dns(const DnsItemConfig &nameserver,
                                          Bytes message);

  boost::asio::awaitable<Bytes> async_query_udp(const DnsItemConfig &nameserver,
                                                Bytes message);

  boost::asio::awaitable<Bytes> async_query_tcp(const DnsItemConfig &nameserver,
                                                Bytes message);

  boost::asio::awaitable<Bytes> async_query_tls(const DnsItemConfig &nameserver,
                                                Bytes message);

  boost::asio::awaitable<Bytes>
  async_query_https(const DnsItemConfig &nameserver, Bytes message);

  bool match_rule(const DnsRouteRuleConfig &rule,
                  std::string_view domain) const;

  DnsConfig config_;
  Connector *connector_{};
  std::unordered_map<std::string, const DnsItemConfig *> nameservers_;
  Router &router_;
};

} // namespace sbox