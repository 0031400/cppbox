#pragma once

#include "config/config.hpp"
#include "core/address.hpp"
#include "dns/dns_message.hpp"
#include <boost/asio.hpp>
#include <vector>

namespace sbox {

class Connector;

class DnsServer {
public:
  explicit DnsServer(const DnsConfig &config);

  void set_connector(Connector &connector);

  boost::asio::awaitable<std::vector<boost::asio::ip::address>>
  resolve(const DomainName &domain);

  boost::asio::awaitable<Bytes> query(Bytes request);

private:
  DnsConfig config_;
  Connector *connector_{};
};

} // namespace sbox