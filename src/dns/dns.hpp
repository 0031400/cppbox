#pragma once

#include "config/config.hpp"
#include "core/address.hpp"
#include <boost/asio.hpp>
#include <vector>
#include "dns/dns_message.hpp"
namespace sbox {

class DnsServer {
public:
  explicit DnsServer(const DnsConfig &config);

  boost::asio::awaitable<std::vector<boost::asio::ip::address>>
  resolve(const DomainName &domain);
  boost::asio::awaitable<Bytes> query(Bytes request);

private:
  DnsConfig config_;
};

} // namespace sbox