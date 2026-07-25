#pragma once

#include "config/config.hpp"
#include "core/address.hpp"
#include <boost/asio.hpp>
#include <string>
#include <vector>


namespace sbox {
class DnsServer {
public:
  explicit DnsServer(const DnsConfig &config);

  std::vector<boost::asio::ip::address> resolve(const DomainName &domain);

  boost::asio::awaitable<void>
  async_tcp_connect(boost::asio::ip::tcp::socket &socket,
                    const Destination &destination);

private:
  DnsConfig config_;
};
} // namespace sbox