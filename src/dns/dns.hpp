#pragma once

#include "config/config.hpp"
#include "core/address.hpp"
#include <boost/asio.hpp>
#include <vector>

namespace sbox {

class DnsServer {
public:
  explicit DnsServer(const DnsConfig &config);

  boost::asio::awaitable<std::vector<boost::asio::ip::address>>
  resolve(const DomainName &domain);

private:
  DnsConfig config_;
};

} // namespace sbox