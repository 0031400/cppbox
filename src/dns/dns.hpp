#pragma once

#include "config/config.hpp"
#include <boost/asio.hpp>
#include <string>
#include <vector>

namespace sbox {
class DnsServer {
public:
  explicit DnsServer(DnsConfig &config_);
  std::vector<std::string> resolve(std::string &name);
  boost::asio::awaitable<void>
  async_tcp_connect(boost::asio::ip::tcp::socket &socket, std::string &name,
                    std::uint16_t port);

private:
  DnsConfig config;
};
bool isV4(std::string);
bool isV6(std::string);
} // namespace sbox