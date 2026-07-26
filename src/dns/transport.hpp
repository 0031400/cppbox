#pragma once

#include "dns/dns_message.hpp"
#include <boost/asio/awaitable.hpp>
#include <string>
#include <string_view>

namespace sbox {

class Connector;

boost::asio::awaitable<Bytes>
async_query_udp(Connector &connector, Bytes message, const std::string &server,
                int port = 53,
                std::string_view bootstrap_server = "119.29.29.29",
                int bootstrap_port = 53);

boost::asio::awaitable<Bytes>
async_query_tcp(Connector &connector, Bytes message, const std::string &server,
                int port = 53,
                std::string_view bootstrap_server = "119.29.29.29",
                int bootstrap_port = 53);

boost::asio::awaitable<Bytes>
async_query_tls(Connector &connector, Bytes message, const std::string &server,
                int port = 853,
                std::string_view bootstrap_server = "119.29.29.29",
                int bootstrap_port = 53);

boost::asio::awaitable<Bytes>
async_query_https(Connector &connector, Bytes message,
                  const std::string &doh_url,
                  std::string_view bootstrap_server = "119.29.29.29",
                  int bootstrap_port = 53);

} // namespace sbox