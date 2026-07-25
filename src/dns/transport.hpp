#pragma once

#include "dns_message.hpp"
#include <boost/asio/awaitable.hpp>
#include <string>
#include <string_view>

namespace dns_one {

boost::asio::awaitable<Bytes>
async_query_udp(Bytes message, const std::string &server, int port = 53,
                std::string_view bootstrap_server = "119.29.29.29",
                int bootstrap_port = 53);

boost::asio::awaitable<Bytes>
async_query_tcp(Bytes message, const std::string &server, int port = 53,
                std::string_view bootstrap_server = "119.29.29.29",
                int bootstrap_port = 53);

boost::asio::awaitable<Bytes>
async_query_tls(Bytes message, const std::string &server, int port = 853,
                std::string_view bootstrap_server = "119.29.29.29",
                int bootstrap_port = 53);

boost::asio::awaitable<Bytes>
async_query_https(Bytes message, const std::string &doh_url,
                  std::string_view bootstrap_server = "119.29.29.29",
                  int bootstrap_port = 53);

} // namespace dns_one