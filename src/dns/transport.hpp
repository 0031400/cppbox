#pragma once
#include "dns_message.hpp"
#include <span>
#include <string_view>
namespace dns_one {
enum class Protocol { Udp, Tcp, Tls, Https };
Protocol parse_protocol(std::string_view text);
Bytes query_udp(std::span<const std::uint8_t> message,
                const std::string &server, int port = 53,
                std::string_view bootstrap_server = "119.29.29.29");
Bytes query_tcp(std::span<const std::uint8_t> message,
                const std::string &server, int port = 53,
                std::string_view bootstrap_server = "119.29.29.29");
Bytes query_tls(std::span<const std::uint8_t> message,
                const std::string &server, int port = 853,
                std::string_view bootstrap_server = "119.29.29.29");
Bytes query_https(std::span<const std::uint8_t> message,
                  const std::string &doh_url,
                  std::string_view bootstrap_server = "119.29.29.29");
}; // namespace dns_one