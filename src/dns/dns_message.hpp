#pragma once
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace dns_one {
using Bytes = std::vector<std::uint8_t>;
enum class QueryType : std::uint16_t {
  A = 1,
  CNAME = 5,
  AAAA = 28,
};
struct DnsRecord {
  std::string name;
  QueryType type{};
  std::string value;
  std::uint32_t ttl{};
};
QueryType parse_query_type(std::string_view text);
Bytes build_query(std::string_view domain, QueryType type);
std::vector<DnsRecord> parse_response(std::span<const std::uint8_t> packet);
}; // namespace dns_one