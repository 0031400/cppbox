#include "dns_message.hpp"
#include "core/utils.hpp"
#include <cstdint>
#include <format>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace cppbox {
namespace {

std::string read_name(std::span<const std::uint8_t> data, std::size_t &offset,
                      int depth = 0) {
  if (depth > 16) {
    throw std::runtime_error("dns name compression loop");
  }
  std::string name;
  while (true) {
    if (offset >= data.size()) {
      throw std::runtime_error("truncated dns packet");
    }
    const auto len = data[offset++];
    if (len == 0) {
      break;
    }
    if ((len & 0xc0) == 0xc0) {
      if (offset >= data.size()) {
        throw std::runtime_error("truncated dns compression pointer");
      }
      const auto pointer =
          static_cast<std::size_t>(((len & 0x3f) << 8) | data[offset++]);
      auto pointer_offset = pointer;
      const auto suffix = read_name(data, pointer_offset, depth + 1);
      if (!name.empty() && !suffix.empty()) {
        name += '.';
      }
      name += suffix;
      break;
    }
    if ((len & 0xc0) != 0) {
      throw std::runtime_error("unsupported dns label type");
    }
    if (offset + len > data.size()) {
      throw std::runtime_error("truncated dns label");
    }
    if (!name.empty()) {
      name += '.';
    }
    name.append(reinterpret_cast<const char *>(data.data() + offset), len);
    offset += len;
  }
  return name;
}
void skip_question(std::span<const std::uint8_t> data, std::size_t &offset) {
  static_cast<void>(read_name(data, offset));
  if (offset + 4 > data.size()) {
    throw std::runtime_error("truncated dns question");
  }
  offset += 4;
}
std::string ipv4_text(std::span<const std::uint8_t> rdata) {
  if (rdata.size() != 4) {
    throw std::runtime_error("invalid A record length");
  }
  return std::format("{}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3]);
}
std::string ipv6_text(std::span<const std::uint8_t> rdata) {
  if (rdata.size() != 16) {
    throw std::runtime_error("invalid AAAA record length");
  }
  std::string result;
  for (std::size_t i = 0; i < 16; i += 2) {
    if (i != 0) {
      result += ':';
    }
    const auto part =
        static_cast<std::uint16_t>((rdata[i] << 8) | rdata[i + 1]);
    result += std::format("{:x}", part);
  }
  return result;
}
} // namespace
QueryType parse_query_type(std::string_view text) {
  if (text == "a" || text == "A") {
    return QueryType::A;
  }
  if (text == "aaaa" || text == "AAAA") {
    return QueryType::AAAA;
  }
  if (text == "cname" || text == "CNAME") {
    return QueryType::CNAME;
  }
  throw std::runtime_error("query type must be A, AAAA, or CNAME");
}
std::string query_type_name(QueryType type) {
  switch (type) {
  case QueryType::A:
    return "A";
  case QueryType::AAAA:
    return "AAAA";
  case QueryType::CNAME:
    return "CNAME";
  }

  return std::to_string(static_cast<std::uint16_t>(type));
}

DnsQuestion parse_question(std::span<const std::uint8_t> packet) {
  if (packet.size() < 12) {
    throw std::runtime_error("dns request too short");
  }

  const auto qdcount = read_be16(packet, 4);
  if (qdcount == 0) {
    throw std::runtime_error("dns request has no question");
  }

  std::size_t offset = 12;
  auto name = read_name(packet, offset);

  if (offset + 4 > packet.size()) {
    throw std::runtime_error("truncated dns question");
  }

  const auto type_raw = read_be16(packet, offset);
  return DnsQuestion{
      .name = std::move(name),
      .type = static_cast<QueryType>(type_raw),
  };
}
Bytes build_query(std::string_view domain, QueryType type) {
  Bytes packet;
  write_be16(packet, 0x1234);
  write_be16(packet, 0x0100);
  write_be16(packet, 1);
  write_be16(packet, 0);
  write_be16(packet, 0);
  write_be16(packet, 0);
  std::size_t start = 0;
  while (start < domain.size()) {
    const auto dot = domain.find('.', start);
    const auto end = dot == std::string_view::npos ? domain.size() : dot;
    const auto len = end - start;
    if (len == 0 || len > 63) {
      throw std::runtime_error("invalid domain label");
    }
    packet.push_back(static_cast<std::uint8_t>(len));
    packet.insert(packet.end(),
                  domain.begin() + static_cast<std::ptrdiff_t>(start),
                  domain.begin() + static_cast<std::ptrdiff_t>(end));
    if (dot == std::string_view::npos) {
      break;
    }
    start = dot + 1;
  }
  packet.push_back(0);
  write_be16(packet, static_cast<uint16_t>(type));
  write_be16(packet, 1);
  return packet;
}
std::vector<DnsRecord> parse_response(std::span<const std::uint8_t> packet) {
  if (packet.size() < 12) {
    throw std::runtime_error("dns response too short");
  }
  const auto qdcount = read_be16(packet, 4);
  const auto ancount = read_be16(packet, 6);
  std::size_t offset = 12;
  for (std::uint16_t i = 0; i < qdcount; ++i) {
    skip_question(packet, offset);
  }
  std::vector<DnsRecord> records;
  for (std::uint16_t i = 0; i < ancount; ++i) {
    auto name = read_name(packet, offset);
    const auto type_raw = read_be16(packet, offset);
    const auto klass = read_be16(packet, offset + 2);
    const auto ttl = read_be32(packet, offset + 4);
    const auto rdlength = read_be16(packet, offset + 8);
    offset += 10;
    if (offset + rdlength > packet.size()) {
      throw std::runtime_error("truncated dns rdata");
    }
    const auto rdata = packet.subspan(offset, rdlength);
    if (klass == 1 && type_raw == static_cast<std::uint16_t>(QueryType::A)) {
      records.push_back({std::move(name), QueryType::A, ipv4_text(rdata), ttl});
    } else if (klass == 1 &&
               type_raw == static_cast<std::uint16_t>(QueryType::AAAA)) {
      records.push_back(
          {std::move(name), QueryType::AAAA, ipv6_text(rdata), ttl});
    } else if (klass == 1 &&
               type_raw == static_cast<std::uint16_t>(QueryType::CNAME)) {
      auto cname_offset = offset;
      records.push_back({std::move(name), QueryType::CNAME,
                         read_name(packet, cname_offset), ttl});
    }
    offset += rdlength;
  }
  return records;
}
}; // namespace cppbox