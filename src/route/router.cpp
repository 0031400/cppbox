#include "route/router.hpp"
#include "config/config.hpp"
#include "core/session.hpp"
#include "rule_set.hpp"
#include <boost/asio/ip/address_v4.hpp>
#include <core/log.hpp>
#include <exception>
#include <memory>
#include <stdexcept>
#include <string>

namespace cppbox {
Router::Router(RouteConfig config) : config_(std::move(config)) {
  for (const auto &item : config_.rule_sets) {
    if (item.type != "local") {
      throw std::runtime_error("only local rule_set is supported: " + item.tag);
    }
    if (item.format != "source") {
      throw std::runtime_error("only source rule_set is supported: " +
                               item.tag);
    }

    if (item.path.empty()) {
      throw std::runtime_error("missing rule_set path: " + item.tag);
    }
    rule_sets_[item.tag] =
        std::make_shared<RuleSet>(RuleSet::load_source(item.path));
  }
}
std::string Router::pick_outbound(const Session &session) const {
  for (const auto &rule : config_.rules) {
    if (match_rule(rule, session.destination)) {
      return rule.outbound;
    }
  }
  return config_.final_outbound;
}
bool Router::ends_with(const std::string &text, const std::string &suffix) {
  return text.size() >= suffix.size() &&
         text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
}
bool Router::contains(const std::string &text, const std::string &keyword) {
  return text.find(keyword) != std::string::npos;
}
bool Router::is_ip(const Destination &dst) { return dst.host.is_ip(); }
bool Router::match_domain(const RouteRuleConfig &rule, const Destination &dst) {
  if (!dst.host.is_domain()) {
    return false;
  }

  const auto domain = dst.host.domain().value();

  for (const auto &item : rule.domain) {
    if (domain == item) {
      return true;
    }
  }

  for (const auto &item : rule.domain_suffix) {
    if (item.empty()) {
      continue;
    }
    if (item.front() == '.') {
      if (ends_with(domain, item)) {
        return true;
      }
    } else if (domain == item || ends_with(domain, "." + item)) {
      return true;
    }
  }

  for (const auto &item : rule.domain_keyword) {
    if (contains(domain, item)) {
      return true;
    }
  }
  return false;
}
std::uint32_t Router::ipv4_to_u32(const ip::address_v4 &ip) {
  auto b = ip.to_bytes();
  return (static_cast<std::uint32_t>(b[0]) << 24) |
         (static_cast<std::uint32_t>(b[1]) << 16) |
         (static_cast<std::uint32_t>(b[2]) << 8) |
         (static_cast<std::uint32_t>(b[3]));
}

bool Router::match_ipv4_cidr(const std::string &ip_text,
                             const std::string &cidr) {
  auto slash = cidr.find("/");
  if (slash == std::string::npos) {
    return ip_text == cidr;
  }
  auto base = ip::make_address_v4(cidr.substr(0, slash));
  auto ip = ip::make_address_v4(ip_text);
  int prefix = std::stoi(cidr.substr(slash + 1));
  if (prefix < 0 || prefix > 32) {
    return false;
  }
  std::uint32_t mask = prefix == 0 ? 0 : (0xffffffffu << (32 - prefix));
  return (ipv4_to_u32(base) & mask) == (ipv4_to_u32(ip) & mask);
}
bool Router::match_ipv6_cidr(const std::string &ip_text,
                             const std::string &cidr) {
  auto slash = cidr.find("/");
  if (slash == std::string::npos) {
    return ip_text == cidr;
  }
  auto base = ip::make_address_v6(cidr.substr(0, slash));
  auto ip = ip::make_address_v6(ip_text);
  auto base_bytes = base.to_bytes();
  auto ip_bytes = ip.to_bytes();
  int prefix = std::stoi(cidr.substr(slash + 1));
  if (prefix < 0 || prefix > 128) {
    return false;
  }
  int full_bytes = prefix / 8;
  int rest_bits = prefix % 8;
  for (int i = 0; i < full_bytes; i++) {
    if (base_bytes[i] != ip_bytes[i]) {
      return false;
    }
  }
  if (rest_bits == 0) {
    return true;
  }
  auto mask = static_cast<unsigned char>(0xffu << (8 - rest_bits));
  return (base_bytes[full_bytes] & mask) == (ip_bytes[full_bytes] & mask);
}
bool Router::match_ip_cidr(const RouteRuleConfig &rule,
                           const Destination &dst) {
  if (!is_ip(dst)) {
    return false;
  }
  for (const auto &cidr : rule.ip_cidr) {
    const auto ip_text = dst.host.to_string();

    if (dst.host.type() == HostType::IPv4) {
      if (cidr.find(':') == std::string::npos &&
          match_ipv4_cidr(ip_text, cidr)) {
        return true;
      }
    }

    if (dst.host.type() == HostType::IPv6) {
      if (cidr.find(':') != std::string::npos &&
          match_ipv6_cidr(ip_text, cidr)) {
        return true;
      }
    }
  }
  return false;
}
bool Router::match_rule_set(std::string_view tag,
                            const Destination &destination) const {
  const auto it = rule_sets_.find(std::string(tag));
  return it != rule_sets_.end() && it->second->match(destination);
}
bool Router::match_rule_conditions(const RouteRuleConfig &rule,
                                   const Destination &dst) {
  return match_domain(rule, dst) || match_ip_cidr(rule, dst);
}

bool Router::match_rule(const RouteRuleConfig &rule,
                        const Destination &dst) const {
  if (match_rule_conditions(rule, dst)) {
    return true;
  }
  for (const auto &tag : rule.rule_set) {
    auto it = rule_sets_.find(tag);
    if (it != rule_sets_.end() && it->second->match(dst)) {
      return true;
    }
  }
  return false;
}
}; // namespace cppbox