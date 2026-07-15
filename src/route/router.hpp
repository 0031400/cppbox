#pragma once
#include "config/config.hpp"
#include "core/session.hpp"
#include "rule_set.hpp"
#include <boost/asio/ip/address.hpp>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
namespace sbox {

class Router {
public:
  explicit Router(RouteConfig config);
  std::string pick_outbound(const Session &session) const;
  static bool match_rule_conditions(const RouteRuleConfig &rule,
                                    const Destination &dst);

private:
  static bool ends_with(const std::string &text, const std::string &suffix);
  static bool contians(const std::string &text, const std::string &keyword);
  static bool is_ip(const Destination &dst);
  static bool match_domain(const RouteRuleConfig &rule, const Destination &dst);
  static std::uint32_t ipv4_to_u32(const boost::asio::ip::address_v4 &ip);
  static bool match_ipv4_cidr(const std::string &ip_text,
                              const std::string &cidr);
  static bool match_ip_cidr(const RouteRuleConfig &rule,
                            const Destination &dst);
  bool match_rule(const RouteRuleConfig &rule, const Destination &dst) const;
  RouteConfig config_;
  std::unordered_map<std::string, std::shared_ptr<RuleSet>> rule_sets_;
};
}; // namespace sbox