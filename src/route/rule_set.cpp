#include "route/rule_set.hpp"
#include "config/config.hpp"
#include "route/router.hpp"
#include <boost/json/parse.hpp>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <utility>
namespace sbox {
RuleSet RuleSet::load_source(const std::string &path) {
  std::ifstream file(path);
  if (!file) {
    throw std::runtime_error("failed to open rule_set: " + path);
  }
  std::string text((std::istreambuf_iterator<char>(file)), {});
  auto root = boost::json::parse(text).as_object();
  RuleSet set;
  auto it = root.find("rules");
  if (it == root.end()) {
    return set;
  }
  for (const auto &item : it->value().as_array()) {
    const auto &o = item.as_object();
    RouteRuleConfig rule;
    rule.domain = get_string_array(o, "domain");
    rule.domain_suffix = get_string_array(o, "domain_suffix");
    rule.domain_keyword = get_string_array(o, "domain_keyword");
    rule.ip_cidr = get_string_array(o, "ip_cidr");
    rule.outbound = get_string(o, "outbound");
    set.rules_.push_back(std::move(rule));
  }
  return set;
}
bool RuleSet::match(const Destination &dst) const {
  for (const auto &rule : rules_) {
    if (Router::match_rule_conditions(rule, dst)) {
      return true;
    }
  }
  return false;
}
}; // namespace sbox