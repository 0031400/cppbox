#include "route/rule_set.hpp"
#include "common/json_common.hpp"
#include "config/config.hpp"
#include "route/router.hpp"
#include <boost/json/parse.hpp>
#include <fstream>
#include <iostream>
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
  if (auto it = root.if_contains("rules"); it && it->is_array()) {
    for (const auto &item : it->as_array()) {
      const auto &obj = item.as_object();
      RouteRuleConfig rule;
      rule.domain = get_string_array(obj, "domain");
      rule.domain_suffix = get_string_array(obj, "domain_suffix");
      rule.domain_keyword = get_string_array(obj, "domain_keyword");
      rule.ip_cidr = get_string_array(obj, "ip_cidr");
      if (rule.domain.empty() && rule.domain_keyword.empty() &&
          rule.domain_suffix.empty() && rule.ip_cidr.empty() &&
          rule.rule_set.empty()) {
        throw std::runtime_error("rule must be not null");
      }
      set.rules_.push_back(std::move(rule));
    }
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