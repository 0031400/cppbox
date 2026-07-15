#pragma once
#include "config/config.hpp"
#include "core/session.hpp"
#include <vector>
namespace sbox {
class RuleSet {
public:
  static RuleSet load_source(const std::string &path);
  bool match(const Destination &dst) const;

private:
  std::vector<RouteRuleConfig> rules_;
};
}; // namespace sbox