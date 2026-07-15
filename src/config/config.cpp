#include "config/config.hpp"
#include <boost/json/object.hpp>
#include <boost/json/parse.hpp>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <utility>
#include <vector>
namespace sbox {
const json::object &as_object(const json::value &v, const char *name) {
  if (!v.is_object()) {
    throw std::runtime_error(std::string(name) + "must be object");
  }
  return v.as_object();
}
std::string get_string(const json::object &o, const char *key,
                       std::string def) {
  auto it = o.find(key);
  if (it == o.end()) {
    return def;
  }
  return std::string(it->value().as_string());
}
bool get_bool(const json::object &o, const char *key, bool def) {
  auto it = o.find(key);
  if (it == o.end()) {
    return def;
  }
  return it->value().as_bool();
}
std::uint16_t get_u16(const json::object &o, const char *key,
                      std::uint16_t def) {
  auto it = o.find(key);
  if (it == o.end()) {
    return def;
  }
  return static_cast<std::uint16_t>(it->value().as_int64());
}
std::vector<std::string> get_string_array(const json::object &o,
                                          const char *key) {
  std::vector<std::string> out;
  auto it = o.find(key);
  if (it == o.end()) {
    return out;
  }
  if (it->value().is_string()) {
    out.emplace_back(it->value().as_string());
    return out;
  }
  for (const auto &item : it->value().as_array()) {
    out.emplace_back(item.as_string());
  }
  return out;
}
AppConfig load_config(const std::string &path) {
  std::ifstream file(path);
  if (!file) {
    throw std::runtime_error("failed to open config: " + path);
  }
  std::string text((std::istreambuf_iterator<char>(file)), {});
  auto root = json::parse(text).as_object();
  AppConfig config;
  for (const auto &item : root["inbounds"].as_array()) {
    const auto &o = item.as_object();
    config.inbounds.push_back({.type = get_string(o, "type"),
                               .tag = get_string(o, "tag"),
                               .listen = get_string(o, "listen", "127.0.0.1"),
                               .listen_port = get_u16(o, "listen_port", 1080)});
  }
  for (auto &item : root["outbounds"].as_array()) {
    const auto &o = item.as_object();
    OutboundConfig outbound;
    outbound.type = get_string(o, "type");
    outbound.tag = get_string(o, "tag");
    outbound.server = get_string(o, "server");
    outbound.server_port = get_u16(o, "server_port");
    outbound.uuid = get_string(o, "uuid");
    if (auto it = o.find("tls"); it != o.end()) {
      const auto &tls = it->value().as_object();
      outbound.tls.enabled = get_bool(tls, "enabled");
      outbound.tls.server_name = get_string(tls, "server_name");
      outbound.tls.insecure = get_bool(tls, "insecure");
    }
    if (auto it = o.find("transport"); it != o.end()) {
      const auto &transport = it->value().as_object();
      if (get_string(transport, "type") == "ws") {
        outbound.ws.enabled = true;
        outbound.ws.path = get_string(transport, "path", "/");
        if (auto hit = transport.find("headers"); hit != transport.end()) {
          outbound.ws.host = get_string(hit->value().as_object(), "Host");
        }
      }
    }
    config.outbounds.push_back(std::move(outbound));
  }
  const auto &route = root["route"].as_object();
  config.route.final_outbound = get_string(route, "final");
  if (auto it = route.find("rule_set"); it != route.end()) {
    for (const auto &item : it->value().as_array()) {
      const auto &o = item.as_object();
      RuleSetConfig rule_set;
      rule_set.type = get_string(o, "type");
      rule_set.tag = get_string(o, "tag");
      rule_set.format = get_string(o, "format");
      rule_set.path = get_string(o, "path");
      if (rule_set.type != "local") {
        throw std::runtime_error("only local rule_set is supported: " +
                                 rule_set.tag);
      }

      if (rule_set.format != "source") {
        throw std::runtime_error("only source rule_set is supported: " +
                                 rule_set.tag);
      }
      if (rule_set.path.empty()) {
        throw std::runtime_error("missing rule_set path: " + rule_set.tag);
      }
      config.route.rule_sets.push_back(std::move(rule_set));
    }
  }
  if (auto it = route.find("rules"); it != route.end()) {
    for (const auto &item : it->value().as_array()) {
      const auto &o = item.as_object();
      RouteRuleConfig rule;
      rule.domain = get_string_array(o, "domain");
      rule.domain_suffix = get_string_array(o, "domain_suffix");
      rule.domain_keyword = get_string_array(o, "domain_keyword");
      rule.ip_cidr = get_string_array(o, "ip_cidr");
      rule.rule_set = get_string_array(o, "rule_set");
      rule.outbound = get_string(o, "outbound");
      config.route.rules.push_back(std::move(rule));
    }
  }
  return config;
}
}; // namespace sbox