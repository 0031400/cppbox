#include "config/config.hpp"
#include <boost/json/object.hpp>
#include <boost/json/parse.hpp>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <utility>
#include <vector>
namespace sbox {
namespace {

std::string get_string(const json::object &o, const char *key,
                       std::string def = {}) {
  auto it = o.find(key);
  if (it == o.end()) {
    return def;
  }
  return std::string(it->value().as_string());
}
bool get_bool(const json::object &o, const char *key, bool def = false) {
  auto it = o.find(key);
  if (it == o.end()) {
    return def;
  }
  return it->value().as_bool();
}
std::uint16_t get_u16(const json::object &o, const char *key,
                      std::uint16_t def = 0) {
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
}; // namespace

AppConfig load_config(const std::string &path) {
  std::ifstream file(path);
  if (!file) {
    throw std::runtime_error("failed to open config: " + path);
  }
  std::string text((std::istreambuf_iterator<char>(file)), {});
  auto root = json::parse(text).as_object();
  AppConfig config;
  // inbounds
  for (const auto &item : root["inbounds"].as_array()) {
    const auto &obj = item.as_object();
    InboundConfig inbound_config;
    inbound_config.type = get_string(obj, "type");
    inbound_config.tag = get_string(obj, "tag");
    inbound_config.listen = get_string(obj, "listen");
    inbound_config.listen_port = get_u16(obj, "listen_port");
    config.inbounds.push_back(std::move(inbound_config));
  }
  // outbounds
  for (auto &item : root["outbounds"].as_array()) {
    const auto &obj = item.as_object();
    OutboundConfig outbound;
    outbound.type = get_string(obj, "type");
    outbound.tag = get_string(obj, "tag");
    outbound.server = get_string(obj, "server");
    outbound.server_port = get_u16(obj, "server_port");
    if (outbound.type == "vless") {
      // vless uuid
      outbound.uuid = get_string(obj, "uuid");
      // vless tls
      if (auto it = obj.find("tls"); it != obj.end()) {
        const auto &tls_obj = it->value().as_object();

        TlsConfig tls;
        tls.enabled = get_bool(tls_obj, "enabled");
        tls.server_name = get_string(tls_obj, "server_name");
        tls.insecure = get_bool(tls_obj, "insecure");

        outbound.tls = std::move(tls);
      }
      // vless transport
      if (auto it = obj.find("transport"); it != obj.end()) {
        const auto &transport_obj = it->value().as_object();
        // vless transport websocket
        TransportConfig transport;
        transport.type = get_string(transport_obj, "type");
        transport.path = get_string(transport_obj, "path", "/");
        outbound.transport = std::move(transport);
      }
    }
    config.outbounds.push_back(std::move(outbound));
  }
  // route
  const auto &route = root["route"].as_object();
  // route final
  config.route.final_outbound = get_string(route, "final");
  if (auto it = route.find("rule_set"); it != route.end()) {
    // route rule_set
    for (const auto &item : it->value().as_array()) {
      const auto &obj = item.as_object();
      RuleSetConfig rule_set;
      rule_set.type = get_string(obj, "type");
      rule_set.tag = get_string(obj, "tag");
      rule_set.format = get_string(obj, "format");
      rule_set.path = get_string(obj, "path");
      config.route.rule_sets.push_back(std::move(rule_set));
    }
  }
  if (auto it = route.find("rules"); it != route.end()) {
    // route rules
    for (const auto &item : it->value().as_array()) {
      const auto &obj = item.as_object();
      RouteRuleConfig rule;
      rule.domain = get_string_array(obj, "domain");
      rule.domain_suffix = get_string_array(obj, "domain_suffix");
      rule.domain_keyword = get_string_array(obj, "domain_keyword");
      rule.ip_cidr = get_string_array(obj, "ip_cidr");
      rule.rule_set = get_string_array(obj, "rule_set");
      rule.outbound = get_string(obj, "outbound");
      config.route.rules.push_back(std::move(rule));
    }
  }
  if (auto it = root.find("windows_proxy"); it != root.end()) {
    const auto &windows_proxy = it->value().as_object();
    config.windows_proxy.enabled = get_bool(windows_proxy, "enabled");
    config.windows_proxy.addr = get_string(windows_proxy, "addr");
    config.windows_proxy.port = get_u16(windows_proxy, "port");
  }
  return config;
}
}; // namespace sbox