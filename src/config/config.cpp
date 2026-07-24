#include "config/config.hpp"
#include <boost/json/object.hpp>
#include <boost/json/parse.hpp>
#include <cstdint>
#include <exception>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include "common/json_common.hpp"
namespace sbox {

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
    if (outbound.type == "vless") {
      outbound.server = get_string(obj, "server");
      outbound.server_port = get_u16(obj, "server_port");
      // vless uuid
      outbound.uuid = get_string(obj, "uuid");
      // vless tls
      if (auto it = obj.if_contains("tls"); it && it->is_object()) {
        auto &tls_obj = it->as_object();
        TlsConfig tls;
        tls.enabled = get_bool(tls_obj, "enabled");
        if (tls.enabled) {
          tls.server_name = get_string(tls_obj, "server_name");
          tls.insecure = get_bool(tls_obj, "insecure");
        }
        outbound.tls = std::move(tls);
      }
      // vless transport
      if (auto it = obj.if_contains("transport"); it && it->is_object()) {
        const auto &transport_obj = it->as_object();
        // vless transport websocket
        TransportConfig transport;
        transport.type = get_string(transport_obj, "type");
        transport.path = get_string(transport_obj, "path");
        outbound.transport = std::move(transport);
      }
    }
    config.outbounds.push_back(std::move(outbound));
  }
  // route
  const auto &route = root["route"].as_object();
  // route final
  config.route.final_outbound = get_string(route, "final");
  if (auto it = route.if_contains("rule_set"); it && it->is_array()) {
    // route rule_set
    for (const auto &item : it->as_array()) {
      const auto &obj = item.as_object();
      RuleSetConfig rule_set;
      rule_set.type = get_string(obj, "type");
      rule_set.tag = get_string(obj, "tag");
      rule_set.format = get_string(obj, "format");
      rule_set.path = get_string(obj, "path");
      config.route.rule_sets.push_back(std::move(rule_set));
    }
  }
  if (auto it = route.if_contains("rules"); it && it->is_array()) {
    // route rules
    for (const auto &item : it->as_array()) {
      const auto &obj = item.as_object();
      RouteRuleConfig rule;
      rule.domain = get_string_array(obj, "domain");
      rule.domain_suffix = get_string_array(obj, "domain_suffix");
      rule.domain_keyword = get_string_array(obj, "domain_keyword");
      rule.ip_cidr = get_string_array(obj, "ip_cidr");
      rule.rule_set = get_string_array(obj, "rule_set");
      if (rule.domain.empty() && rule.domain_keyword.empty() &&
          rule.domain_suffix.empty() && rule.ip_cidr.empty() &&
          rule.rule_set.empty()) {
        throw std::runtime_error("rule must be not null");
      }
      rule.outbound = get_string(obj, "outbound");
      config.route.rules.push_back(std::move(rule));
    }
  }
  if (auto it = root.if_contains("windows_proxy"); it && it->is_object()) {
    const auto &windows_proxy = it->as_object();
    config.windows_proxy.enabled = get_bool(windows_proxy, "enabled");
    if (config.windows_proxy.enabled) {
      config.windows_proxy.addr = get_string(windows_proxy, "addr");
      config.windows_proxy.port = get_u16(windows_proxy, "port");
    }
  }
  return config;
}
}; // namespace sbox