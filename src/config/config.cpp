#include "config/config.hpp"
#include "common/json_common.hpp"
#include <boost/json/object.hpp>
#include <boost/json/parse.hpp>
#include <cstdint>
#include <exception>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>


namespace cppbox {

AppConfig load_config(const std::string &path) {
  std::ifstream file(path);
  if (!file) {
    throw std::runtime_error("failed to open config: " + path);
  }
  std::string text((std::istreambuf_iterator<char>(file)), {});
  auto root = json::parse(text).as_object();
  AppConfig config;
  // inbounds
  if (root.contains("inbounds") && root.at("inbounds").is_array()) {
    for (const auto &item : root["inbounds"].as_array()) {
      const auto &obj = item.as_object();
      InboundConfig inbound_config;
      inbound_config.type = get_string(obj, "type");
      inbound_config.tag = get_string(obj, "tag");
      inbound_config.listen = get_string(obj, "listen");
      inbound_config.listen_port = get_u16(obj, "listen_port");
      config.inbounds.push_back(std::move(inbound_config));
    }
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
  // dns
  const auto &dns_obj = root.at("dns").as_object();

  if (auto it = dns_obj.if_contains("listen"); it) {
    if (!it->is_string()) {
      throw std::runtime_error("dns.listen must be a string");
    }
    config.dns.listen = std::string(it->as_string().c_str());
  }

  const auto &servers = dns_obj.at("servers").as_array();
  if (servers.empty()) {
    throw std::runtime_error("dns.servers must not be empty");
  }

  std::unordered_set<std::string> dns_server_tags;

  for (const auto &item : servers) {
    if (!item.is_object()) {
      throw std::runtime_error("dns.servers item must be an object");
    }

    const auto &obj = item.as_object();
    DnsItemConfig server;

    server.tag = get_string(obj, "tag");
    server.type = get_string(obj, "type");
    server.server = get_string(obj, "server");
    server.server_port = get_u16(obj, "server_port");

    if (!dns_server_tags.insert(server.tag).second) {
      throw std::runtime_error("duplicate DNS server tag: " + server.tag);
    }

    if (server.type != "udp" && server.type != "tcp" && server.type != "tls" &&
        server.type != "https") {
      throw std::runtime_error("unsupported DNS server type: " + server.type);
    }

    if (server.type == "https") {
      server.path = get_string(obj, "path");
      if (!server.path.starts_with('/')) {
        throw std::runtime_error("DNS HTTPS path must start with /");
      }
    }

    if (server.type == "tls" || server.type == "https") {
      if (auto it = obj.if_contains("server_name"); it) {
        if (!it->is_string()) {
          throw std::runtime_error("dns server_name must be a string");
        }
        server.server_name = std::string(it->as_string().c_str());
      }
    }

    config.dns.servers.push_back(std::move(server));
  }

  if (auto it = dns_obj.if_contains("rules"); it) {
    if (!it->is_array()) {
      throw std::runtime_error("dns.rules must be an array");
    }

    for (const auto &item : it->as_array()) {
      if (!item.is_object()) {
        throw std::runtime_error("dns.rules item must be an object");
      }

      const auto &obj = item.as_object();
      DnsRouteRuleConfig rule;

      rule.domain = get_string_array(obj, "domain");
      rule.domain_suffix = get_string_array(obj, "domain_suffix");
      rule.domain_keyword = get_string_array(obj, "domain_keyword");
      rule.rule_set = get_string_array(obj, "rule_set");
      rule.server = get_string(obj, "server");

      if (rule.domain.empty() && rule.domain_suffix.empty() &&
          rule.domain_keyword.empty() && rule.rule_set.empty()) {
        throw std::runtime_error("dns rule must contain a match condition");
      }

      if (!dns_server_tags.contains(rule.server)) {
        throw std::runtime_error("dns rule references unknown server: " +
                                 rule.server);
      }

      config.dns.rules.push_back(std::move(rule));
    }
  }

  config.dns.final = get_string(dns_obj, "final");

  if (!dns_server_tags.contains(config.dns.final)) {
    throw std::runtime_error("dns.final references unknown server: " +
                             config.dns.final);
  }

  // override_address
  if (auto it = root.if_contains("override_address"); it && it->is_bool()) {
    config.override_address = it->as_bool();
  }
  if (auto it = root.if_contains("tun"); it && it->is_object()) {
    const auto &tun = it->as_object();
    config.tun.enable = get_bool(tun, "enable");
    if (config.tun.enable) {
      config.tun.tun_ip = get_string(tun, "tun_ip");
      config.tun.tun_next_ip = get_string(tun, "tun_next_ip");
    }
  }
  return config;
}
}; // namespace cppbox