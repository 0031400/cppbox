#pragma once
#include <boost/json.hpp>
#include <boost/json/object.hpp>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
namespace sbox {
namespace json = boost::json;
struct InboundConfig {
  std::string type;
  std::string tag;
  std::string listen = "127.0.0.1";
  std::uint16_t listen_port = 1080;
};
struct TlsConfig {
  bool enabled = false;
  std::string server_name;
  bool insecure = false;
};
struct TransportConfig {
  std::string type;
  std::string path;
};
struct OutboundConfig {
  std::string type;
  std::string tag;
  std::string server;
  std::uint16_t server_port = 0;
  std::string uuid;
  std::optional<TlsConfig> tls;
  std::optional<TransportConfig> transport;
};
struct RouteRuleConfig {
  std::vector<std::string> domain;
  std::vector<std::string> domain_suffix;
  std::vector<std::string> domain_keyword;
  std::vector<std::string> ip_cidr;
  std::vector<std::string> rule_set;
  std::string action;
  std::string outbound;
};
struct RuleSetConfig {
  std::string type;
  std::string tag;
  std::string format;
  std::string path;
};
struct RouteConfig {
  std::vector<RouteRuleConfig> rules;
  std::string final_outbound;
  std::vector<RuleSetConfig> rule_sets;
};
struct WindowsProxyConfig {
  bool enabled = false;
  std::string addr = "127.0.0.1";
  std::uint16_t port = 1080;
};
struct AppConfig {
  std::vector<InboundConfig> inbounds;
  std::vector<OutboundConfig> outbounds;
  RouteConfig route;
  WindowsProxyConfig windows_proxy;
};
AppConfig load_config(const std::string &path);
}; // namespace sbox