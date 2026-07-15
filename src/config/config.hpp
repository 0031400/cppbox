#pragma once
#include <boost/json.hpp>
#include <boost/json/object.hpp>
#include <cstdint>
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
struct WsTransportConfig {
  bool enabled = false;
  std::string path = "/";
  std::string host;
};
struct OutboundConfig {
  std::string type;
  std::string tag;
  std::string server;
  std::uint16_t server_port = 0;
  std::string uuid;
  TlsConfig tls;
  WsTransportConfig ws;
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
struct AppConfig {
  std::vector<InboundConfig> inbounds;
  std::vector<OutboundConfig> outbounds;
  RouteConfig route;
};
const json::object &as_object(const json::value &v, const char *name);
std::string get_string(const json::object &o, const char *key,
                       std::string def = {});
bool get_bool(const json::object &o, const char *key, bool def = false);
std::uint16_t get_u16(const json::object &o, const char *key,
                      std::uint16_t def = 0);
std::vector<std::string> get_string_array(const json::object &o,
                                          const char *key);
AppConfig load_config(const std::string &path);
}; // namespace sbox