#include "common/json_common.hpp"
namespace sbox {

std::string get_string(const json::object &o, const char *key) {
  return std::string(o.at(key).as_string());
}
bool get_bool(const json::object &o, const char *key) {
  return o.at(key).as_bool();
}
std::uint16_t get_u16(const json::object &o, const char *key) {
  auto v = o.at(key).as_int64();
  if (v > UINT16_MAX) {
    throw std::runtime_error("need u16");
  }
  return static_cast<std::uint16_t>(v);
}
std::vector<std::string> get_string_array(const json::object &o,
                                          const char *key, bool force) {
  if (!o.if_contains(key)) {
    return {};
  }
  auto &value = o.at(key);
  if (value.is_string()) {
    return {std::string(value.as_string())};
  }
  if (value.is_array()) {
    std::vector<std::string> out;
    for (const auto &item : value.as_array()) {
      out.emplace_back(item.as_string());
    }
    return out;
  }
  if (force) {
    throw std::runtime_error("need string or string array");
  }
  return {};
}
} // namespace sbox
