#pragma once
#include <boost/json.hpp>
namespace sbox {
namespace json = boost::json;
std::string get_string(const json::object &o, const char *key);
bool get_bool(const json::object &o, const char *key);
std::uint16_t get_u16(const json::object &o, const char *key);
std::vector<std::string> get_string_array(const json::object &o,
                                          const char *key, bool force = false);
} // namespace sbox