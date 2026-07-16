#include <source_location>
#include <string_view>
#pragma once
namespace sbox {

void log_error(std::string_view messsage, const std::source_location location =
                                              std::source_location::current());

void log_info(std::string_view messsage, const std::source_location location =
                                             std::source_location::current());
}; // namespace sbox