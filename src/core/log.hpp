#pragma once
#include <iostream>
#include <source_location>
namespace sbox {
inline void log_error(
    std::string_view messsage,
    const std::source_location location = std::source_location::current()) {
  std::cerr << "[error] " << location.file_name() << ":" << location.line()
            << " " << location.function_name() << " - " << messsage
            << std::endl;
}
inline void log_info(
    std::string_view messsage,
    const std::source_location location = std::source_location::current()) {
  std::cerr << "[info] " << location.file_name() << ":" << location.line()
            << " " << location.function_name() << " - " << messsage
            << std::endl;
}
}; // namespace sbox