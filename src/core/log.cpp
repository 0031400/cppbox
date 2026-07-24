#include <iostream>
#include <source_location>
#include <string_view>
namespace sbox {
void log_error(std::string_view messsage, const std::source_location location =
                                              std::source_location::current()) {
  std::cerr << "[error] " << location.file_name() << ":" << location.line()
            << " " << location.function_name() << " - " << messsage
            << std::endl;
}
void log_info(std::string_view messsage, const std::source_location location =
                                             std::source_location::current()) {
  std::cout << "[info] " << messsage << std::endl;
}
} // namespace sbox