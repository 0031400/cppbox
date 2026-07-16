#include <iostream>
#include <source_location>
#include <string_view>
namespace sbox {
void log_(
    std::string_view title, std::string_view messsage, std::ostream &os,
    bool show_location = false,
    const std::source_location location = std::source_location::current()) {
  if (show_location) {
    os << "[" << title << "] " << location.file_name() << ":" << location.line()
       << " " << location.function_name() << " - " << messsage << std::endl;
  } else {
    os << "[" << title << "] " << messsage << std::endl;
  }
}
void log_error(std::string_view messsage, const std::source_location location =
                                              std::source_location::current()) {
  log_("error", messsage, std::cerr, true, location);
}
void log_info(std::string_view messsage, const std::source_location location =
                                             std::source_location::current()) {
  log_("info", messsage, std::cout, false);
}
} // namespace sbox