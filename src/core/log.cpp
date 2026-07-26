#include <boost/stacktrace.hpp>
#include <iostream>
#include <source_location>
#include <string>
#include <string_view>

namespace sbox {
void log_error(std::string_view messsage, const std::source_location location =
                                              std::source_location::current()) {
  std::cerr << "[error] " << location.file_name() << ":" << location.line()
            << " " << location.function_name() << " - " << messsage
            << std::endl;

  for (const auto &frame : boost::stacktrace::stacktrace()) {
    const auto source_file = frame.source_file();
    if (!source_file.contains("sbox")) {
      continue;
    }
    std::cerr << "  at " << source_file << ":" << frame.source_line() << " "
              << frame.name() << '\n';
  }
}
void log_info(std::string_view messsage, const std::source_location location =
                                             std::source_location::current()) {
  std::cout << "[info] " << messsage << std::endl;
}
} // namespace sbox