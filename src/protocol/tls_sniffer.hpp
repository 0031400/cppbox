#pragma once

#include <optional>
#include <span>
#include <string>

namespace cppbox {

std::optional<std::string> sniff_tls_sni(std::span<const unsigned char> data);

} // namespace cppbox