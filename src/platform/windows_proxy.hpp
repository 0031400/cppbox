#pragma once

#include <string>
namespace cppbox {
bool setWindowsProxy(const std::string &host, uint16_t port);
bool unsetWindowsProxy();
}; // namespace cppbox