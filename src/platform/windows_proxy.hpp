#pragma once

#include <string>
namespace sbox {
bool setWindowsProxy(const std::string &host, uint16_t port);
bool unsetWindowsProxy();
}; // namespace sbox