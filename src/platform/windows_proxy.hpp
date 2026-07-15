#pragma once

#include <string>
namespace sbox {
bool setWindowsProxy(const std::wstring &host, int port);
bool unsetWindowsProxy();
std::wstring widen(const std::string &text);
class WindowsProxyGuard {
public:
  WindowsProxyGuard(bool enabled, std::string host, int port);
  ~WindowsProxyGuard();
  void reset();
  WindowsProxyGuard(const WindowsProxyGuard &) = delete;
  WindowsProxyGuard &operator=(const WindowsProxyGuard &) = delete;

private:
  bool enabled_ = false;
};
}; // namespace sbox