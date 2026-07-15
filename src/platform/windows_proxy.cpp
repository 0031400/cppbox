#include "platform/windows_proxy.hpp"
#include "core/log.hpp"
#include <string>
#include <windows.h>
#include <wininet.h>

namespace sbox {
constexpr const wchar_t *kInternetSettingsKey =
    L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
bool setDwordValue(HKEY key, const wchar_t *name, DWORD value) {
  return RegSetValueExW(key, name, 0, REG_DWORD,
                        reinterpret_cast<const BYTE *>(&value),
                        sizeof(value)) == ERROR_SUCCESS;
}
bool setStringValue(HKEY key, const wchar_t *name, const std::wstring &value) {
  return RegSetValueExW(key, name, 0, REG_SZ,
                        reinterpret_cast<const BYTE *>(value.c_str()),
                        static_cast<DWORD>((value.size() + 1) *
                                           sizeof(wchar_t))) == ERROR_SUCCESS;
}
void refreshProxySettings() {
  InternetSetOptionW(nullptr, INTERNET_OPTION_SETTINGS_CHANGED, nullptr, 0);
  InternetSetOptionW(nullptr, INTERNET_OPTION_REFRESH, nullptr, 0);
}
bool setWindowsProxy(const std::wstring &host, int port) {
  HKEY key = nullptr;
  if (RegOpenKeyExW(HKEY_CURRENT_USER, kInternetSettingsKey, 0, KEY_SET_VALUE,
                    &key) != ERROR_SUCCESS) {
    return false;
  }
  const std::wstring proxyServer = host + L":" + std::to_wstring(port);
  const bool ok = setDwordValue(key, L"ProxyEnable", 1) &&
                  setStringValue(key, L"ProxyServer", proxyServer);
  RegCloseKey(key);
  if (ok) {
    refreshProxySettings();
  }
  return ok;
}
bool unsetWindowsProxy() {
  HKEY key = nullptr;
  if (RegOpenKeyExW(HKEY_CURRENT_USER, kInternetSettingsKey, 0, KEY_SET_VALUE,
                    &key) != ERROR_SUCCESS) {
    return false;
  }
  const bool ok = setDwordValue(key, L"ProxyEnable", 0);
  RegCloseKey(key);
  if (ok) {
    refreshProxySettings();
  }
  return ok;
}

std::wstring widen(const std::string &text) {
  return std::wstring(text.begin(), text.end());
}
WindowsProxyGuard::WindowsProxyGuard(bool enabled, std::string host, int port) {
  if (enabled) {
    enabled_ = setWindowsProxy(widen(host), port);
    if (!enabled_) {
      log_error("fail to set windows proxy");
    }
  }
}
WindowsProxyGuard::~WindowsProxyGuard() { reset(); }
void WindowsProxyGuard::reset() {
  if (enabled_) {
    unsetWindowsProxy();
    enabled_ = false;
  }
}
}; // namespace sbox