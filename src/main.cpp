#include "config/config.hpp"
#include "core/log.hpp"
#include "core/session.hpp"
#include "inbound/mixed_inbound.hpp"
#include "outbound/block_outbound.hpp"
#include "outbound/direct_outbound.hpp"
#include "outbound/outbound.hpp"
#include "outbound/vless_outbound.hpp"
#include "platform/windows_proxy.hpp"
#include "protocol/vless.hpp"
#include "route/router.hpp"
#include "transport/ws_client.hpp"
#include <Windows.h>
#include <atomic>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <exception>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#ifdef _WIN32
boost::asio::io_context *g_io = nullptr;
std::atomic_bool g_stopping = false;
std::atomic_bool g_windows_proxy = false;
BOOL WINAPI consoleCtrlHandler(DWORD signal) {
  switch (signal) {
  case CTRL_C_EVENT:
  case CTRL_BREAK_EVENT:
  case CTRL_CLOSE_EVENT:
  case CTRL_LOGOFF_EVENT:
  case CTRL_SHUTDOWN_EVENT:
    if (g_stopping.exchange(true)) {
      return TRUE;
    }
    if (g_io != nullptr && !g_io->stopped()) {
      sbox::log_info("stopping");
      g_io->stop();
    }
    if (g_windows_proxy) {
      sbox::unsetWindowsProxy();
      sbox::log_info("unset windows proxy");
    }
    return FALSE;
  default:
    return FALSE;
  }
}
#endif
int main() {
  try {
    boost::asio::io_context io;
#ifdef _WIN32
    g_io = &io;
#endif
    auto config = sbox::load_config("config.json");
    sbox::Router router(config.route);
    std::unordered_map<std::string, std::shared_ptr<sbox::Outbound>> outbounds;
    for (const auto &item : config.outbounds) {
      if (item.type == "direct") {
        outbounds[item.tag] = std::make_shared<sbox::DirectOutbound>(io);
      } else if (item.type == "vless") {
        outbounds[item.tag] = std::make_shared<sbox::VlessOutbound>(
            io, sbox::VlessOutboundConfig{
                    .vless = sbox::VlessConfig{.uuid = item.uuid},
                    .transport = sbox::WsClientConfig{
                        .server_host = item.server,
                        .server_port = item.server_port,
                        .path = item.ws.path,
                        .host_header = item.ws.host,
                        .tls = sbox::TlsClientConfig{
                            .enabled = item.tls.enabled,
                            .server_name = item.tls.server_name.empty()
                                               ? item.server
                                               : item.tls.server_name,
                            .insecure = item.tls.insecure}}});
      } else if (item.type == "block") {
        outbounds[item.tag] = std::make_shared<sbox::BlockOutbound>();
      }
    }
    std::unordered_map<std::string, std::shared_ptr<sbox::MixedInbound>>
        inbounds;
    for (const auto &inbound_config : config.inbounds) {
      if (inbound_config.type == "mixed") {
        auto endpoint = sbox::tcp::endpoint{
            boost::asio::ip::make_address(inbound_config.listen),
            inbound_config.listen_port};
        auto inbound = std::make_shared<sbox::MixedInbound>(
            io, endpoint,
            [&](sbox::tcp::socket socket,
                sbox::Session session) -> boost::asio::awaitable<void> {
              auto tag = router.pick_outbound(session);
              std::cout << "[route] " << session.destination.host << ":"
                        << session.destination.port << " -> " << tag
                        << std::endl;
              auto it = outbounds.find(tag);
              if (it == outbounds.end()) {
                throw std::runtime_error("outbound not found: " + tag);
              }
              co_await it->second->handle(std::move(socket),
                                          std::move(session));
            });
        boost::asio::co_spawn(io, inbound->start(), boost::asio::detached);
        std::cout << "sbox listening on mixed://" << inbound_config.listen
                  << ":" << inbound_config.listen_port << "\n";
        inbounds[inbound_config.tag] = inbound;
      }
    }
#ifdef _WIN32
    SetConsoleCtrlHandler(consoleCtrlHandler, TRUE);
    if (config.windows_proxy.enabled) {
      sbox::setWindowsProxy(config.windows_proxy.addr,
                            config.windows_proxy.port);
      g_windows_proxy = true;
      sbox::log_info("set windows proxy: http://" + config.windows_proxy.addr +
                     ":" + std::to_string(config.windows_proxy.port));
#else
    if (config.windows_proxy.enabled) {
      sbox::log_info("windows proxy only support windows");
    }
#endif
    }
    io.run();
  } catch (const std::exception &e) {
    sbox::log_error(e.what());
    return 1;
  }
  return 0;
}