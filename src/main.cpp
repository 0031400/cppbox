#include "config/config.hpp"
#include "core/log.hpp"
#include "core/session.hpp"
#include "core/shutdown.hpp"
#include "dns/dns.hpp"
#include "inbound/http_inbound.hpp"
#include "inbound/inbound.hpp"
#include "inbound/mixed_inbound.hpp"
#include "inbound/socks5_inbound.hpp"
#include "outbound/block_outbound.hpp"
#include "outbound/direct_outbound.hpp"
#include "outbound/outbound.hpp"
#include "outbound/vless_outbound.hpp"
#include "platform/windows_proxy.hpp"
#include "protocol/vless.hpp"
#include "route/router.hpp"
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

int main() {
  try {
    boost::asio::io_context io;
    sbox::Shutdown shutdown(io);
    auto config = sbox::load_config("config.json");
    sbox::DnsServer dnsServer(config.dns);
    sbox::Connector connector(dnsServer);
    sbox::Router router(config.route);
    std::unordered_map<std::string, std::shared_ptr<sbox::Outbound>> outbounds;
    for (const auto &item : config.outbounds) {
      if (item.type == "direct") {
        outbounds[item.tag] =
            std::make_shared<sbox::DirectOutbound>(io, connector);
      } else if (item.type == "vless") {
        outbounds[item.tag] = std::make_shared<sbox::VlessOutbound>(
            io,
            sbox::VlessOutboundConfig{
                .server =
                    sbox::Destination{
                        .host = sbox::Host::parse(item.server),
                        .port = item.server_port,
                    },
                .vless = sbox::VlessConfig{.uuid = item.uuid},
                .tls = item.tls,
                .transport = item.transport,
                .override_address = config.override_address,
            },
            connector);
      } else if (item.type == "block") {
        outbounds[item.tag] = std::make_shared<sbox::BlockOutbound>();
      }
    }
    std::unordered_map<std::string, std::shared_ptr<sbox::Inbound>> inbounds;
    auto handler = [&](sbox::tcp::socket socket,
                       sbox::Session session) -> boost::asio::awaitable<void> {
      auto tag = router.pick_outbound(session);
      std::cout << "[route] " << session.destination.to_string() << " -> "
                << tag << std::endl;
      auto it = outbounds.find(tag);
      try {
        if (it == outbounds.end()) {
          throw std::runtime_error("outbound not found: " + tag);
        }
        co_await it->second->handle(std::move(socket), std::move(session));
      } catch (const std::exception &e) {
        sbox::log_error(e.what());
      }
    };
    for (const auto &inbound_config : config.inbounds) {
      auto endpoint = sbox::tcp::endpoint{
          boost::asio::ip::make_address(inbound_config.listen),
          inbound_config.listen_port};
      std::shared_ptr<sbox::Inbound> inbound;
      if (inbound_config.type == "mixed") {
        inbound = std::make_shared<sbox::MixedInbound>(io, endpoint, handler);
      } else if (inbound_config.type == "socks5") {
        inbound = std::make_shared<sbox::Socks5Inbound>(io, endpoint, handler);
      } else if (inbound_config.type == "http") {
        inbound = std::make_shared<sbox::HttpInbound>(io, endpoint, handler);
      } else {
        throw std::runtime_error("unsupported inbound type: " +
                                 inbound_config.type);
      }
      boost::asio::co_spawn(io, inbound->start(), boost::asio::detached);
      std::cout << "sbox listening on " << inbound_config.type << "://"
                << inbound_config.listen << ":" << inbound_config.listen_port
                << "\n";
      inbounds[inbound_config.tag] = inbound;
    }
#ifdef _WIN32
    if (config.windows_proxy.enabled) {
      sbox::setWindowsProxy(config.windows_proxy.addr,
                            config.windows_proxy.port);

      shutdown.on_stop([] {
        sbox::unsetWindowsProxy();
        sbox::log_info("unset windows proxy");
      });

      sbox::log_info("set windows proxy: http://" + config.windows_proxy.addr +
                     ":" + std::to_string(config.windows_proxy.port));
    }
#else
    if (config.windows_proxy.enabled) {
      sbox::log_info("windows proxy only support windows");
    }
#endif
    shutdown.start();
    io.run();
  } catch (const std::exception &e) {
    sbox::log_error(e.what());
    return 1;
  }
  return 0;
}