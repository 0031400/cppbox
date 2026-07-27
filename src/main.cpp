#include "config/config.hpp"
#include "core/log.hpp"
#include "core/shutdown.hpp"
#include "dns/dns.hpp"
#include "dns/dns_inbound.hpp"
#include "inbound/http_inbound.hpp"
#include "inbound/inbound.hpp"
#include "inbound/mixed_inbound.hpp"
#include "inbound/socks5_inbound.hpp"
#include "inbound/tun_inbound.hpp"
#include "inbound/tun_route.hpp"
#include "outbound/block_outbound.hpp"
#include "outbound/direct_outbound.hpp"
#include "outbound/outbound.hpp"
#include "outbound/vless_outbound.hpp"
#include "platform/windows_proxy.hpp"
#include "protocol/vless.hpp"
#include "route/router.hpp"
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
    cppbox::Shutdown shutdown(io);
    auto config = cppbox::load_config("config.json");
    cppbox::Router router(config.route);
    cppbox::DnsServer dnsServer(config.dns, router);
    cppbox::Connector connector(dnsServer);
    dnsServer.set_connector(connector);
    std::unordered_map<std::string, std::shared_ptr<cppbox::Outbound>> outbounds;
    std::shared_ptr<cppbox::Inbound> tun_inbound;

    for (const auto &item : config.outbounds) {
      if (item.type == "direct") {
        outbounds[item.tag] =
            std::make_shared<cppbox::DirectOutbound>(io, connector);
      } else if (item.type == "vless") {
        outbounds[item.tag] = std::make_shared<cppbox::VlessOutbound>(
            io,
            cppbox::VlessOutboundConfig{
                .server =
                    cppbox::Destination{
                        .host = cppbox::Host::parse(item.server),
                        .port = item.server_port,
                    },
                .vless = cppbox::VlessConfig{.uuid = item.uuid},
                .tls = item.tls,
                .transport = item.transport,
                .override_address = config.override_address,
            },
            connector);
      } else if (item.type == "block") {
        outbounds[item.tag] = std::make_shared<cppbox::BlockOutbound>();
      }
    }

    std::unordered_map<std::string, std::shared_ptr<cppbox::Inbound>> inbounds;
    auto handler = [&](cppbox::tcp::socket socket,
                       cppbox::Session session) -> boost::asio::awaitable<void> {
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
        cppbox::log_error(e.what());
      }
    };
    if (config.tun.enable) {
      auto outbound_index = cppbox::find_default_route_interface_index();
      if (!outbound_index) {
        throw std::runtime_error("failed to find outbound interface for tun");
      }

      connector.set_outbound_interface_index(*outbound_index);
      cppbox::log_info("tun outbound interface index: " +
                     std::to_string(*outbound_index));
      tun_inbound = std::make_shared<cppbox::TunInbound>(
          io,
          cppbox::TunInboundConfig{
              .tun_ip = config.tun.tun_ip,
              .tun_next_ip = config.tun.tun_next_ip,
          },
          handler);
      boost::asio::co_spawn(io, tun_inbound->start(), boost::asio::detached);
      inbounds["tun"] = tun_inbound;
      cppbox::log_info("cppbox tun inbound enabled: " + config.tun.tun_ip);
    }
    for (const auto &inbound_config : config.inbounds) {
      auto endpoint = cppbox::tcp::endpoint{
          boost::asio::ip::make_address(inbound_config.listen),
          inbound_config.listen_port};
      std::shared_ptr<cppbox::Inbound> inbound;
      if (inbound_config.type == "mixed") {
        inbound = std::make_shared<cppbox::MixedInbound>(io, endpoint, handler);
      } else if (inbound_config.type == "socks5") {
        inbound = std::make_shared<cppbox::Socks5Inbound>(io, endpoint, handler);
      } else if (inbound_config.type == "http") {
        inbound = std::make_shared<cppbox::HttpInbound>(io, endpoint, handler);
      } else {
        throw std::runtime_error("unsupported inbound type: " +
                                 inbound_config.type);
      }
      boost::asio::co_spawn(io, inbound->start(), boost::asio::detached);
      std::cout << "cppbox listening on " << inbound_config.type << "://"
                << inbound_config.listen << ":" << inbound_config.listen_port
                << "\n";
      inbounds[inbound_config.tag] = inbound;
    }
    if (config.dns.listen) {
      auto dns_inbound =
          std::make_shared<cppbox::DnsInbound>(io, *config.dns.listen, dnsServer);

      inbounds["dns"] = dns_inbound;
      boost::asio::co_spawn(io, dns_inbound->start(), boost::asio::detached);
    }
    shutdown.on_stop([&inbounds] {
      for (const auto &[tag, inbound] : inbounds) {
        cppbox::log_info("stopping inbound: " + tag);
        inbound->stop();
      }
    });
    // windows proxy
#ifdef _WIN32
    if (config.windows_proxy.enabled) {
      cppbox::setWindowsProxy(config.windows_proxy.addr,
                            config.windows_proxy.port);

      shutdown.on_stop([] {
        cppbox::unsetWindowsProxy();
        cppbox::log_info("unset windows proxy");
      });

      cppbox::log_info("set windows proxy: http://" + config.windows_proxy.addr +
                     ":" + std::to_string(config.windows_proxy.port));
    }
#else
    if (config.windows_proxy.enabled) {
      cppbox::log_info("windows proxy only support windows");
    }
#endif
    shutdown.start();
    io.run();
  } catch (const std::exception &e) {
    cppbox::log_error(e.what());
    return 1;
  }
  return 0;
}