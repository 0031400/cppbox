#include "config/config.hpp"
#include "core/session.hpp"
#include "inbound/mixed_inbound.hpp"
#include "inbound/socks5_inbound.hpp"
#include "outbound/block_outbound.hpp"
#include "outbound/direct_outbound.hpp"
#include "outbound/outbound.hpp"
#include "outbound/vless_ws_outbound.hpp"
#include "route/router.hpp"
#include <algorithm>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <exception>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <unordered_map>
#include <utility>

int main() {
  try {
    boost::asio::io_context io;
    auto config = sbox::load_config("config.json");
    sbox::Router router(config.route);
    std::unordered_map<std::string, std::shared_ptr<sbox::Outbound>> outbounds;
    for (const auto &item : config.outbounds) {
      if (item.type == "direct") {
        outbounds[item.tag] = std::make_shared<sbox::DirectOutbound>(io);
      } else if (item.type == "vless") {
        outbounds[item.tag] = std::make_shared<sbox::VlessWsOutbound>(
            io, sbox::VLessWsConfig{.server_host = item.server,
                                    .server_port = item.server_port,
                                    .uuid = item.uuid,
                                    .ws_path = item.ws.path,
                                    .host_header = item.ws.host,
                                    .allow_insecure = item.tls.insecure});
      } else if (item.type == "block") {
        outbounds[item.tag] = std::make_shared<sbox::BlockOutbound>();
      }
    }
    const auto &inbound_config = config.inbounds.front();
    sbox::MixedInbound inbound(
        io,
        {boost::asio::ip::make_address(inbound_config.listen),
         inbound_config.listen_port},
        [&](sbox::tcp::socket socket,
            sbox::Session session) -> boost::asio::awaitable<void> {
          auto tag = router.pick_outbound(session);
          std::cout << "[route] " << session.destination.host << ":"
                    << session.destination.port << " -> " << tag << std::endl;
          auto it = outbounds.find(tag);
          if (it == outbounds.end()) {
            throw std::runtime_error("outbound not found: " + tag);
          }
          co_await it->second->handle(std::move(socket), std::move(session));
        });
    boost::asio::co_spawn(io, inbound.start(), boost::asio::detached);
    std::cout << "sbox listening on mixed://" << inbound_config.listen << ":"
              << inbound_config.listen_port << "\n";
    io.run();
  } catch (const std::exception &e) {
    std::cerr << "fatal: " << e.what() << std::endl;
    return 1;
  }
  return 0;
}