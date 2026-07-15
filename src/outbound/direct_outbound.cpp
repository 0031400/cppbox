#pragma once
#include "outbound/direct_outbound.hpp"
#include "core/net.hpp"
#include <boost/asio/connect.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <exception>
#include <iostream>
#include <string>

namespace sbox {

using boost::asio::experimental::awaitable_operators::operator||;
DirectOutbound::DirectOutbound(asio::io_context &io) : resolver_(io) {}
asio::awaitable<void> DirectOutbound::handle(tcp::socket inbound,
                                             Session session) {
  tcp::socket outbound(co_await asio::this_coro::executor);
  try {
    auto results = co_await resolver_.async_resolve(
        session.destination.host, std::to_string(session.destination.port),
        asio::use_awaitable);
    co_await asio::async_connect(outbound, results, asio::use_awaitable);
    co_await (relay(inbound, outbound) || relay(outbound, inbound));

  } catch (const std::exception &e) {
    std::cerr << "[direct] " << e.what() << std::endl;
  }
}
asio::awaitable<void> DirectOutbound::relay(tcp::socket &from,
                                            tcp::socket &to) {
  std::array<unsigned char, 16 * 1024> buffer{};
  for (;;) {
    auto n = co_await from.async_read_some(asio::buffer(buffer),
                                           asio::use_awaitable);
    co_await asio::async_write(to, asio::buffer(buffer.data(), n),
                               asio::use_awaitable);
  }
}
}; // namespace sbox