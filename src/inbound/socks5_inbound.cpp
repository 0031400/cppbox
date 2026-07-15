#pragma once
#include "inbound/socks5_inbound.hpp"
#include "core/session.hpp"
#include "core/utils.hpp"
#include <algorithm>
#include <array>
#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <exception>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace sbox {

Socks5Inbound::Socks5Inbound(asio::io_context &io, tcp::endpoint endpoint,
                             Handler handler)
    : acceptor_(io, endpoint), handler_(std::move(handler)) {}
asio::awaitable<void> Socks5Inbound::start() {
  for (;;) {
    tcp::socket socket = co_await acceptor_.async_accept(asio::use_awaitable);
    asio::co_spawn(acceptor_.get_executor(), handle_client(std::move(socket)),
                   asio::detached);
  }
}

asio::awaitable<void> Socks5Inbound::handle_client(tcp::socket socket) {
  try {
    auto session = co_await read_session(socket);
    co_await handler_(std::move(socket), std::move(session));
  } catch (const std::exception &e) {
    std::cerr << "[socks5] " << e.what() << std::endl;
    close_socket(socket);
  }
}
asio::awaitable<Session> Socks5Inbound::read_session(tcp::socket &socket) {
  std::array<unsigned char, 2> greeting{};
  co_await asio::async_read(socket, asio::buffer(greeting),
                            asio::use_awaitable);
  require(greeting[0] == 0x05, "invalid socks version");

  require(greeting[1] > 0, "empty socks method list");
  std::vector<unsigned char> methods(greeting[1]);
  co_await asio::async_read(socket, asio::buffer(methods), asio::use_awaitable);
  bool no_auth = false;
  for (auto method : methods) {
    if (method == 0x00) {
      no_auth = true;
      break;
    }
  }
  std::array<unsigned char, 2> method_reply{
      0x05, static_cast<unsigned char>(no_auth ? 0x00 : 0xff)};
  co_await asio::async_write(socket, asio::buffer(method_reply),
                             asio::use_awaitable);
  require(no_auth, "socks no-auth method not supported by client");
  std::array<unsigned char, 4> header{};
  co_await asio::async_read(socket, asio::buffer(header), asio::use_awaitable);
  require(header[0] == 0x05, "invalid socks request version");
  require(header[1] == 0x01, "only socks CONNECT is supported");
  require(header[2] == 0x00, "invalid socks reserved byte");
  Destination dst;
  dst.type = parse_address_type(header[3]);
  dst.host = co_await read_address(socket, dst.type);
  std::array<unsigned char, 2> port{};
  co_await asio::async_read(socket, asio::buffer(port), asio::use_awaitable);
  dst.port = read_be16(port.data());
  co_await write_success_reply(socket);
  co_return Session(std::move(dst));
}
AddressType Socks5Inbound::parse_address_type(unsigned char atyp) {
  switch (atyp) {
  case 0x01:
    return AddressType::IPv4;
  case 0x03:
    return AddressType::Domain;
  case 0x04:
    return AddressType::IPv6;
  default:
    throw std::runtime_error("unsupported socks address type");
  }
}
asio::awaitable<std::string> Socks5Inbound::read_address(tcp::socket &socket,
                                                         AddressType type) {
  if (type == AddressType::IPv4) {
    std::array<unsigned char, 4> raw{};
    co_await asio::async_read(socket, asio::buffer(raw), asio::use_awaitable);
    asio::ip::address_v4::bytes_type bytes{raw[0], raw[1], raw[2], raw[3]};
    co_return asio::ip::address_v4(bytes).to_string();
  }
  if (type == AddressType::IPv6) {
    std::array<unsigned char, 16> raw{};
    co_await asio::async_read(socket, asio::buffer(raw), asio::use_awaitable);
    asio::ip::address_v6::bytes_type bytes{};
    std::copy(raw.begin(), raw.end(), bytes.begin());
    co_return asio::ip::address_v6(bytes).to_string();
  }
  std::array<unsigned char, 1> len{};
  co_await asio::async_read(socket, asio::buffer(len), asio::use_awaitable);
  require(len[0] > 0, "empty socks domain");
  std::vector<unsigned char> domain(len[0]);
  co_await asio::async_read(socket, asio::buffer(domain), asio::use_awaitable);
  co_return std::string(domain.begin(), domain.end());
}
asio::awaitable<void> Socks5Inbound::write_success_reply(tcp::socket &socket) {
  std::array<unsigned char, 10> reply{
      0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  co_await asio::async_write(socket, asio::buffer(reply), asio::use_awaitable);
}
}; // namespace sbox