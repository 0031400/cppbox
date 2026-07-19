#include "inbound/mixed_inbound.hpp"
#include "core/session.hpp"
#include "core/utils.hpp"
#include "protocol/http_proxy.hpp"
#include "protocol/socks5.hpp"
#include <algorithm>
#include <array>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <cctype>
#include <core/log.hpp>
#include <exception>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

namespace sbox {
MixedInbound::MixedInbound(asio::io_context &io, tcp::endpoint endpoint,
                           Handler handler)
    : acceptor_(io, endpoint), handler_(std::move(handler)) {}
asio::awaitable<void> MixedInbound::start() {
  for (;;) {
    tcp::socket socket = co_await acceptor_.async_accept(asio::use_awaitable);
    asio::co_spawn(acceptor_.get_executor(), handle_client(std::move(socket)),
                   asio::detached);
  }
}
asio::awaitable<void> MixedInbound::handle_client(tcp::socket socket) {
  try {
    std::array<unsigned char, 1> first{};
    co_await socket.async_receive(
        asio::buffer(first), tcp::socket::message_peek, asio::use_awaitable);
    Session session;
    if (first[0] == 0x05) {
      session = co_await socks5::read_session(socket);
    } else {
      session = co_await http_proxy::read_session(socket);
    }
    co_await handler_(std::move(socket), std::move(session));
  } catch (const std::exception &e) {
    log_error(std::string("[mixed] ") + e.what());
    close_socket(socket);
  }
}
asio::awaitable<Session>
MixedInbound::read_socks5_session(tcp::socket &socket) {
  std::array<unsigned char, 2> greeting{};
  co_await asio::async_read(socket, asio::buffer(greeting),
                            asio::use_awaitable);
  require(greeting[0] == 0x05, "version must be 5");

  require(greeting[1] > 0, "empty socks5 method list");
  std::vector<unsigned char> methods(greeting[1]);
  co_await asio::async_read(socket, asio::buffer(methods), asio::use_awaitable);
  bool no_auth =
      std::find(methods.begin(), methods.end(), 0x00) != methods.end();
  std::array<unsigned char, 2> method_reply{
      0x05, static_cast<unsigned char>(no_auth ? 0x00 : 0xff)};
  co_await asio::async_write(socket, asio::buffer(method_reply),
                             asio::use_awaitable);
  require(no_auth, "socks5 no-auth method not supported by client");
  std::array<unsigned char, 4> header{};
  co_await asio::async_read(socket, asio::buffer(header), asio::use_awaitable);
  require(header[0] == 0x05, "invalid socks5 request version");
  require(header[1] == 0x01, "only socks5 CONNECT is supported");
  require(header[2] == 0x00, "invalid socks5 reserved byte");
  Destination dst;
  dst.type = parse_socks_address_type(header[3]);
  dst.host = co_await read_socks_address(socket, dst.type);
  std::array<unsigned char, 2> port{};
  co_await asio::async_read(socket, asio::buffer(port), asio::use_awaitable);
  dst.port = read_be16(port.data());
  co_await write_socks_success_reply(socket);
  co_return Session(std::move(dst));
}

AddressType MixedInbound::parse_socks_address_type(unsigned char atyp) {
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
asio::awaitable<std::string>
MixedInbound::read_socks_address(tcp::socket &socket, AddressType type) {
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
std::string MixedInbound::trim(std::string text) {
  auto not_space = [](unsigned char c) { return !std::isspace(c); };
  text.erase(text.begin(), std::find_if(text.begin(), text.end(), not_space));
  text.erase(std::find_if(text.rbegin(), text.rend(), not_space).base(),
             text.end());
  return text;
}
asio::awaitable<void>
MixedInbound::write_socks_success_reply(tcp::socket &socket) {
  std::array<unsigned char, 10> reply{
      0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  co_await asio::async_write(socket, asio::buffer(reply), asio::use_awaitable);
}

asio::awaitable<void>
MixedInbound::write_http_error_reply(tcp::socket &socket, int code,
                                     const std::string &text) {
  std::string reply = "HTTP/1.1 " + std::to_string(code) + " " + text +
                      "\r\n"
                      "Connection: close\r\n"
                      "Content-Length: 0\r\n"
                      "\r\n";
  co_await asio::async_write(socket, asio::buffer(reply), asio::use_awaitable);
}
}; // namespace sbox