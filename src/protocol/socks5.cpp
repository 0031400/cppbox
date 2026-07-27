#include "protocol/socks5.hpp"
#include "core/address.hpp"
#include "core/utils.hpp"
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>

namespace sbox::socks5 {
namespace {

asio::awaitable<Host> read_host(tcp::socket &socket, unsigned char atyp) {
  if (atyp == 0x01) {
    std::array<unsigned char, 4> raw{};
    co_await asio::async_read(socket, asio::buffer(raw), asio::use_awaitable);

    ip::address_v4::bytes_type bytes{raw[0], raw[1], raw[2], raw[3]};
    co_return Host(IPv4Address(ip::address_v4(bytes)));
  }

  if (atyp == 0x04) {
    std::array<unsigned char, 16> raw{};
    co_await asio::async_read(socket, asio::buffer(raw), asio::use_awaitable);

    ip::address_v6::bytes_type bytes{};
    std::copy(raw.begin(), raw.end(), bytes.begin());
    co_return Host(IPv6Address(ip::address_v6(bytes)));
  }

  if (atyp == 0x03) {
    std::array<unsigned char, 1> length{};
    co_await asio::async_read(socket, asio::buffer(length),
                              asio::use_awaitable);
    require(length[0] > 0, "empty socks5 domain");

    std::vector<unsigned char> raw(length[0]);
    co_await asio::async_read(socket, asio::buffer(raw), asio::use_awaitable);
    co_return Host::domain(std::string(raw.begin(), raw.end()));
  }

  throw std::runtime_error("unsupported socks5 address type");
}

} // namespace

asio::awaitable<Session> read_session(tcp::socket &socket) {
  std::array<unsigned char, 2> greeting{};
  co_await asio::async_read(socket, asio::buffer(greeting),
                            asio::use_awaitable);
  require(greeting[0] == 0x05, "invalid socks version");
  require(greeting[1] > 0, "empty socks method list");

  std::vector<unsigned char> methods(greeting[1]);
  co_await asio::async_read(socket, asio::buffer(methods), asio::use_awaitable);

  bool no_auth = false;
  for (const auto method : methods) {
    if (method == 0x00) {
      no_auth = true;
      break;
    }
  }

  const std::array<unsigned char, 2> method_reply{
      0x05, static_cast<unsigned char>(no_auth ? 0x00 : 0xff)};
  co_await asio::async_write(socket, asio::buffer(method_reply),
                             asio::use_awaitable);
  require(no_auth, "socks no-auth method not supported by client");

  std::array<unsigned char, 4> header{};
  co_await asio::async_read(socket, asio::buffer(header), asio::use_awaitable);
  require(header[0] == 0x05, "invalid socks request version");
  require(header[1] == 0x01, "only socks CONNECT is supported");
  require(header[2] == 0x00, "invalid socks reserved byte");

  auto destination_host = co_await read_host(socket, header[3]);

  std::array<unsigned char, 2> port{};
  co_await asio::async_read(socket, asio::buffer(port), asio::use_awaitable);
  auto destination_port = read_be16(port.data());

  co_await write_success_reply(socket);
  co_return Session{Destination{destination_host, destination_port}, {}};
}

asio::awaitable<void> write_success_reply(tcp::socket &socket) {
  const std::array<unsigned char, 10> reply{
      0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  co_await asio::async_write(socket, asio::buffer(reply), asio::use_awaitable);
}

} // namespace sbox::socks5