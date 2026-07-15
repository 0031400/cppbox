#pragma once
#include "core/session.hpp"
#include "core/utils.hpp"
#include <boost/asio.hpp>
#include <functional>

namespace sbox {
class Socks5Inbound {
public:
  using Handler = std::function<asio::awaitable<void>(tcp::socket, Session)>;
  Socks5Inbound(asio::io_context &io, tcp::endpoint endpoint, Handler handler);
  asio::awaitable<void> start();

private:
  asio::awaitable<void> handle_client(tcp::socket socket);
  asio::awaitable<Session> read_session(tcp::socket &socket);
  static AddressType parse_address_type(unsigned char atyp);
  asio::awaitable<std::string> read_address(tcp::socket &socket,
                                            AddressType type);
  asio::awaitable<void> write_success_reply(tcp::socket &socket);
  tcp::acceptor acceptor_;
  Handler handler_;
};
}; // namespace sbox