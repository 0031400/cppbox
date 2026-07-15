#pragma once
#include "core/net.hpp"
#include "core/session.hpp"
#include <boost/asio/awaitable.hpp>
#include <functional>

namespace sbox {
class MixedInbound {

public:
  using Handler = std::function<asio::awaitable<void>(tcp::socket, Session)>;
  MixedInbound(asio::io_context &io, tcp::endpoint endpoint, Handler handler);
  asio::awaitable<void> start();

private:
  asio::awaitable<void> handle_client(tcp::socket socket);
  asio::awaitable<Session> read_socks5_session(tcp::socket &socket);
  asio::awaitable<Session> read_http_connect_session(tcp::socket &socket);
  static AddressType parse_socks_address_type(unsigned char atyp);
  asio::awaitable<std::string> read_socks_address(tcp::socket &socket,
                                                  AddressType type);
  static Destination parse_connect_target(const std::string &target);
  static std::string trim(std::string text);
  asio::awaitable<void> write_socks_success_reply(tcp::socket &socket);
  asio::awaitable<void> write_http_success_reply(tcp::socket &socket);
  asio::awaitable<void> write_http_error_reply(tcp::socket &socket,int code,const std::string&text);
  tcp::acceptor acceptor_;
  Handler handler_;
};
}; // namespace sbox