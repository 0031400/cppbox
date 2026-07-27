#pragma once
#include "core/net.hpp"
#include "core/session.hpp"
namespace cppbox::socks5 {
asio::awaitable<Session> read_session(tcp::socket &socket);
asio::awaitable<void> write_success_reply(tcp::socket &socket);
} // namespace cppbox::socks5