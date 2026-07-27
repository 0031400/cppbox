#pragma once
#include "core/net.hpp"
#include "core/session.hpp"
namespace cppbox::http_proxy {
asio::awaitable<Session> read_session(tcp::socket &socket);
asio::awaitable<void> write_success_reply(tcp::socket &socket);
} // namespace cppbox::http_proxy