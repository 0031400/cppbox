#pragma once
#include "core/session.hpp"
#include "core/utils.hpp"
#include <boost/asio.hpp>

namespace sbox {
class Outbound {
public:
  virtual ~Outbound() = default;
  virtual asio::awaitable<void> handle(tcp::socket socket, Session session) = 0;
};
}; // namespace sbox