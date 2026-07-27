#pragma once
#include <boost/asio/awaitable.hpp>
namespace sbox {
class Inbound {
public:
  virtual ~Inbound() = default;
  virtual asio::awaitable<void> start() = 0;
  virtual void stop() noexcept = 0;

};
}; // namespace sbox