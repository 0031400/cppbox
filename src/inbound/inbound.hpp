#pragma once
#include <boost/asio/awaitable.hpp>
namespace sbox {
class Inbound {
public:
  virtual ~Inbound() = default;
  virtual boost::asio::awaitable<void> start() = 0;
};
}; // namespace sbox