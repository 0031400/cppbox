#pragma once
#include "outbound/outbound.hpp"
namespace sbox {
class BlockOutbound : public Outbound {
public:
  asio::awaitable<void> handle(tcp::socket socket, Session session) override;
};
}; // namespace sbox