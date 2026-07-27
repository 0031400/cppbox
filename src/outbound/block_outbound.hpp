#pragma once
#include "outbound/outbound.hpp"
namespace cppbox {
class BlockOutbound : public Outbound {
public:
  asio::awaitable<void> handle(tcp::socket socket, Session session) override;
};
}; // namespace cppbox