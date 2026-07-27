#include "outbound/block_outbound.hpp"
#include "core/utils.hpp"

namespace cppbox {

asio::awaitable<void> BlockOutbound::handle(tcp::socket socket,
                                            Session session) {
  close_socket(socket);
  co_return;
}

} // namespace cppbox