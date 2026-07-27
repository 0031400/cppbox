#include "inbound/listen.hpp"
namespace cppbox {

tcp::acceptor make_acceptor(asio::io_context &io,
                            const tcp::endpoint &endpoint) {
  tcp::acceptor acceptor(io);

  acceptor.open(endpoint.protocol());
  acceptor.set_option(asio::socket_base::reuse_address(true));
  acceptor.bind(endpoint);
  acceptor.listen(asio::socket_base::max_listen_connections);

  return acceptor;
}

} // namespace cppbox