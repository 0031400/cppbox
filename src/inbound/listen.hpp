#pragma once

#include "core/net.hpp"

namespace cppbox {

tcp::acceptor make_acceptor(asio::io_context &io,
                            const tcp::endpoint &endpoint);

} // namespace cppbox