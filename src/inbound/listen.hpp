#pragma once

#include "core/net.hpp"

namespace sbox {

tcp::acceptor make_acceptor(asio::io_context &io,
                            const tcp::endpoint &endpoint);

} // namespace sbox