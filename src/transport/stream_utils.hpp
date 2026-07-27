#pragma once

#include "core/net.hpp"

namespace sbox {

inline bool is_stream_closed(const error_code &ec) {
  return ec == asio::error::eof || ec == asio::error::connection_reset ||
         ec == asio::error::operation_aborted;
}

inline bool is_websocket_closed(const error_code &ec) {
  return is_stream_closed(ec) || ec == websocket::error::closed;
}

} // namespace sbox