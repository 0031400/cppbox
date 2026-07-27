#pragma once

#include "core/net.hpp"
#include "transport/stream.hpp"
namespace sbox {

inline bool is_stream_closed(const error_code &ec) {
  return ec == asio::error::eof || ec == asio::error::connection_reset ||
         ec == asio::error::operation_aborted;
}

inline bool is_websocket_closed(const error_code &ec) {
  return is_stream_closed(ec) || ec == websocket::error::closed;
}

template <typename StreamLike> class TcpStreamImpl final : public Stream {
public:
  explicit TcpStreamImpl(StreamLike stream) : stream_(std::move(stream)) {}

  asio::awaitable<std::vector<unsigned char>> read() override {
    std::array<unsigned char, 16 * 1024> buffer{};
    error_code ec;

    const auto n = co_await stream_.async_read_some(
        asio::buffer(buffer), asio::redirect_error(asio::use_awaitable, ec));

    if (is_stream_closed(ec)) {
      co_return std::vector<unsigned char>{};
    }

    if (ec) {
      throw boost::system::system_error(ec);
    }

    co_return std::vector<unsigned char>(buffer.begin(), buffer.begin() + n);
  }

  asio::awaitable<void>
  write(const std::vector<unsigned char> &bytes) override {
    error_code ec;

    co_await asio::async_write(stream_, asio::buffer(bytes),
                               asio::redirect_error(asio::use_awaitable, ec));

    if (is_stream_closed(ec)) {
      co_return;
    }

    if (ec) {
      throw boost::system::system_error(ec);
    }
  }

  void close() override {
    error_code ignored;
    auto &socket = beast::get_lowest_layer(stream_);
    socket.cancel(ignored);
    socket.shutdown(tcp::socket::shutdown_both, ignored);
    socket.close(ignored);
  }

private:
  StreamLike stream_;
};

template <typename WebSocketLike> class WsStreamImpl final : public Stream {
public:
  explicit WsStreamImpl(WebSocketLike ws) : ws_(std::move(ws)) {
    ws_.binary(true);
  }

  asio::awaitable<std::vector<unsigned char>> read() override {
    beast::flat_buffer buffer;
    error_code ec;

    co_await ws_.async_read(buffer,
                            asio::redirect_error(asio::use_awaitable, ec));

    if (is_websocket_closed(ec)) {
      co_return std::vector<unsigned char>{};
    }

    if (ec) {
      throw boost::system::system_error(ec);
    }

    std::vector<unsigned char> bytes(buffer.size());
    asio::buffer_copy(asio::buffer(bytes), buffer.data());
    co_return bytes;
  }

  asio::awaitable<void>
  write(const std::vector<unsigned char> &bytes) override {
    error_code ec;

    co_await ws_.async_write(asio::buffer(bytes),
                             asio::redirect_error(asio::use_awaitable, ec));

    if (is_websocket_closed(ec)) {
      co_return;
    }

    if (ec) {
      throw boost::system::system_error(ec);
    }
  }

  void close() override {
    error_code ignored;
    auto &socket = beast::get_lowest_layer(ws_);
    socket.cancel(ignored);
    socket.shutdown(tcp::socket::shutdown_both, ignored);
    socket.close(ignored);
  }

private:
  WebSocketLike ws_;
};
} // namespace sbox