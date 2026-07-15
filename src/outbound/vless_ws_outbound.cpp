#include "outbound/vless_ws_outbound.hpp"
#include "core/session.hpp"
#include "core/utils.hpp"
#include <array>
#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>
#include <boost/asio/ssl/stream_base.hpp>
#include <boost/asio/ssl/verify_mode.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast.hpp>
#include <boost/beast/core/error.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/core/stream_traits.hpp>
#include <boost/beast/http/field.hpp>
#include <boost/beast/http/fields_fwd.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/ssl/ssl_stream.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/rfc6455.hpp>
#include <boost/beast/websocket/stream.hpp>
#include <boost/beast/websocket/stream_base.hpp>
#include <boost/system/system_error.hpp>
#include <exception>
#include <core/log.hpp>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <string>
#include <utility>
#include <vector>

namespace sbox {
namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace ssl = boost::asio::ssl;

VlessWsOutbound::VlessWsOutbound(asio::io_context &io, VLessWsConfig config)
    : io_(io), ssl_context_(ssl::context::tls_client), resolver_(io_),
      config_(std::move(config)) {
  if (config_.host_header.empty()) {
    config_.host_header = config_.server_host;
  }
  ssl_context_.set_default_verify_paths();
  if (config_.allow_insecure) {
    ssl_context_.set_verify_mode(ssl::verify_none);
  } else {
    ssl_context_.set_verify_mode(ssl::verify_peer);
  }
}
asio::awaitable<void> VlessWsOutbound::handle(tcp::socket inbound,
                                              Session session) {
  websocket::stream<beast::ssl_stream<tcp::socket>> ws(
      co_await asio::this_coro::executor, ssl_context_);
  try {
    co_await connect_websocket(ws);
    ws.binary(true);
    auto request = build_vless_request(session.destination);
    co_await ws.async_write(asio::buffer(request), asio::use_awaitable);
    if (!session.initial_payload.empty()) {
      co_await ws.async_write(asio::buffer(session.initial_payload),
                              asio::use_awaitable);
    }
    co_await (reply_tcp_to_ws(inbound, ws) || reply_ws_to_tcp(ws, inbound));
  } catch (const std::exception &e) {
    log_error(std::string("[vless-ws-tls] ") + e.what());
  }
  close_socket(inbound);
  error_code ignored;
  ignored =
      beast::get_lowest_layer(ws).shutdown(tcp::socket::shutdown_both, ignored);
  ignored = beast::get_lowest_layer(ws).close(ignored);
}

asio::awaitable<void> VlessWsOutbound::connect_websocket(WsTlsStream &ws) {
  auto port = std::to_string(config_.server_port);
  auto results = co_await resolver_.async_resolve(config_.server_host, port,
                                                  asio::use_awaitable);
  co_await asio::async_connect(beast::get_lowest_layer(ws), results,
                               asio::use_awaitable);
  if (!SSL_set_tlsext_host_name(ws.next_layer().native_handle(),
                                config_.server_host.c_str())) {
    throw beast::system_error(error_code(static_cast<int>(::ERR_get_error()),
                                         asio::error::get_ssl_category()),
                              "set tls sni");
  }
  if (!config_.allow_insecure) {
    ws.next_layer().set_verify_callback(
        ssl::host_name_verification(config_.server_host));
  }
  co_await ws.next_layer().async_handshake(ssl::stream_base::client,
                                           asio::use_awaitable);
  ws.set_option(
      websocket::stream_base::decorator([this](websocket::request_type &req) {
        req.set(beast::http::field::host, config_.host_header);
        req.set(beast::http::field::user_agent, "sbox-cpp/0.1");
      }));
  co_await ws.async_handshake(config_.host_header, config_.ws_path,
                              asio::use_awaitable);
}
std::vector<unsigned char>
VlessWsOutbound::build_vless_request(const Destination &dst) const {
  std::vector<unsigned char> out;
  out.reserve(64 + dst.host.size());
  out.push_back(0x00);
  auto uuid_bytes = parse_uuid(config_.uuid);
  out.insert(out.end(), uuid_bytes.begin(), uuid_bytes.end());
  out.push_back(0x00);
  out.push_back(0x01);
  write_be16(out, dst.port);
  if (dst.type == AddressType::IPv4) {
    out.push_back(0x01);
    auto ip = asio::ip::make_address_v4(dst.host).to_bytes();
    out.insert(out.end(), ip.begin(), ip.end());
    return out;
  }
  if (dst.type == AddressType::IPv6) {
    out.push_back(0x03);
    auto ip = asio::ip::make_address_v6(dst.host).to_bytes();
    out.insert(out.end(), ip.begin(), ip.end());
    return out;
  }
  require(dst.host.size() <= 255, "vless domain too long");
  out.push_back(0x02);
  out.push_back(static_cast<unsigned char>(dst.host.size()));
  out.insert(out.end(), dst.host.begin(), dst.host.end());
  return out;
}
asio::awaitable<void> VlessWsOutbound::reply_tcp_to_ws(tcp::socket &tcp_socket,
                                                       WsTlsStream &ws) {
  std::array<unsigned char, 16 * 1024> buffer{};
  for (;;) {
    error_code ec;
    auto n = co_await tcp_socket.async_read_some(
        asio::buffer(buffer), asio::redirect_error(asio::use_awaitable, ec));
    if (ec == asio::error::eof || ec == asio::error::connection_reset ||
        ec == asio::error::operation_aborted) {
      co_return;
    }
    if (ec) {
      throw boost::system::system_error(ec);
    }
    co_await ws.async_write(asio::buffer(buffer.data(), n),
                            asio::redirect_error(asio::use_awaitable, ec));
    if (ec == asio::error::eof || ec == asio::error::connection_reset ||
        ec == asio::error::operation_aborted ||
        ec == websocket::error::closed) {
      co_return;
    }
    if (ec) {
      throw boost::system::system_error(ec);
    }
  }
}
asio::awaitable<void>
VlessWsOutbound::reply_ws_to_tcp(WsTlsStream &ws, tcp::socket &tcp_socket) {
  bool first_message = true;
  for (;;) {
    beast::flat_buffer buffer;
    error_code ec;

    co_await ws.async_read(buffer,
                           asio::redirect_error(asio::use_awaitable, ec));

    if (ec == websocket::error::closed || ec == asio::error::eof ||
        ec == asio::error::connection_reset ||
        ec == asio::error::operation_aborted) {
      co_return;
    }
    if (ec) {
      throw boost::system::system_error(ec);
    }

    std::vector<unsigned char> bytes(buffer.size());
    boost::asio::buffer_copy(boost::asio::buffer(bytes), buffer.data());
    if (first_message) {
      first_message = false;
      strip_vless_response_header(bytes);
    }
    if (!bytes.empty()) {
      co_await asio::async_write(tcp_socket, asio::buffer(bytes),
                                 asio::redirect_error(asio::use_awaitable, ec));

      if (ec == asio::error::eof || ec == asio::error::connection_reset ||
          ec == asio::error::operation_aborted) {
        co_return;
      }
      if (ec) {
        throw boost::system::system_error(ec);
      }
    }
  }
}
void VlessWsOutbound::strip_vless_response_header(
    std::vector<unsigned char> &bytes) {
  require(bytes.size() >= 2, "short vless response header");
  const auto addon_len = bytes[1];
  const std::size_t header_len = 2u + addon_len;
  require(bytes.size() >= header_len, "incomplete vless header");
  bytes.erase(bytes.begin(),
              bytes.begin() + static_cast<std::ptrdiff_t>(header_len));
}
}; // namespace sbox