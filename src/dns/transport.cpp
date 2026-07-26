#include "dns/transport.hpp"

#include "core/tls.hpp"
#include "transport/connector.hpp"
#include <array>
#include <boost/asio/buffer.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/ssl/stream_base.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/system/detail/error_code.hpp>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>

namespace sbox {
namespace {

namespace http = beast::http;

struct ParsedUrl {
  std::string host;
  std::string port;
  std::string target;
};

ParsedUrl parse_https_url(std::string_view url) {
  constexpr std::string_view prefix = "https://";
  if (!url.starts_with(prefix)) {
    throw std::runtime_error("DoH URL must start with https://");
  }

  url.remove_prefix(prefix.size());

  const auto slash = url.find('/');
  const auto authority =
      slash == std::string_view::npos ? url : url.substr(0, slash);
  const auto target = slash == std::string_view::npos
                          ? std::string("/")
                          : std::string(url.substr(slash));

  if (authority.empty()) {
    throw std::runtime_error("DoH URL missing host");
  }

  const auto colon = authority.find(':');
  if (colon != std::string_view::npos) {
    return {std::string(authority.substr(0, colon)),
            std::string(authority.substr(colon + 1)), target};
  }

  return {std::string(authority), "443", target};
}

Bytes add_tcp_length(std::span<const std::uint8_t> message) {
  if (message.size() > 0xffff) {
    throw std::runtime_error("dns message too large");
  }

  Bytes framed;
  framed.reserve(message.size() + 2);
  framed.push_back(static_cast<std::uint8_t>(message.size() >> 8));
  framed.push_back(static_cast<std::uint8_t>(message.size() & 0xff));
  framed.insert(framed.end(), message.begin(), message.end());
  return framed;
}

std::uint16_t read_tcp_length(const std::array<std::uint8_t, 2> &bytes) {
  return static_cast<std::uint16_t>((bytes[0] << 8) | bytes[1]);
}

bool is_ip_literal(std::string_view host) {
  boost::system::error_code ec;
  asio::ip::make_address(host, ec);
  return !ec;
}

asio::ip::address parse_ip(std::string_view ip) {
  boost::system::error_code ec;
  auto address = asio::ip::make_address(ip, ec);
  if (ec) {
    throw std::runtime_error("expected IP address, got domain name: " +
                             std::string(ip));
  }

  return address;
}

asio::awaitable<Bytes> query_udp_ip_only_raw(Bytes message,
                                             std::string_view server_ip,
                                             int port) {
  auto executor = co_await asio::this_coro::executor;
  udp::socket socket(executor);

  const auto endpoint =
      udp::endpoint(parse_ip(server_ip), static_cast<unsigned short>(port));

  socket.open(endpoint.protocol());
  co_await socket.async_send_to(asio::buffer(message), endpoint,
                                asio::use_awaitable);

  Bytes response(4096);
  udp::endpoint sender;
  const auto size = co_await socket.async_receive_from(
      asio::buffer(response), sender, asio::use_awaitable);

  response.resize(size);
  co_return response;
}

asio::awaitable<std::string>
resolve_host_with_bootstrap(std::string_view host,
                            std::string_view bootstrap_server,
                            int bootstrap_port) {
  if (is_ip_literal(host)) {
    co_return std::string(host);
  }

  if (!is_ip_literal(bootstrap_server)) {
    throw std::runtime_error("bootstrap DNS must be an IP address");
  }

  auto query = build_query(host, QueryType::A);
  auto response = co_await query_udp_ip_only_raw(std::move(query),
                                                 bootstrap_server,
                                                 bootstrap_port);

  for (const auto &record : parse_response(response)) {
    if (record.type == QueryType::A && !record.value.empty()) {
      co_return record.value;
    }
  }

  throw std::runtime_error("failed to resolve host via bootstrap DNS: " +
                           std::string(host));
}

asio::awaitable<std::string>
resolve_dns_server_ip(const std::string &server,
                      std::string_view bootstrap_server,
                      int bootstrap_port) {
  co_return co_await resolve_host_with_bootstrap(server, bootstrap_server,
                                                 bootstrap_port);
}

} // namespace

asio::awaitable<Bytes>
async_query_udp(Connector &connector, Bytes message, const std::string &server,
                int port, std::string_view bootstrap_server,
                int bootstrap_port) {
  const auto server_ip =
      co_await resolve_dns_server_ip(server, bootstrap_server, bootstrap_port);

  auto executor = co_await asio::this_coro::executor;
  udp::socket socket(executor);

  co_await connector.connect(
      socket, Destination{.host = Host::parse(server_ip),
                          .port = static_cast<std::uint16_t>(port)});

  co_await socket.async_send(asio::buffer(message), asio::use_awaitable);

  Bytes response(4096);
  const auto size =
      co_await socket.async_receive(asio::buffer(response), asio::use_awaitable);

  response.resize(size);
  co_return response;
}

asio::awaitable<Bytes>
async_query_tcp(Connector &connector, Bytes message, const std::string &server,
                int port, std::string_view bootstrap_server,
                int bootstrap_port) {
  const auto server_ip =
      co_await resolve_dns_server_ip(server, bootstrap_server, bootstrap_port);

  auto executor = co_await asio::this_coro::executor;
  tcp::socket socket(executor);

  co_await connector.connect(
      socket, Destination{.host = Host::parse(server_ip),
                          .port = static_cast<std::uint16_t>(port)});

  auto framed = add_tcp_length(message);
  co_await asio::async_write(socket, asio::buffer(framed), asio::use_awaitable);

  std::array<std::uint8_t, 2> length_bytes{};
  co_await asio::async_read(socket, asio::buffer(length_bytes),
                            asio::use_awaitable);

  Bytes response(read_tcp_length(length_bytes));
  co_await asio::async_read(socket, asio::buffer(response),
                            asio::use_awaitable);

  co_return response;
}

asio::awaitable<Bytes>
async_query_tls(Connector &connector, Bytes message, const std::string &server,
                int port, std::string_view bootstrap_server,
                int bootstrap_port) {
  const auto server_ip =
      co_await resolve_dns_server_ip(server, bootstrap_server, bootstrap_port);

  auto executor = co_await asio::this_coro::executor;

  ssl::context ctx(ssl::context::tls_client);
  tls::configure_client_context(ctx, false);

  ssl::stream<tcp::socket> stream(executor, ctx);
  tls::configure_server_identity(stream, server, false);

  co_await connector.connect(
      stream.next_layer(),
      Destination{.host = Host::parse(server_ip),
                  .port = static_cast<std::uint16_t>(port)});

  co_await stream.async_handshake(ssl::stream_base::client,
                                  asio::use_awaitable);

  auto framed = add_tcp_length(message);
  co_await asio::async_write(stream, asio::buffer(framed), asio::use_awaitable);

  std::array<std::uint8_t, 2> length_bytes{};
  co_await asio::async_read(stream, asio::buffer(length_bytes),
                            asio::use_awaitable);

  Bytes response(read_tcp_length(length_bytes));
  co_await asio::async_read(stream, asio::buffer(response),
                            asio::use_awaitable);

  co_return response;
}

asio::awaitable<Bytes>
async_query_https(Connector &connector, Bytes message,
                  const std::string &doh_url,
                  std::string_view bootstrap_server, int bootstrap_port) {
  const auto url = parse_https_url(doh_url);
  const auto server_ip = co_await resolve_dns_server_ip(
      url.host, bootstrap_server, bootstrap_port);

  auto executor = co_await asio::this_coro::executor;

  ssl::context ctx(ssl::context::tls_client);
  tls::configure_client_context(ctx, false);

  beast::ssl_stream<beast::tcp_stream> stream(executor, ctx);
  tls::configure_server_identity(stream, url.host, false);

  co_await connector.connect(
      beast::get_lowest_layer(stream).socket(),
      Destination{.host = Host::parse(server_ip),
                  .port = static_cast<std::uint16_t>(std::stoi(url.port))});

  co_await stream.async_handshake(ssl::stream_base::client,
                                  asio::use_awaitable);

  http::request<http::vector_body<std::uint8_t>> req{http::verb::post,
                                                     url.target, 11};
  req.set(http::field::host, url.host);
  req.set(http::field::user_agent, "sbox-cpp/0.1");
  req.set(http::field::content_type, "application/dns-message");
  req.set(http::field::accept, "application/dns-message");
  req.body() = std::move(message);
  req.prepare_payload();

  co_await http::async_write(stream, req, asio::use_awaitable);

  beast::flat_buffer buffer;
  http::response<http::vector_body<std::uint8_t>> res;
  co_await http::async_read(stream, buffer, res, asio::use_awaitable);

  boost::system::error_code ignored;
  co_await stream.async_shutdown(
      asio::redirect_error(asio::use_awaitable, ignored));

  if (res.result() != http::status::ok) {
    throw std::runtime_error("DoH server returned HTTP " +
                             std::to_string(res.result_int()));
  }

  co_return std::move(res.body());
}

} // namespace sbox