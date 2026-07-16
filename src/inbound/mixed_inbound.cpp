#include "inbound/mixed_inbound.hpp"
#include "core/session.hpp"
#include "core/utils.hpp"
#include <algorithm>
#include <array>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <cctype>
#include <exception>
#include <core/log.hpp>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
namespace sbox {
MixedInbound::MixedInbound(asio::io_context &io, tcp::endpoint endpoint,
                           Handler handler)
    : acceptor_(io, endpoint), handler_(std::move(handler)) {}
asio::awaitable<void> MixedInbound::start() {
  for (;;) {
    tcp::socket socket = co_await acceptor_.async_accept(asio::use_awaitable);
    asio::co_spawn(acceptor_.get_executor(), handle_client(std::move(socket)),
                   asio::detached);
  }
}
asio::awaitable<void> MixedInbound::handle_client(tcp::socket socket) {
  try {
    std::array<unsigned char, 1> first{};
    co_await socket.async_receive(
        asio::buffer(first), tcp::socket::message_peek, asio::use_awaitable);
    Session session;
    if (first[0] == 0x05) {
      session = co_await read_socks5_session(socket);
    } else {
      session = co_await read_http_session(socket);
    }
    co_await handler_(std::move(socket), std::move(session));
  } catch (const std::exception &e) {
    log_error(std::string("[mixed] ") + e.what());
    close_socket(socket);
  }
}
asio::awaitable<Session>
MixedInbound::read_socks5_session(tcp::socket &socket) {
  std::array<unsigned char, 2> greeting{};
  co_await asio::async_read(socket, asio::buffer(greeting),
                            asio::use_awaitable);
  require(greeting[0] == 0x05, "invalid socks version");

  require(greeting[1] > 0, "empty socks method list");
  std::vector<unsigned char> methods(greeting[1]);
  co_await asio::async_read(socket, asio::buffer(methods), asio::use_awaitable);
  bool no_auth =
      std::find(methods.begin(), methods.end(), 0x00) != methods.end();
  std::array<unsigned char, 2> method_reply{
      0x05, static_cast<unsigned char>(no_auth ? 0x00 : 0xff)};
  co_await asio::async_write(socket, asio::buffer(method_reply),
                             asio::use_awaitable);
  require(no_auth, "socks no-auth method not supported by client");
  std::array<unsigned char, 4> header{};
  co_await asio::async_read(socket, asio::buffer(header), asio::use_awaitable);
  require(header[0] == 0x05, "invalid socks request version");
  require(header[1] == 0x01, "only socks CONNECT is supported");
  require(header[2] == 0x00, "invalid socks reserved byte");
  Destination dst;
  dst.type = parse_socks_address_type(header[3]);
  dst.host = co_await read_socks_address(socket, dst.type);
  std::array<unsigned char, 2> port{};
  co_await asio::async_read(socket, asio::buffer(port), asio::use_awaitable);
  dst.port = read_be16(port.data());
  co_await write_socks_success_reply(socket);
  co_return Session(std::move(dst));
}

asio::awaitable<Session> MixedInbound::read_http_session(tcp::socket &socket) {
  std::string header;
  auto header_size = co_await asio::async_read_until(
      socket, asio::dynamic_buffer(header), "\r\n\r\n", asio::use_awaitable);
  auto line_end = header.find("\r\n");
  require(line_end != std::string::npos, "invalid http proxy request");
  std::string request_line = header.substr(0, line_end);
  std::istringstream iss(request_line);
  std::string method;
  std::string target;
  std::string version;
  iss >> method >> target >> version;
  require(!method.empty(), "empty http method");
  require(!target.empty(), "empty http CONNECT target");
  require(version.rfind("HTTP/", 0) == 0, "invalid http version");
  if (method == "CONNECT") {
    Destination dst = parse_connect_target(target);
    co_await write_http_success_reply(socket);
    co_return Session{std::move(dst), {}};
  }
  Destination dst = parse_http_absolute_target(target);
  auto payload =
      build_http_initial_payload(header, header_size, method, target, version);
  co_return Session{std::move(dst), std::move(payload)};
}
AddressType MixedInbound::parse_socks_address_type(unsigned char atyp) {
  switch (atyp) {
  case 0x01:
    return AddressType::IPv4;
  case 0x03:
    return AddressType::Domain;
  case 0x04:
    return AddressType::IPv6;
  default:
    throw std::runtime_error("unsupported socks address type");
  }
}
asio::awaitable<std::string>
MixedInbound::read_socks_address(tcp::socket &socket, AddressType type) {
  if (type == AddressType::IPv4) {
    std::array<unsigned char, 4> raw{};
    co_await asio::async_read(socket, asio::buffer(raw), asio::use_awaitable);
    asio::ip::address_v4::bytes_type bytes{raw[0], raw[1], raw[2], raw[3]};
    co_return asio::ip::address_v4(bytes).to_string();
  }
  if (type == AddressType::IPv6) {
    std::array<unsigned char, 16> raw{};
    co_await asio::async_read(socket, asio::buffer(raw), asio::use_awaitable);
    asio::ip::address_v6::bytes_type bytes{};
    std::copy(raw.begin(), raw.end(), bytes.begin());
    co_return asio::ip::address_v6(bytes).to_string();
  }
  std::array<unsigned char, 1> len{};
  co_await asio::async_read(socket, asio::buffer(len), asio::use_awaitable);
  require(len[0] > 0, "empty socks domain");
  std::vector<unsigned char> domain(len[0]);
  co_await asio::async_read(socket, asio::buffer(domain), asio::use_awaitable);
  co_return std::string(domain.begin(), domain.end());
}
Destination MixedInbound::parse_connect_target(const std::string &target) {
  Destination dst;
  if (!target.empty() && target.front() == '[') {
    auto close = target.find(']');
    require(close != std::string::npos, "invalid ipv6 CONNECT target");
    require(close + 1 < target.size() && target[close + 1] == ':',
            "missing ipv6 CONNECT port");
    dst.type = AddressType::IPv6;
    dst.host = target.substr(1, close - 1);
    dst.port = static_cast<std::uint16_t>(std::stoi(target.substr(close + 2)));
    return dst;
  }
  auto colon = target.rfind(':');
  require(colon != std::string::npos, "missing CONNECT port");

  dst.host = target.substr(0, colon);
  dst.port = static_cast<std::uint16_t>(std::stoi(target.substr(colon + 1)));
  error_code ec;
  auto address = asio::ip::make_address(dst.host, ec);
  if (!ec && address.is_v4()) {
    dst.type = AddressType::IPv4;
  } else if (!ec && address.is_v6()) {
    dst.type = AddressType::IPv6;
  } else {
    dst.type = AddressType::Domain;
  }
  require(!dst.host.empty(), "empty CONNECT host");
  require(dst.port != 0, "invalid CONNECT port");
  return dst;
}
std::string MixedInbound::trim(std::string text) {
  auto not_space = [](unsigned char c) { return !std::isspace(c); };
  text.erase(text.begin(), std::find_if(text.begin(), text.end(), not_space));
  text.erase(std::find_if(text.rbegin(), text.rend(), not_space).base(),
             text.end());
  return text;
}
asio::awaitable<void>
MixedInbound::write_socks_success_reply(tcp::socket &socket) {
  std::array<unsigned char, 10> reply{
      0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  co_await asio::async_write(socket, asio::buffer(reply), asio::use_awaitable);
}
asio::awaitable<void>
MixedInbound::write_http_success_reply(tcp::socket &socket) {
  static constexpr std::string_view reply =
      "HTTP/1.1 200 Connection Established\r\n"
      "Proxy-Agent: sbox-cpp/0.1\r\n"
      "\r\n";
  co_await asio::async_write(socket, asio::buffer(reply), asio::use_awaitable);
}
asio::awaitable<void>
MixedInbound::write_http_error_reply(tcp::socket &socket, int code,
                                     const std::string &text) {
  std::string reply = "HTTP/1.1 " + std::to_string(code) + " " + text +
                      "\r\n"
                      "Connection: close\r\n"
                      "Content-Length: 0\r\n"
                      "\r\n";
  co_await asio::async_write(socket, asio::buffer(reply), asio::use_awaitable);
}
Destination
MixedInbound::parse_http_absolute_target(const std::string &target) {
  constexpr std::string_view prefix = "http://";
  require(target.rfind(prefix, 0) == 0,
          "only absolute-form request is supported");
  std::string rest = target.substr(prefix.size());
  auto slash = rest.find('/');
  std::string authority =
      slash == std::string::npos ? rest : rest.substr(0, slash);
  require(!authority.empty(), "empty http authority");
  Destination dst;
  auto colon = authority.rfind(':');
  if (colon != std::string ::npos) {
    dst.host = authority.substr(0, colon);
    dst.port =
        static_cast<std::uint16_t>(std::stoi(authority.substr(colon + 1)));
  } else {
    dst.host = authority;
    dst.port = 80;
  }
  error_code ec;
  auto address = asio::ip::make_address(dst.host, ec);
  if (!ec && address.is_v4()) {
    dst.type = AddressType::IPv4;
  } else if (!ec && address.is_v6()) {
    dst.type = AddressType::IPv6;
  } else {
    dst.type = AddressType::Domain;
  }
  require(!dst.host.empty(), "empty http host");
  require(dst.port != 0, "invalid http port");
  return dst;
}
std::vector<unsigned char> MixedInbound::build_http_initial_payload(
    const std::string &header, std::size_t header_size,
    const std::string &method, const std::string &target,
    const std::string &version) {
  constexpr std::string_view prefix = "http://";
  std::string rest = target.substr(prefix.size());
  auto slash = rest.find('/');
  std::string path = slash == std::string::npos ? "/" : rest.substr(slash);
  if (path.empty()) {
    path = "/";
  }
  std::string rewritten;
  rewritten.reserve(header.size());
  rewritten += method;
  rewritten += ' ';
  rewritten += path;
  rewritten += ' ';
  rewritten += version;
  rewritten += "\r\n";
  auto line_end = header.find("\r\n");
  std::size_t pos = line_end + 2;
  while (pos < header_size) {
    auto next = header.find("\r\n", pos);
    if (next == std::string::npos || next == pos) {
      break;
    }
    std::string line = header.substr(pos, next - pos);
    std::string lower = line;
    std::transform(
        lower.begin(), lower.end(), lower.begin(),
        [](unsigned char c) { return static_cast<char>(tolower(c)); });
    if (lower.rfind("proxy-connection:", 0) != 0 &&
        lower.rfind("proxy-authorization:", 0) != 0) {
      rewritten += line;
      rewritten += "\r\n";
    }
    pos = next + 2;
  }
  rewritten += "\r\n";
  if (header.size() > header_size) {
    rewritten.append(header.data() + header_size, header.size() - header_size);
  }
  return {rewritten.begin(), rewritten.end()};
}
}; // namespace sbox