#include "protocol/http_proxy.hpp"
#include "core/utils.hpp"
#include "http_proxy.hpp"
#include <algorithm>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <cctype>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace sbox::http_proxy {
namespace {

Destination parse_connect_target(const std::string &target) {
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

Destination parse_http_absolute_target(const std::string &target) {
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

std::vector<unsigned char> build_initial_payload(const std::string &header,
                                                 std::size_t header_size,
                                                 const std::string &method,
                                                 const std::string &target,
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
}; // namespace
asio::awaitable<Session> read_session(tcp::socket &socket) {
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
    co_await write_success_reply(socket);
    co_return Session{std::move(dst), {}};
  }
  Destination dst = parse_http_absolute_target(target);
  auto payload =
      build_initial_payload(header, header_size, method, target, version);
  co_return Session{std::move(dst), std::move(payload)};
}

asio::awaitable<void> write_success_reply(tcp::socket &socket) {
  static constexpr std::string_view reply =
      "HTTP/1.1 200 Connection Established\r\n"
      "Proxy-Agent: sbox-cpp/0.1\r\n"
      "\r\n";
  co_await asio::async_write(socket, asio::buffer(reply), asio::use_awaitable);
}
} // namespace sbox::http_proxy