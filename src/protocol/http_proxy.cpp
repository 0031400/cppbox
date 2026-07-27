#include "protocol/http_proxy.hpp"
#include "core/utils.hpp"
#include <algorithm>
#include <boost/asio/buffer.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <charconv>
#include <cctype>
#include <cstdint>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace cppbox::http_proxy {
namespace {

std::uint16_t parse_port(std::string_view text) {
  require(!text.empty(), "missing port");

  unsigned int value = 0;
  const auto [ptr, ec] =
      std::from_chars(text.data(), text.data() + text.size(), value);

  require(ec == std::errc{} && ptr == text.data() + text.size() &&
              value > 0 && value <= 65535,
          "invalid port");

  return static_cast<std::uint16_t>(value);
}

Destination parse_authority(std::string_view authority,
                            std::uint16_t default_port,
                            bool require_explicit_port) {
  require(!authority.empty(), "empty authority");

  std::string host;
  std::uint16_t port = default_port;

  if (authority.front() == '[') {
    const auto close = authority.find(']');
    require(close != std::string_view::npos, "invalid IPv6 authority");

    host = std::string(authority.substr(1, close - 1));
    const auto suffix = authority.substr(close + 1);

    if (suffix.empty()) {
      require(!require_explicit_port, "missing IPv6 port");
    } else {
      require(suffix.front() == ':', "invalid IPv6 authority");
      port = parse_port(suffix.substr(1));
    }

    return Destination{
        .host = Host::ipv6(host),
        .port = port,
    };
  }

  const auto colon = authority.rfind(':');
  if (colon == std::string_view::npos) {
    require(!require_explicit_port, "missing port");
    host = std::string(authority);
  } else {
    host = std::string(authority.substr(0, colon));
    port = parse_port(authority.substr(colon + 1));

    require(host.find(':') == std::string::npos,
            "IPv6 address must use brackets");
  }

  require(!host.empty(), "empty host");

  return Destination{
      .host = Host::parse(host),
      .port = port,
  };
}

Destination parse_connect_target(const std::string &target) {
  return parse_authority(target, 0, true);
}

Destination parse_http_absolute_target(const std::string &target) {
  constexpr std::string_view prefix = "http://";
  require(target.rfind(prefix, 0) == 0,
          "only absolute-form HTTP requests are supported");

  const std::string_view rest(target.data() + prefix.size(),
                              target.size() - prefix.size());

  const auto slash = rest.find('/');
  const auto authority =
      slash == std::string_view::npos ? rest : rest.substr(0, slash);

  return parse_authority(authority, 80, false);
}

std::vector<unsigned char>
build_initial_payload(const std::string &header, std::size_t header_size,
                      const std::string &method, const std::string &target,
                      const std::string &version) {
  constexpr std::string_view prefix = "http://";

  const std::string_view rest(target.data() + prefix.size(),
                              target.size() - prefix.size());
  const auto slash = rest.find('/');

  std::string path =
      slash == std::string_view::npos ? "/" : std::string(rest.substr(slash));
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

  const auto first_line_end = header.find("\r\n");
  std::size_t pos = first_line_end + 2;

  while (pos < header_size) {
    const auto next = header.find("\r\n", pos);
    if (next == std::string::npos || next == pos) {
      break;
    }

    const std::string line = header.substr(pos, next - pos);
    std::string lower = line;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) {
                     return static_cast<char>(std::tolower(c));
                   });

    if (lower.rfind("proxy-connection:", 0) != 0 &&
        lower.rfind("proxy-authorization:", 0) != 0) {
      rewritten += line;
      rewritten += "\r\n";
    }

    pos = next + 2;
  }

  rewritten += "\r\n";

  if (header.size() > header_size) {
    rewritten.append(header.data() + header_size,
                     header.size() - header_size);
  }

  return {rewritten.begin(), rewritten.end()};
}

} // namespace

asio::awaitable<Session> read_session(tcp::socket &socket) {
  std::string header;
  const auto header_size = co_await asio::async_read_until(
      socket, asio::dynamic_buffer(header), "\r\n\r\n", asio::use_awaitable);

  const auto line_end = header.find("\r\n");
  require(line_end != std::string::npos, "invalid HTTP proxy request");

  const std::string request_line = header.substr(0, line_end);
  std::istringstream stream(request_line);

  std::string method;
  std::string target;
  std::string version;
  stream >> method >> target >> version;

  require(!method.empty(), "empty HTTP method");
  require(!target.empty(), "empty HTTP target");
  require(version.rfind("HTTP/", 0) == 0, "invalid HTTP version");

  if (method == "CONNECT") {
    auto destination = parse_connect_target(target);
    co_await write_success_reply(socket);
    co_return Session{.destination = std::move(destination),
                      .initial_payload = {}};
  }

  auto destination = parse_http_absolute_target(target);
  auto payload =
      build_initial_payload(header, header_size, method, target, version);

  co_return Session{
      .destination = std::move(destination),
      .initial_payload = std::move(payload),
  };
}

asio::awaitable<void> write_success_reply(tcp::socket &socket) {
  static constexpr std::string_view reply =
      "HTTP/1.1 200 Connection Established\r\n"
      "Proxy-Agent: cppbox-cpp/0.1\r\n"
      "\r\n";

  co_await asio::async_write(socket, asio::buffer(reply),
                             asio::use_awaitable);
}

} // namespace cppbox::http_proxy