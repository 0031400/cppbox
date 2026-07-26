#include "dns/dns_inbound.hpp"

#include "core/log.hpp"
#include "dns/dns_message.hpp"
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <charconv>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <sstream>
namespace sbox {
namespace {

using udp = asio::ip::udp;
std::string endpoint_text(const udp::endpoint &endpoint) {
  return endpoint.address().to_string() + ":" + std::to_string(endpoint.port());
}
std::uint16_t parse_port(std::string_view text) {
  unsigned int value{};
  const auto [end, error] =
      std::from_chars(text.data(), text.data() + text.size(), value);

  if (error != std::errc{} || end != text.data() + text.size() ||
      value > 65535) {
    throw std::runtime_error("invalid DNS listen port");
  }

  return static_cast<std::uint16_t>(value);
}

udp::endpoint parse_endpoint(std::string_view listen) {
  std::string_view host;
  std::string_view port;

  if (listen.starts_with('[')) {
    const auto close = listen.find(']');
    if (close == std::string_view::npos || close + 1 >= listen.size() ||
        listen[close + 1] != ':') {
      throw std::runtime_error("dns.listen must be [ipv6]:port");
    }

    host = listen.substr(1, close - 1);
    port = listen.substr(close + 2);
  } else {
    const auto colon = listen.rfind(':');
    if (colon == std::string_view::npos || listen.find(':') != colon) {
      throw std::runtime_error("dns.listen must be ipv4:port or [ipv6]:port");
    }

    host = listen.substr(0, colon);
    port = listen.substr(colon + 1);
  }

  boost::system::error_code error;
  const auto address = asio::ip::make_address(host, error);
  if (error) {
    throw std::runtime_error("invalid DNS listen IP: " + std::string(host));
  }

  return udp::endpoint(address, parse_port(port));
}
std::string ip_list_text(const Bytes &response) {
  std::ostringstream out;
  bool first = true;

  for (const auto &record : parse_response(response)) {
    if (record.type != QueryType::A && record.type != QueryType::AAAA) {
      continue;
    }

    if (!first) {
      out << ", ";
    }

    out << record.value;
    first = false;
  }

  return first ? "<empty>" : out.str();
}
} // namespace

DnsInbound::DnsInbound(asio::io_context &io, std::string listen,
                       DnsServer &dns_server)
    : endpoint_(parse_endpoint(listen)), socket_(io), dns_server_(dns_server) {}

asio::awaitable<void> DnsInbound::start() {
  socket_.open(endpoint_.protocol());
  socket_.set_option(asio::socket_base::reuse_address(true));
  socket_.bind(endpoint_);

  log_info("dns listening on " + endpoint_.address().to_string() + ":" +
           std::to_string(endpoint_.port()));

  try {
    while (!stopping_.load()) {
      Bytes request(65535);
      udp::endpoint client;

      const auto size = co_await socket_.async_receive_from(
          asio::buffer(request), client, asio::use_awaitable);
      request.resize(size);

      asio::co_spawn(socket_.get_executor(),
                     handle_request(std::move(request), client),
                     asio::detached);
    }
  } catch (const boost::system::system_error &e) {
    if (!stopping_.load() && e.code() != asio::error::operation_aborted) {
      log_error(std::string("[dns] receive failed: ") + e.what());
    }
  }
}

asio::awaitable<void> DnsInbound::handle_request(Bytes request,
                                                 udp::endpoint client) {
  try {
    std::string domain = "<unknown>";

    try {
      domain = parse_question(request).name;
    } catch (const std::exception &e) {
      log_error(std::string("[dns] parse question failed: ") + e.what());
    }

    auto response = co_await dns_server_.query(std::move(request));
    const auto ips = ip_list_text(response);

    co_await socket_.async_send_to(asio::buffer(response), client,
                                   asio::use_awaitable);

    log_info("[dns] " + domain + " -> " + ips);
  } catch (const std::exception &e) {
    if (!stopping_.load()) {
      log_error(std::string("[dns] query failed: ") + e.what());
    }
  }
}

void DnsInbound::stop() noexcept {
  if (stopping_.exchange(true)) {
    return;
  }

  error_code ignored;
  socket_.cancel(ignored);
  socket_.close(ignored);
}

} // namespace sbox