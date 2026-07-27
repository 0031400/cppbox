#include "dns/dns.hpp"
#include "core/net.hpp"
#include "core/tls.hpp"
#include "core/utils.hpp"
#include "route/router.hpp"
#include "transport/connector.hpp"
#include <array>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/ssl/stream_base.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/system/detail/error_code.hpp>
#include <cctype>
#include <exception>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>

namespace cppbox {

namespace {

namespace http = beast::http;

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

std::string normalize_domain(std::string_view domain) {
  std::string result;
  result.reserve(domain.size());

  for (const auto ch : domain) {
    result.push_back(
        static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
  }

  while (!result.empty() && result.back() == '.') {
    result.pop_back();
  }

  return result;
}

} // namespace

DnsServer::DnsServer(const DnsConfig &config, Router &router)
    : config_(config), router_(router) {
  if (config_.servers.empty()) {
    throw std::runtime_error("dns.servers must not be empty");
  }

  for (const auto &server : config_.servers) {
    if (server.tag.empty()) {
      throw std::runtime_error("dns server tag must not be empty");
    }

    if (!is_ip_literal(server.server)) {
      throw std::runtime_error("dns server must be an IP address: " +
                               server.tag);
    }

    if (server.server_port == 0) {
      throw std::runtime_error("dns server port must not be zero: " +
                               server.tag);
    }

    if (server.type != "udp" && server.type != "tcp" && server.type != "tls" &&
        server.type != "https") {
      throw std::runtime_error("unsupported DNS server type: " + server.type);
    }

    if ((server.type == "udp" || server.type == "tcp") &&
        !server.server_name.empty()) {
      throw std::runtime_error(
          "udp/tcp DNS server must not specify server_name: " + server.tag);
    }

    if ((server.type == "tls" || server.type == "https") &&
        server.server_name.empty()) {
      throw std::runtime_error("tls/https DNS server requires server_name: " +
                               server.tag);
    }

    if (server.type == "https" &&
        (server.path.empty() || !server.path.starts_with('/'))) {
      throw std::runtime_error("https DNS server path must start with /: " +
                               server.tag);
    }

    if (!nameservers_.emplace(server.tag, &server).second) {
      throw std::runtime_error("duplicate DNS server tag: " + server.tag);
    }
  }

  static_cast<void>(find_nameserver(config_.final));
  for (const auto &rule : config_.rules) {
    if (!rule.rule_set.empty() && !rule.domain.empty() &&
        !rule.domain_suffix.empty() && !rule.domain_keyword.empty()) {
      throw std::runtime_error("dns rule must not be null");
    }

    static_cast<void>(find_nameserver(rule.server));
  }
}

void DnsServer::set_connector(Connector &connector) { connector_ = &connector; }

const DnsItemConfig &DnsServer::find_nameserver(std::string_view tag) const {
  const auto it = nameservers_.find(std::string(tag));
  if (it == nameservers_.end()) {
    throw std::runtime_error("unknown DNS server tag: " + std::string(tag));
  }

  return *it->second;
}

bool DnsServer::match_rule(const DnsRouteRuleConfig &rule,
                           std::string_view domain) const {
  for (const auto &item : rule.domain) {
    if (domain == normalize_domain(item)) {
      return true;
    }
  }

  for (const auto &item : rule.domain_suffix) {
    const auto suffix = normalize_domain(item);
    if (suffix.empty()) {
      continue;
    }

    if (suffix.front() == '.') {
      if (domain.ends_with(suffix)) {
        return true;
      }
      continue;
    }

    if (domain == suffix || domain.ends_with("." + suffix)) {
      return true;
    }
  }

  for (const auto &item : rule.domain_keyword) {
    const auto keyword = normalize_domain(item);
    if (!keyword.empty() && domain.find(keyword) != std::string_view::npos) {
      return true;
    }
  }
  const Destination destination{
      .host = Host::domain(std::string(domain)),
      .port = 0,
  };

  for (const auto &tag : rule.rule_set) {
    if (router_.match_rule_set(tag, destination)) {
      return true;
    }
  }
  return false;
}

const DnsItemConfig &DnsServer::pick_nameserver(std::string_view domain) const {
  const auto normalized_domain = normalize_domain(domain);

  for (const auto &rule : config_.rules) {
    if (match_rule(rule, normalized_domain)) {
      return find_nameserver(rule.server);
    }
  }

  return find_nameserver(config_.final);
}
std::string DnsServer::pick_nameserver_tag(std::string_view domain) const {
  return pick_nameserver(domain).tag;
}
asio::awaitable<Bytes> DnsServer::query(Bytes request) {
  if (!connector_) {
    throw std::runtime_error("DNS connector is not configured");
  }

  const auto question = parse_question(request);
  const auto &nameserver = pick_nameserver(question.name);

  co_return co_await query_dns(nameserver, std::move(request));
}

asio::awaitable<Bytes> DnsServer::query_dns(const DnsItemConfig &nameserver,
                                            Bytes message) {
  if (nameserver.type == "udp") {
    co_return co_await async_query_udp(nameserver, std::move(message));
  }

  if (nameserver.type == "tcp") {
    co_return co_await async_query_tcp(nameserver, std::move(message));
  }

  if (nameserver.type == "tls") {
    co_return co_await async_query_tls(nameserver, std::move(message));
  }

  if (nameserver.type == "https") {
    co_return co_await async_query_https(nameserver, std::move(message));
  }

  throw std::runtime_error("unsupported DNS type: " + nameserver.type);
}

asio::awaitable<Bytes>
DnsServer::async_query_udp(const DnsItemConfig &nameserver, Bytes message) {
  auto executor = co_await asio::this_coro::executor;
  udp::socket socket(executor);

  co_await connector_->connect(
      socket, Destination{.host = Host::parse(nameserver.server),
                          .port = nameserver.server_port});

  co_await socket.async_send(asio::buffer(message), asio::use_awaitable);

  Bytes response(4096);
  const auto size = co_await socket.async_receive(asio::buffer(response),
                                                  asio::use_awaitable);
  response.resize(size);

  co_return response;
}

asio::awaitable<Bytes>
DnsServer::async_query_tcp(const DnsItemConfig &nameserver, Bytes message) {
  auto executor = co_await asio::this_coro::executor;
  tcp::socket socket(executor);

  co_await connector_->connect(
      socket, Destination{.host = Host::parse(nameserver.server),
                          .port = nameserver.server_port});

  auto framed = add_tcp_length(message);
  co_await asio::async_write(socket, asio::buffer(framed), asio::use_awaitable);

  std::array<std::uint8_t, 2> length_bytes{};
  co_await asio::async_read(socket, asio::buffer(length_bytes),
                            asio::use_awaitable);

  Bytes response(read_be16(length_bytes.data()));
  co_await asio::async_read(socket, asio::buffer(response),
                            asio::use_awaitable);

  co_return response;
}

asio::awaitable<Bytes>
DnsServer::async_query_tls(const DnsItemConfig &nameserver, Bytes message) {
  auto executor = co_await asio::this_coro::executor;

  ssl::context ctx(ssl::context::tls_client);
  tls::configure_tls_context(ctx, false);

  ssl::stream<tcp::socket> stream(executor, ctx);
  tls::configure_tls_stream_identity(stream, nameserver.server_name, false);

  co_await connector_->connect(
      stream.next_layer(), Destination{.host = Host::parse(nameserver.server),
                                       .port = nameserver.server_port});

  co_await stream.async_handshake(ssl::stream_base::client,
                                  asio::use_awaitable);

  auto framed = add_tcp_length(message);
  co_await asio::async_write(stream, asio::buffer(framed), asio::use_awaitable);

  std::array<std::uint8_t, 2> length_bytes{};
  co_await asio::async_read(stream, asio::buffer(length_bytes),
                            asio::use_awaitable);

  Bytes response(read_be16(length_bytes.data()));
  co_await asio::async_read(stream, asio::buffer(response),
                            asio::use_awaitable);

  co_return response;
}

asio::awaitable<Bytes>
DnsServer::async_query_https(const DnsItemConfig &nameserver, Bytes message) {
  auto executor = co_await asio::this_coro::executor;

  ssl::context ctx(ssl::context::tls_client);
  tls::configure_tls_context(ctx, false);

  beast::ssl_stream<beast::tcp_stream> stream(executor, ctx);
  tls::configure_tls_stream_identity(stream, nameserver.server_name, false);

  co_await connector_->connect(
      beast::get_lowest_layer(stream).socket(),
      Destination{.host = Host::parse(nameserver.server),
                  .port = nameserver.server_port});

  co_await stream.async_handshake(ssl::stream_base::client,
                                  asio::use_awaitable);

  std::string host_header = nameserver.server_name;
  if (nameserver.server_port != 443) {
    host_header += ":" + std::to_string(nameserver.server_port);
  }

  http::request<http::vector_body<std::uint8_t>> req{http::verb::post,
                                                     nameserver.path, 11};
  req.set(http::field::host, host_header);
  req.set(http::field::user_agent, "cppbox-cpp/0.1");
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

asio::awaitable<std::vector<ip::address>>
DnsServer::resolve(const DomainName &domain) {
  std::vector<ip::address> output;
  std::exception_ptr last_error;

  for (const auto type : {QueryType::A, QueryType::AAAA}) {
    try {
      const auto response = co_await query(build_query(domain.value(), type));

      for (const auto &record : parse_response(response)) {
        if (record.type != QueryType::A && record.type != QueryType::AAAA) {
          continue;
        }

        boost::system::error_code ec;
        auto address = ip::make_address(record.value, ec);
        if (!ec) {
          output.push_back(address);
        }
      }
    } catch (...) {
      last_error = std::current_exception();
    }
  }

  if (!output.empty()) {
    co_return output;
  }

  if (last_error) {
    std::rethrow_exception(last_error);
  }

  throw std::runtime_error("DNS returned no address for " + domain.value());
}

} // namespace cppbox