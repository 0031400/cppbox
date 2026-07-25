#include "transport.hpp"
#include "dns_message.hpp"
#include <array>
#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/impl/write.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/ssl/stream_base.hpp>
#include <boost/asio/ssl/verify_mode.hpp>
#include <boost/beast.hpp>
#include <boost/beast/core/error.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/core/stream_traits.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/http/field.hpp>
#include <boost/beast/http/impl/write.hpp>
#include <boost/beast/http/message_fwd.hpp>
#include <boost/beast/http/status.hpp>
#include <boost/beast/http/vector_body.hpp>
#include <boost/beast/http/verb.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/system/detail/error_code.hpp>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509err.h>
#include <string>
#include <string_view>
#ifdef _WIN32
#include <wincrypt.h>
#include <windows.h>

#endif

namespace dns_one {
namespace {
namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace ssl = asio::ssl;
using tcp = asio::ip::tcp;
using udp = asio::ip::udp;
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
  if (message.size() > 0xffff)

  {
    throw std::runtime_error("dns message too large");
  }
  Bytes framed;
  framed.reserve(message.size() + 1);
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

udp::endpoint make_udp_endpoint(std::string_view ip, int port) {
  return udp::endpoint(parse_ip(ip), static_cast<unsigned short>(port));
}
tcp::endpoint make_tcp_endpoint(std::string_view ip, int port) {
  return tcp::endpoint(parse_ip(ip), static_cast<unsigned short>(port));
}
Bytes query_udp_ip_only(std::span<const std::uint8_t> message,
                        std::string_view server_ip, int port) {
  asio::io_context io;
  udp::socket socket(io);
  const auto endpoint = make_udp_endpoint(server_ip, port);
  socket.open(endpoint.protocol());
  socket.send_to(asio::buffer(message), endpoint);
  Bytes response(4096);
  udp ::endpoint sender;
  const auto size = socket.receive_from(asio::buffer(response), sender);
  response.resize(size);
  return response;
}
std::string resolve_host_with_dns(std::string_view host,
                                  std::string_view bootstrap_server) {
  if (is_ip_literal(host)) {
    return std::string(host);
  }
  const auto query = build_query(host, QueryType::A);
  const auto response = query_udp_ip_only(query, bootstrap_server, 53);
  const auto records = parse_response(response);
  for (const auto &record : records) {
    if (record.type == QueryType::A && !record.value.empty())
      return record.value;
  }
  throw std::runtime_error("failed to resolve host via bootstrap DNS: " +
                           std::string(host));
}
void load_system_root_certificates(ssl::context &ctx) {
#ifdef _WIN32
  HCERTSTORE cert_store = CertOpenSystemStore(0, "ROOT");
  if (!cert_store) {
    throw std::runtime_error("failed to open Windows ROOT certificate store");
  }
  X509_STORE *x509_store = SSL_CTX_get_cert_store(ctx.native_handle());
  if (!x509_store) {
    CertCloseStore(cert_store, 0);
    throw std::runtime_error("failed to get OpenSSL certificate store");
  }
  PCCERT_CONTEXT cert_context = nullptr;
  while ((cert_context = CertEnumCertificatesInStore(
              cert_store, cert_context)) != nullptr) {
    const unsigned char *encoded = cert_context->pbCertEncoded;
    X509 *cert = d2i_X509(nullptr, &encoded, cert_context->cbCertEncoded);
    if (!cert) {
      continue;
    }
    if (X509_STORE_add_cert(x509_store, cert) != 1) {
      const auto err = ERR_peek_last_error();
      if (ERR_GET_REASON(err) == X509_R_CERT_ALREADY_IN_HASH_TABLE)
        ERR_clear_error();
    }
    X509_free(cert);
  }
  CertCloseStore(cert_store, 0);
#else
  ctx.set_default_verify_paths();
#endif
}
}; // namespace

Protocol parse_protocol(std::string_view text) {
  if (text == "udp") {
    return Protocol::Udp;
  }
  if (text == "tcp") {
    return Protocol::Tcp;
  }
  if (text == "tls" || text == "dot") {
    return Protocol::Tls;
  }
  if (text == "https" || text == "doh") {
    return Protocol::Https;
  }
  throw std::runtime_error("protocol must be udp, tcp, tls, or https");
}
Bytes query_udp(std::span<const std::uint8_t> message,
                const std::string &server, int port,
                std::string_view bootstrap_server) {
  const auto server_ip = resolve_host_with_dns(server, bootstrap_server);
  return query_udp_ip_only(message, server_ip, port);
}

Bytes query_tcp(std::span<const std::uint8_t> message,
                const std::string &server, int port,
                std::string_view bootstrap_server) {
  const auto server_ip = resolve_host_with_dns(server, bootstrap_server);
  asio::io_context io;
  tcp::socket socket(io);
  socket.connect(make_tcp_endpoint(server_ip, port));
  const auto framed = add_tcp_length(message);
  asio::write(socket, asio::buffer(framed));
  std::array<std::uint8_t, 2> length_bytes;
  asio::read(socket, asio::buffer(length_bytes));
  Bytes response(read_tcp_length(length_bytes));
  asio::read(socket, asio::buffer(response));
  return response;
}
Bytes query_tls(std::span<const std::uint8_t> message,
                const std::string &server, int port,
                std::string_view bootstrap_server) {
  asio::io_context io;
  ssl::context ctx(ssl::context::tls_client);
  load_system_root_certificates(ctx);
  ssl::stream<tcp::socket> stream(io, ctx);
  stream.set_verify_mode(ssl::verify_peer);
  stream.set_verify_callback(ssl::host_name_verification(server));
  if (!SSL_set_tlsext_host_name(stream.native_handle(), server.c_str())) {
    throw beast::system_error(beast::error_code(
        static_cast<int>(::ERR_get_error()), asio::error::get_ssl_category())

    );
  }
  const auto server_ip = resolve_host_with_dns(server, bootstrap_server);
  stream.next_layer().connect(make_tcp_endpoint(server_ip, port));
  stream.handshake(ssl::stream_base::client);
  const auto framed = add_tcp_length(message);
  asio::write(stream, asio::buffer(framed));
  std::array<std::uint8_t, 2> length_bytes;
  asio::read(stream, asio::buffer(length_bytes));
  Bytes response(read_tcp_length(length_bytes));
  asio::read(stream, asio::buffer(response));
  return response;
}
Bytes query_https(std::span<const std::uint8_t> message,
                  const std::string &doh_url,
                  std::string_view bootstrap_server) {
  const auto url = parse_https_url(doh_url);
  asio::io_context io;
  ssl::context ctx(ssl::context::tls_client);
  load_system_root_certificates(ctx);
  beast::ssl_stream<beast::tcp_stream> stream(io, ctx);
  stream.set_verify_mode(ssl::verify_peer);
  stream.set_verify_callback(ssl::host_name_verification(url.host));
  if (!SSL_set_tlsext_host_name(stream.native_handle(), url.host.c_str())) {
    throw beast::system_error(beast::error_code(
        static_cast<int>(::ERR_get_error()), asio::error::get_ssl_category())

    );
  }
  const auto server_ip = resolve_host_with_dns(url.host, bootstrap_server);
  beast::get_lowest_layer(stream).connect(
      make_tcp_endpoint(server_ip, std::stoi(url.port)));
  stream.handshake(ssl::stream_base::client);
  http::request<http::vector_body<std::uint8_t>> req{http::verb::post,
                                                     url.target, 11};
  req.set(http::field::host, url.host);
  req.set(http::field::user_agent,
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36");
  req.set(http::field::content_type, "application/dns-message");
  req.set(http::field::accept, "application/dns-message");
  req.body().assign(message.begin(), message.end());
  req.prepare_payload();
  http::write(stream, req);
  beast::flat_buffer buffer;
  http::response<http::vector_body<std::uint8_t>> res;
  http::read(stream, buffer, res);
  beast::error_code ec;
  ec = stream.shutdown(ec);
  if (res.result() != http::status::ok) {
    throw std::runtime_error("DoH server returned HTTP " +
                             std::to_string(res.result_int()));
  }
  return std::move(res.body());
}
}; // namespace dns_one