#pragma once

#include "core/net.hpp"
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>
#include <boost/system/system_error.hpp>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <string>
#include <string_view>

namespace cppbox::tls {

void configure_tls_context(ssl::context &context, bool insecure);

template <typename SslStream>
void configure_tls_stream_identity(SslStream &stream, std::string_view server_name,
                               bool insecure) {
  const std::string name(server_name);

  if (!SSL_set_tlsext_host_name(stream.native_handle(), name.c_str())) {
    throw boost::system::system_error(
        error_code(static_cast<int>(::ERR_get_error()),
                   asio::error::get_ssl_category()),
        "set TLS SNI");
  }

  if (!insecure) {
    stream.set_verify_callback(ssl::host_name_verification(name));
  }
}

} // namespace cppbox::tls