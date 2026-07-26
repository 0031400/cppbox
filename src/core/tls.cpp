#include "core/tls.hpp"

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509err.h>
#include <stdexcept>

#ifdef _WIN32
#include <wincrypt.h>
#include <windows.h>
#endif

namespace sbox::tls {
namespace {

void load_system_root_certificates(ssl::context &context) {
#ifdef _WIN32
  HCERTSTORE cert_store = CertOpenSystemStore(0, "ROOT");
  if (!cert_store) {
    throw std::runtime_error("failed to open Windows ROOT certificate store");
  }

  X509_STORE *x509_store = SSL_CTX_get_cert_store(context.native_handle());
  if (!x509_store) {
    CertCloseStore(cert_store, 0);
    throw std::runtime_error("failed to get OpenSSL certificate store");
  }

  PCCERT_CONTEXT cert_context = nullptr;
  while ((cert_context =
              CertEnumCertificatesInStore(cert_store, cert_context)) != nullptr) {
    const unsigned char *encoded = cert_context->pbCertEncoded;
    X509 *cert = d2i_X509(nullptr, &encoded, cert_context->cbCertEncoded);
    if (!cert) {
      continue;
    }

    if (X509_STORE_add_cert(x509_store, cert) != 1) {
      const auto err = ERR_peek_last_error();
      if (ERR_GET_REASON(err) == X509_R_CERT_ALREADY_IN_HASH_TABLE) {
        ERR_clear_error();
      }
    }

    X509_free(cert);
  }

  CertCloseStore(cert_store, 0);
#else
  context.set_default_verify_paths();
#endif
}

} // namespace

void configure_client_context(ssl::context &context, bool insecure) {
  load_system_root_certificates(context);
  context.set_verify_mode(insecure ? ssl::verify_none : ssl::verify_peer);
}

} // namespace sbox::tls