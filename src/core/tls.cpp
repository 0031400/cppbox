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
#ifdef _WIN32
X509_STORE *system_root_store() {
  static std::once_flag once;
  static X509_STORE *store = nullptr;

  std::call_once(once, [] {
    store = X509_STORE_new();
    if (!store) {
      throw std::runtime_error("failed to create OpenSSL certificate store");
    }

    HCERTSTORE cert_store = CertOpenSystemStore(0, "ROOT");
    if (!cert_store) {
      X509_STORE_free(store);
      store = nullptr;
      throw std::runtime_error("failed to open Windows ROOT certificate store");
    }

    PCCERT_CONTEXT cert_context = nullptr;
    while ((cert_context = CertEnumCertificatesInStore(
                cert_store, cert_context)) != nullptr) {
      const unsigned char *encoded = cert_context->pbCertEncoded;
      X509 *cert = d2i_X509(nullptr, &encoded, cert_context->cbCertEncoded);
      if (!cert) {
        continue;
      }

      if (X509_STORE_add_cert(store, cert) != 1) {
        const auto error = ERR_peek_last_error();
        if (ERR_GET_REASON(error) == X509_R_CERT_ALREADY_IN_HASH_TABLE) {
          ERR_clear_error();
        }
      }

      X509_free(cert);
    }

    CertCloseStore(cert_store, 0);
  });

  return store;
}
#endif
void load_system_root_certificates(ssl::context &context) {
#ifdef _WIN32
  X509_STORE *store = system_root_store();
  if (X509_STORE_up_ref(store) != 1) {
    throw std::runtime_error("failed to retain OpenSSL certificate store");
  }

  SSL_CTX_set_cert_store(context.native_handle(), store);
#else
  context.set_default_verify_paths();
#endif
}

} // namespace

void configure_tls_context(ssl::context &context, bool insecure) {
  load_system_root_certificates(context);
  context.set_verify_mode(insecure ? ssl::verify_none : ssl::verify_peer);
}

} // namespace sbox::tls