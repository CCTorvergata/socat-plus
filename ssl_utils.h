#ifndef SSL_UTILS_H
#define SSL_UTILS_H

#include <openssl/ssl.h>

SSL_CTX *init_tls_context(void);
SSL_CTX *create_client_context_tls(char *root_ca_path);
SSL_CTX *create_tls_server_context(char *cert_path, char *key_path);

#endif
