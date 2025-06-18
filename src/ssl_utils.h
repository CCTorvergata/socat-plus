#ifndef SSL_UTILS_H
#define SSL_UTILS_H

#include <openssl/ssl.h>


extern const unsigned char alpn_protos[];


SSL_CTX *create_client_context_tls(char *root_ca_path);
SSL_CTX *create_tls_server_context(char *cert_path, char *key_path);
int alpn_select_callback(SSL *ssl, const unsigned char **out,
                              unsigned char *outlen,
                              const unsigned char *in, unsigned int inlen,
                              void *arg);
#endif
