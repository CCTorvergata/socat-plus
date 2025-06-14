#ifndef TLS_SERVER_H
#define TLS_SERVER_H

#include <openssl/ssl.h>


SSL_CTX *create_ssl_context(char *cert_path, char *key_path);
void *tls_server(char *address, int port, char *cert_path, char *key_path, int tcp_server_port);

#endif
