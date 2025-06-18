#ifndef PROXY_H
#define PROXY_H

#include <openssl/ssl.h>

#include "proxy_tls.h"
#include "proxy_grpc.h"

void forward(SSL *ssl_socket, int socket_fd);

#endif
