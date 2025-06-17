#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "ssl_utils.h"
#include "common.h" 
#include "proxy_tls.h"


void tcp_client_handler(int client_fd, int service_port, char *root_ca_path)
{
        Socket service_client;
        SSL_CTX *ctx;
        SSL *ssl_service_client;

        service_client = create_client("127.0.0.1", service_port);

        ctx = create_client_context_tls(root_ca_path);

        if (ctx == NULL) {
                close_socket(service_client);
                exit(EXIT_FAILURE);
        }

        ssl_service_client = SSL_new(ctx);

        SSL_set_fd(ssl_service_client, service_client.fd);

        printf("[*] TCP Server: Trying to connect to the service...\n");

        if (SSL_connect(ssl_service_client) <= 0) {
                ERR_print_errors_fp(stderr);
                SSL_free(ssl_service_client);
                SSL_CTX_free(ctx);
                close_socket(service_client);
                exit(EXIT_FAILURE);
        }

        printf("[*] Successfully connected to the service via TLS.\n");

        proxy(ssl_service_client, client_fd);

        SSL_free(ssl_service_client);
        SSL_shutdown(ssl_service_client);
        close_socket(service_client);
}


void tls_client_handler(int client_fd, char *cert_path, char *key_path, int tcp_server_port)
{
        SSL_CTX *ctx = create_tls_server_context(cert_path, key_path);
        SSL *ssl_client;

        Socket client_tcp;

        ssl_client = SSL_new(ctx);
        SSL_set_fd(ssl_client, client_fd);

        if (SSL_accept(ssl_client) <= 0) {
                ERR_print_errors_fp(stderr);
                SSL_free(ssl_client);
                close(client_fd);
        }

        
        client_tcp = create_client("127.0.0.1", tcp_server_port);

        printf("[*] TLS Server: Successfully connected to server TCP\n");

        proxy(ssl_client, client_tcp.fd);

        SSL_shutdown(ssl_client);
        SSL_free(ssl_client);
        SSL_CTX_free(ctx);
        EVP_cleanup();
        close_socket(client_tcp);
}


void proxy(SSL *ssl_socket, int socket_fd)
{
        struct pollfd fds[2];
        char buffer[BUFFER_SIZE + 1];
        int ret;
        int bytes_read;

        fds[0].fd = SSL_get_fd(ssl_socket);
        fds[0].events = POLLIN;
        fds[1].fd = socket_fd;
        fds[1].events = POLLIN;

        while (1) {
                ret = poll(fds, 2, -1);

                if (ret < 0)
                        break;

                if (fds[0].revents & POLLIN) {
                        bytes_read = SSL_read(ssl_socket, buffer, BUFFER_SIZE);

                        if (bytes_read <= 0)
                                break;

                        write(socket_fd, buffer, bytes_read);
                }

                if (fds[1].revents & POLLIN) {
                        bytes_read = read(socket_fd, buffer, BUFFER_SIZE);

                        if (bytes_read <= 0)
                                break;

                        SSL_write(ssl_socket, buffer, bytes_read);
                }
        }
}

