#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "common.h"
#include "ssl_utils.h"
#include "tls_server.h"


void tls_server(char *address, int port, char *cert_path, char *key_path, int tcp_server_port)
{
        Socket tls_server = create_server(address, port);
        printf("[*] TLS Server: Listening on port %d...\n", port);

        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        SSL_CTX *ctx = create_tls_server_context(cert_path, key_path);
        SSL *ssl_client;

        Socket client_tcp;

        while (1) {
                int client = accept(tls_server.fd, (struct sockaddr*)&client_addr, &client_len);

                if (client < 0) {
                        perror("[*] TLS Server: accept");
                        continue;
                }

                pid_t pid = fork();

                if (pid == -1) {
                        perror("[!] TLS Server: Error forking the process!");
                        exit(EXIT_FAILURE);
                }

                if (pid == 0) {
                        close_socket(tls_server);
                        ssl_client = SSL_new(ctx);
                        SSL_set_fd(ssl_client, client);

                        if (SSL_accept(ssl_client) <= 0) {
                                ERR_print_errors_fp(stderr);
                                SSL_free(ssl_client);
                                close(client);
                                continue;
                        }

                        printf("[*] TLS Server: New connection TLS from %s\n", inet_ntoa(client_addr.sin_addr));
                        
                        client_tcp = create_client("127.0.0.1", tcp_server_port);

                        printf("[*] TLS Server: Successfully connected to server TCP\n");

                        proxy(ssl_client, client_tcp.fd);

                        SSL_shutdown(ssl_client);
                        SSL_free(ssl_client);
                        close(client);
                        close_socket(client_tcp);
                        exit(EXIT_SUCCESS);
                } else {
                        close(client);
                }
        }

        close_socket(tls_server);
        SSL_CTX_free(ctx);
        EVP_cleanup();
}

