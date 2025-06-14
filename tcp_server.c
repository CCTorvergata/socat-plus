#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <limits.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "common.h"

#define MAX_CLIENTS 50


SSL_CTX *create_client_context_tls()
{
    SSL_CTX *ctx;

    // Inizializza le librerie OpenSSL (solo una volta nel programma)
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Crea il contesto usando TLS client method
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Disabilita la verifica del certificato
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    return ctx;
}


void *tcp_server(char *address, int port, int service_port)
{
        int client;
        struct sockaddr_in client_address;
        socklen_t client_len = sizeof(client_address);

        Socket tcp_server = create_server(address, port);

        Socket service_client;
        SSL_CTX *ctx;
        SSL *ssl_service_client;

        printf("[*] TCP Server: Listening on port %d...\n", port);

        while (1) {
                client = accept(tcp_server.fd, (struct sockaddr*)&client_address, &client_len);

                if (client < 0) {
                        perror("[*] TCP Server: accept");
                        continue;
                }

                pid_t pid = fork();
                
                if (pid == -1) {
                        perror("[!] TLS Server: Error forking the process!");
                        goto exit;
                        exit(EXIT_FAILURE);
                }


                if (pid == 0) {
                        close_socket(tcp_server);
                        service_client = create_client("127.0.0.1", service_port);

                        ctx = create_client_context_tls();
                        ssl_service_client = SSL_new(ctx);

                        SSL_set_fd(ssl_service_client, service_client.fd);

                        printf("[*] TCP Server: Trying to connect to the service...\n");

                        if (SSL_connect(ssl_service_client) <= 0) {
                                ERR_print_errors_fp(stderr);
                                SSL_free(ssl_service_client);
                                SSL_CTX_free(ctx);
                                exit(EXIT_FAILURE);
                        }

                        printf("[*] Successfully connected to the service via TLS.\n");

                        proxy(ssl_service_client, client);

                        SSL_free(ssl_service_client);
                        SSL_shutdown(ssl_service_client);
                        close_socket(service_client);
                        close(client);

                        printf("[*] TCP Server: Connection terminated.\n");

                        exit(EXIT_SUCCESS);
                } else {
                        close(client);
                }
        }
exit:
        close_socket(tcp_server);

        return NULL;
}
