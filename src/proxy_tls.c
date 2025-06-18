#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "socketserver.h"
#include "ssl_utils.h"
#include "socket_utils.h" 
#include "proxy.h"
#include "proxy_tls.h"


struct tls_client_handler_args {
        int tcp_server_port;
        char *cert_path;
        char *key_path;
};

struct tcp_client_handler_args {
        int service_port;
        char *ca_cert_path;
};


static void tcp_client_handler(int client_fd, void *args)
{
        struct tcp_client_handler_args *tcp_args = (struct tcp_client_handler_args*)args;
        int service_port = tcp_args->service_port;
        char *root_ca_path = tcp_args->ca_cert_path;

        Socket service_client;
        SSL_CTX *ctx;
        SSL *ssl_service_client;

        service_client = create_client("127.0.0.1", service_port);

        ctx = create_client_context_tls(root_ca_path);

        if (ctx == NULL) {
                close_socket(service_client);
		perror("[*] TCP Server: Error creating SSL context.");
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

        printf("[*] TCP Server: Successfully connected to the service via TLS.\n");

        forward(ssl_service_client, client_fd);

	SSL_free(ssl_service_client);
        SSL_shutdown(ssl_service_client);
        close_socket(service_client);
}


void tls_client_handler(int client_fd, void *args)
{
        struct tls_client_handler_args *tls_args = (struct tls_client_handler_args*)args;
        int tcp_server_port = tls_args->tcp_server_port;
        char *cert_path = tls_args->cert_path;
        char *key_path = tls_args->key_path;

        SSL_CTX *ctx = create_tls_server_context(cert_path, key_path);
        
        if (ctx == NULL) {
                perror("[*] TLS Server: Error creating SSL context.");
                exit(EXIT_FAILURE);
        }

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

        forward(ssl_client, client_tcp.fd);

        SSL_shutdown(ssl_client);
        SSL_free(ssl_client);
        SSL_CTX_free(ctx);
        EVP_cleanup();
        close_socket(client_tcp);
}


void proxy_tls(int tcp_port, int tls_port, int service_port, char* cert_path, char *key_path, char *ca_cert_path)
{
        int pid;

        pid = fork();

        if (pid == -1) {
                perror("Error forking the process");
                exit(EXIT_FAILURE);
        }

        struct tls_client_handler_args *tls_args = malloc(sizeof(struct tls_client_handler_args));
        tls_args->cert_path = cert_path;
        tls_args->key_path = key_path;
        tls_args->tcp_server_port = tcp_port;

        struct tcp_client_handler_args *tcp_args = malloc(sizeof(struct tcp_client_handler_args));
        tcp_args->service_port = service_port;
        tcp_args->ca_cert_path = ca_cert_path;


        if (pid == 0) {
                tcp_server("127.0.0.1", tcp_port, tcp_client_handler, tcp_args);
        }
        
        else {
                tls_server(NULL, tls_port, tls_client_handler, tls_args);
        }
}
