#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "ssl_utils.h"
#include "socket_utils.h" 
#include "proxy.h"
#include "proxy_grpc.h"


static void tcp_server(char *address, int port, int service_port, char *ca_cert_path) 
{
        struct sockaddr_in client_address;
        socklen_t client_len = sizeof(client_address);

        Socket tcp_server = create_server(address, port);

        printf("[*] TCP Server: Listening on port %d...\n", port);

        SSL_CTX *ctx = create_client_context_tls(ca_cert_path);

        if (ctx == NULL) {
                perror("[*] TCP Server: Error creating SSL context.");
                exit(EXIT_FAILURE);
        }

        SSL_CTX_set_alpn_protos(ctx, alpn_protos, strlen((const char*)alpn_protos));

        while (1) {
                int client = accept(tcp_server.fd, (struct sockaddr*)&client_address, &client_len);

                if (client < 0) {
                        perror("[*] TCP Server: accept");
                        continue;
                }

                pid_t pid = fork();
               
                if (pid == -1 ) {
                        perror("[!] gRPC Server: Error forking the process!");
                        exit(EXIT_FAILURE);
                }


                if (pid == 0) {
                        close_socket(tcp_server);

                        Socket service_client;
                        SSL *ssl_service_client;

                        service_client = create_client("127.0.0.1", service_port);

                        ssl_service_client = SSL_new(ctx);
                        SSL_set_fd(ssl_service_client, service_client.fd);

                        printf("[*] TCP Server: Trying to connect to the service...\n");

                        if (SSL_connect(ssl_service_client) <= 0) {
                                ERR_print_errors_fp(stderr);
                                SSL_free(ssl_service_client);
                                close_socket(service_client);
                                close(client);
                                exit(EXIT_FAILURE);
                        }

                        printf("[*] TCP Server: Successfully connected to the service via gRPC.\n");

                        forward(ssl_service_client, client);
                        
                        SSL_shutdown(ssl_service_client);
                        SSL_free(ssl_service_client);
                        close_socket(service_client);
                        SSL_CTX_free(ctx);
                        EVP_cleanup();
                        close(client);

                        printf("[*] TCP Server: Connection terminated.\n");
                        exit(EXIT_SUCCESS);
                } else {
                        close(client);
                }
        }

        close_socket(tcp_server);
}


static void grpc_server(char *address, int port, char *cert_path, char *key_path, int tcp_server_port) 
{
        Socket grpc_server = create_server(address, port);

        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        printf("[*] gRPC Server: Listening on port %d...\n", port);
        
        SSL_CTX *ctx = create_tls_server_context(cert_path, key_path);

        if (ctx == NULL) {
                perror("[*] gRPC Server: Error creating SSL context.");
                exit(EXIT_FAILURE);
        }
        
        SSL_CTX_set_alpn_select_cb(ctx, alpn_select_callback, NULL);

        while (1) {
                int client = accept(grpc_server.fd, (struct sockaddr*)&client_addr, &client_len);

                if (client < 0) {
                        perror("[*] gRPC Server: Accept failed!");
                        continue;
                }

                pid_t pid = fork();

                if (pid == -1) {
                        perror("[!] gRPC Server: Error forking the process!");
                        exit(EXIT_FAILURE);
                }

                if (pid == 0) {
                        close_socket(grpc_server);
                        printf("[*] gRPC Server: New gRPC connection from %s\n", inet_ntoa(client_addr.sin_addr));

                        Socket client_tcp;
                        SSL *ssl_client;

                        ssl_client = SSL_new(ctx);
                        SSL_set_fd(ssl_client, client);

                        if (SSL_accept(ssl_client) <= 0) {
                                ERR_print_errors_fp(stderr);
                                exit(EXIT_FAILURE);
                        }

                        client_tcp = create_client("127.0.0.1", tcp_server_port);

                        printf("[*] gRPC Server: Successfully connected to server TCP\n");

                        forward(ssl_client, client_tcp.fd);

                        SSL_shutdown(ssl_client);
                        SSL_free(ssl_client);
                        close_socket(client_tcp);
                        close(client);
                        printf("[*] gRPC Server: Connection terminated.\n");
                        exit(EXIT_SUCCESS);
                } else {
                        close(client);
                }
        }

        SSL_CTX_free(ctx);
        EVP_cleanup();
        close_socket(grpc_server);
}



void proxy_grpc(int tcp_port, int tls_port, int service_port, char* cert_path, char *key_path, char *ca_cert_path)
{
        int pid;

        pid = fork();

        if (pid == -1) {
                perror("Error forking the process");
                exit(EXIT_FAILURE);
        }


        if (pid == 0) {
                tcp_server("127.0.0.1", tcp_port, service_port, ca_cert_path);
        } else {
                grpc_server(NULL, tls_port, cert_path, key_path, tcp_port);
        }
}



