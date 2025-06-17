#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "socket_utils.h"
#include "ssl_utils.h"
#include "socketserver.h"


void tcp_server(char *address, int port, void (*client_handler)(int, void *), void *handler_args)
{
        struct sockaddr_in client_address;
        socklen_t client_len = sizeof(client_address);

        Socket tcp_server = create_server(address, port);

        printf("[*] TCP Server: Listening on port %d...\n", port);

        while (1) {
                int client = accept(tcp_server.fd, (struct sockaddr*)&client_address, &client_len);

                if (client < 0) {
                        perror("[*] TCP Server: accept");
                        continue;
                }

                pid_t pid = fork();
               
                if (pid == -1 ) {
                        perror("[!] TLS Server: Error forking the process!");
                        exit(EXIT_FAILURE);
                }


                if (pid == 0) {
                        close_socket(tcp_server);

                        client_handler(client, handler_args);

                        close(client);
                        printf("[*] TCP Server: Connection terminated.\n");

                        exit(EXIT_SUCCESS);
                } else {
                        close(client);
                }
        }

        close_socket(tcp_server);
}


void tls_server(char *address, int port, void (*client_handler)(int, void *), void *handler_args)
{
        Socket tls_server = create_server(address, port);
        printf("[*] TLS Server: Listening on port %d...\n", port);

        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);


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
                        printf("[*] TLS Server: New connection TLS from %s\n", inet_ntoa(client_addr.sin_addr));

                        client_handler(client, handler_args);

                        close(client);
                        exit(EXIT_SUCCESS);
                } else {
                        close(client);
                }
        }

        close_socket(tls_server);
}
