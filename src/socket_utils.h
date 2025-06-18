#ifndef COMMON_H
#define COMMON_H

#define BUFFER_SIZE 16384
#define MAX_CLIENTS 50

#include <netinet/in.h>
#include <openssl/ssl.h>

typedef struct Socket {
        int fd;
        struct sockaddr_in address;
} Socket;

Socket create_socket(char *address, int port);
Socket create_server(char *address, int port);
Socket create_client(char *server_address, int port);
int close_socket(Socket s);

#endif
