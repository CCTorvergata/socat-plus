#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "socket_utils.h"


Socket create_socket(char *address, int port)
{
        Socket s;

        if ((s.fd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
                perror("Failed to create socket");
                exit(EXIT_FAILURE);
        }
       
        bzero(&s.address, sizeof(s.address));
        s.address.sin_family = AF_INET;
        s.address.sin_port = htons(port);

        if (address == NULL) {
                s.address.sin_addr.s_addr = htonl(INADDR_ANY);
        } else {
                if (inet_pton(AF_INET, address, &s.address.sin_addr) <= 0) {
                        perror("Invalid address");
                        close(s.fd);
                        exit(EXIT_FAILURE);
                }
        }
       
        return s; 
}


Socket create_server(char *address, int port)
{
        Socket server = create_socket(address, port);
        int optval = 1;

        if (setsockopt(server.fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
                perror("Can't configure server");
                close(server.fd);
                exit(EXIT_FAILURE);
        }

        if (bind(server.fd, (struct sockaddr *)&server.address, sizeof(server.address)) < 0) {
                perror("Cannot bind server to the port or address");
                close(server.fd);
                exit(EXIT_FAILURE);
        }

        if (listen(server.fd, MAX_CLIENTS) < 0) {
                perror("Cannot listen");
                close(server.fd);
                exit(EXIT_FAILURE);
        }

        return server;
}


Socket create_client(char *server_address, int port)
{
        int ret;

        if (server_address == NULL) {
                perror("Server address cannot be null!");
                exit(EXIT_FAILURE);
        }

        Socket client = create_socket(server_address, port);

        ret = connect(client.fd, (struct sockaddr*)&client.address, sizeof(client.address));

        if (ret == -1) {
                printf("Connection to %s:%d failed\n", server_address, port);
                close_socket(client);
                exit(EXIT_FAILURE);
        }
        
        return client;
}

int close_socket(Socket s)
{
        return close(s.fd);
}
