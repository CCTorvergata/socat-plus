#ifndef SOCKETSERVER_H
#define SOCKETSERVER_H

void tcp_server(char *address, int port, void (*client_handler)(int, void *), void *handler_args);
void tls_server(char *address, int port, void (*client_handler)(int, void *), void *handler_args);

#endif
