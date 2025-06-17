#ifndef SOCKETSERVER_H
#define SOCKETSERVER_H

void tcp_server(char *address, int port, int service_port, char *root_ca_path);
void tls_server(char *address, int port, char *cert_path, char *key_path, int tcp_server_port);

#endif
