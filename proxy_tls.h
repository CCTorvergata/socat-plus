#ifndef PROXY_TLS_H
#define PROXY_TLS_H

void tcp_client_handler(int client_fd, int service_port, char *root_ca_path);
void tls_client_handler(int client_fd, char *cert_path, char *key_path, int tcp_server_port);

#endif
