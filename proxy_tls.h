#ifndef PROXY_TLS_H
#define PROXY_TLS_H

struct tls_client_handler_args {
        int tcp_server_port;
        char *cert_path;
        char *key_path;
};

struct tcp_client_handler_args {
        int service_port;
        char *ca_cert_path;
};

void tcp_client_handler(int client_fd, void *args);
void tls_client_handler(int client_fd, void *args);
void proxy_tls(int tcp_port, int tls_port, int service_port, char* cert_path, char *key_path, char *ca_cert_path);

#endif
