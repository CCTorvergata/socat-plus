#ifndef PROXY_TLS_H
#define PROXY_TLS_H

void proxy_tls(int tcp_port, int tls_port, int service_port, char* cert_path, char *key_path, char *ca_cert_path);

#endif
