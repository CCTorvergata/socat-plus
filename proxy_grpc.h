#ifndef PROXY_GRPC_H
#define PROXY_GRPC_H

void proxy_grpc(int tcp_port, int tls_port, int service_port, char* cert_path, char *key_path, char *ca_cert_path);

#endif
