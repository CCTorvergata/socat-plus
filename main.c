#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>

#include "proxy.h"


void print_usage(const char *progname) {
        fprintf(stderr,
                "Usage: %s -t <TLS port> -s <Service port> -x <Proxy type> [-p <TCP port>] [-c <Cert path>] [-k <Key path>] [-r <Root CA path]\n",
                progname);
}


int main(int argc, char *argv[]) {
        int tls_port = 0;
        int tcp_port = 8080;
        int service_port = 0;
        char *cert_path = "cert.pem";
        char *key_path  = "key.pem";
        char *root_ca_path = NULL;
        char *proxy_type = NULL;

        int opt;

        while ((opt = getopt(argc, argv, "t:p:s:c:k:r:x:")) != -1) {
                switch (opt) {
                        case 't':
                            tls_port = atoi(optarg);
                            break;
                        case 'p':
                            tcp_port = atoi(optarg);
                            break;
                        case 's':
                            service_port = atoi(optarg);
                            break;
                        case 'c':
                            cert_path = optarg;
                            break;
                        case 'k':
                                key_path = optarg;
                                break;
                        case 'r':
                                root_ca_path = optarg;
                                break;
                        default:
                                print_usage(argv[0]);
                                exit(EXIT_FAILURE);
                }
        }

        if (tls_port == 0) {
                perror("Error: TLS port (-t) is required.\n");
                goto error;
        }

        if (service_port == 0) {
                perror("Error: Service port (-s) is required.\n");
                goto error;
        }

        if (proxy_type == NULL) {
                perror("Error: Proxy Type (-x) is required.\n");
                goto error;
        }


        if (strcmp(proxy_type,"tls") == 0) {
                proxy_tls(tcp_port, tls_port, service_port, cert_path, key_path, root_ca_path);
        } else if (strcmp(proxy_type,"grpc") == 0) {
                proxy_grpc(tcp_port, tls_port, service_port, cert_path, key_path, root_ca_path);
        } else {
                fprintf(stderr, "Error: Proxy type '%s' is not supported", proxy_type);
                perror("Valid Proxy type: tls, grpc");
                exit(EXIT_FAILURE);
        }

        return 0;

error:
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
}
