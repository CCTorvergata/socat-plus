#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "proxy_tls.h"


void print_usage(const char *progname) {
        fprintf(stderr,
                "Usage: %s -t <TLS port> -s <Service port> [-p <TCP port>] [-c <Cert path>] [-k <Key path>] [-r <Root CA path]\n",
                progname);
}


int main(int argc, char *argv[]) {
        int tls_port = 0;
        int tcp_port = 8080;
        int service_port = 0;
        char *cert_path = "cert.pem";
        char *key_path  = "key.pem";
        char *root_ca_path = NULL;

        int opt;

        while ((opt = getopt(argc, argv, "t:p:s:c:k:")) != -1) {
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

        if (tls_port == 0 || service_port == 0) {
                fprintf(stderr, "Error: TLS port (-t) or Service port (-s) are required.\n");
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
        }

        proxy_tls(tcp_port, tls_port, service_port, cert_path, key_path, root_ca_path);

        return 0;
}
