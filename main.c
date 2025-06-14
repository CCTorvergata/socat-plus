#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "tcp_server.h"
#include "tls_server.h"


void print_usage(const char *progname) {
        fprintf(stderr,
                "Usage: %s -t <TLS Port> -s <Service Port> [-p <TCP Port>] [-c <Cert Path>] [-k <Key Path>]\n"
                "Defaults:\n"
                "  TCP Port: 8080\n"
                "  Cert Path: cert.pem\n"
                "  Key Path:  key.pem\n",
                progname);
}


int main(int argc, char *argv[]) {
        int tls_port = 0;
        int tcp_port = 8080;
        int service_port = 0;
        char *cert_path = "cert.pem";
        char *key_path  = "key.pem";

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
                        default:
                                print_usage(argv[0]);
                                exit(EXIT_FAILURE);
                }
        }

        if (tls_port == 0 || service_port == 0) {
                fprintf(stderr, "Error: TLS Port (-t) or Service Port (-s) are required.\n");
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
        }

        int pid;

        pid = fork();

        if (pid == -1) {
                perror("Error forking the process");
                exit(EXIT_FAILURE);
        }

        if (pid == 0) {
                tcp_server(NULL, tcp_port, service_port);
        }
        
        else {
                tls_server(NULL, tls_port, cert_path, key_path, tcp_port);
        }
}
