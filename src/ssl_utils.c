#include <openssl/ssl.h>
#include <openssl/err.h>

#include "ssl_utils.h"


const unsigned char alpn_protos[] = {
    8, 'h', 't', 't', 'p', '/', '1', '.', '1',
    8, 'h', 't', 't', 'p', '/', '1', '.', '0',
    2, 'h', '2'
};


SSL_CTX *init_tls_context(int method_type)
{
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();

        const SSL_METHOD *method;
        if (method_type == 0)
		method = TLS_server_method();
	else
		method = TLS_client_method();

        SSL_CTX *ctx = SSL_CTX_new(method);

        if (!ctx) {
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
        }

        return ctx;
}


SSL_CTX *create_client_context_tls(char *root_ca_path)
{
        SSL_CTX *ctx = init_tls_context(1);

        // Disabilita la verifica del certificato
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

        if (root_ca_path != NULL) {
                if (SSL_CTX_load_verify_locations(ctx, root_ca_path, NULL) != 1) {
                        fprintf(stderr, "[!] TCP Server: Cannot laod root CA file: %s\n", root_ca_path);
                        ERR_print_errors_fp(stderr);
                        SSL_CTX_free(ctx);
                        return NULL;
                }
        }

    return ctx;
}


SSL_CTX *create_tls_server_context(char *cert_path, char *key_path)
{
        SSL_CTX *ctx = init_tls_context(0);

        if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0 ||
            SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
                ERR_print_errors_fp(stderr);
                SSL_CTX_free(ctx);
                return NULL;
        }

        return ctx;
}


int alpn_select_callback(SSL *ssl, const unsigned char **out,
                              unsigned char *outlen,
                              const unsigned char *in, unsigned int inlen,
                              void *arg)
{
        (void)ssl;
        (void)arg;

        if (SSL_select_next_proto((unsigned char **)out, outlen, in, inlen,
                            alpn_protos, sizeof(alpn_protos)) != OPENSSL_NPN_NEGOTIATED) {
                return SSL_TLSEXT_ERR_NOACK;
        }

        return SSL_TLSEXT_ERR_OK;
}
