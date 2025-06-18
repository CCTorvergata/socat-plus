#include <poll.h>
#include <unistd.h>
#include <openssl/ssl.h>

#include "socket_utils.h"

void forward(SSL *ssl_socket, int socket_fd)
{
        struct pollfd fds[2];
        char buffer[BUFFER_SIZE + 1];
        int ret;
        int bytes_read;

        fds[0].fd = SSL_get_fd(ssl_socket);
        fds[0].events = POLLIN;
        fds[1].fd = socket_fd;
        fds[1].events = POLLIN;

        while (1) {
                ret = poll(fds, 2, -1);

                if (ret < 0)
                        break;

                if (fds[0].revents & POLLIN) {
                        bytes_read = SSL_read(ssl_socket, buffer, BUFFER_SIZE);

                        if (bytes_read <= 0)
                                break;

                        write(socket_fd, buffer, bytes_read);
                }

                if (fds[1].revents & POLLIN) {
                        bytes_read = read(socket_fd, buffer, BUFFER_SIZE);

                        if (bytes_read <= 0)
                                break;

                        SSL_write(ssl_socket, buffer, bytes_read);
                }
        }
}
