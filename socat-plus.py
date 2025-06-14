import os
import socket
import ssl
import sys
import threading


def http_socket(service_port: int, port: int = 8080):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', port))
    server_socket.listen(50)

    service_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    tls_service_client = context.wrap_socket(
        service_client, server_hostname="localhost")

    print(f"[*] Server listening on localhost:{port}")

    while True:
        client, addr = server_socket.accept()

        print(f"[*] Connection from {addr}")

        pid = os.fork()

        if pid == 0:
            server_socket.close()
            tls_service_client.connect(('localhost', service_port))

            while True:
                client_data = client.recv(1024)

                if not client_data:
                    break

                tls_service_client.send(client_data)
                service_data = tls_service_client.recv(1024)
                print(service_data)

                client.send(service_data)


def https_socket(port: int, http_port: int = 8080,
                       cert_path: str = "./cert.pem",
                       key_path: str = "./key.pem"):

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', port))
    server_socket.listen(50)

    print(f"[*] TLS Server listening on 0.0.0.0:{port}")

    while True:
        team_client, addr = server_socket.accept()
        print(f"[*] Connection from {addr}")

        pid = os.fork()

        if pid == 0:
            server_socket.close()

            try:
                tls_socket = context.wrap_socket(team_client, server_side=True)

                while True:
                    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client.connect(('localhost', http_port))

                    data = tls_socket.recv(1024)
                    client.send(data)
                    data = client.recv(1024)
                    tls_socket.send(data)

            except ssl.SSLError as e:
                print(f"Errore TLS: {e}")


if __name__ == "__main__":
    pid = 0

    if pid == -1:
        print("[!] Error starting the sockets!")
        sys.exit(0)

    if pid == 0:
        https_socket(8443)
        sys.exit(0)

    else:
        http_socket(8555)
