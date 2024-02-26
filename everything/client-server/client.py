import socket


def start_client():
    host = "127.0.0.1"
    port = 1057

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))

        message = "Hello, Server!".encode()
        s.sendall(message)


if __name__ == "__main__":
    start_client()
