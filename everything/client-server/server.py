import socket


def start_server():
    host = "127.0.0.1"
    port = 9090

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        conn, addr = s.accept()

        with conn:
            data = conn.recv(1024)
            print(data.decode())


if __name__ == "__main__":
    start_server()
