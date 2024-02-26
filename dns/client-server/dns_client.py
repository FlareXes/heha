import socket
from scapy.all import DNS, DNSQR
from scapy.arch import get_if_addr


def dns_client():
    # Replace with your server IP address and port
    server_ip = "127.0.0.1"
    server_port = 1057

    # Create UDP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    while True:
        # Get user input for domain name
        domain_name = input("Enter domain name (e.g., example.com): ")

        # Create DNS query
        dns_query = DNS(id=1, qr=0, qd=DNSQR(qname=domain_name))

        # Send DNS query to server
        client_socket.sendto(bytes(dns_query), (server_ip, server_port))

        # Receive DNS response
        data, addr = client_socket.recvfrom(1024)
        dns_response = DNS(data)

        # Display DNS response
        print("\nDNS Response:")
        print(dns_response.show())


if __name__ == "__main__":
    dns_client()
