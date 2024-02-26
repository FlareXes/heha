from scapy.all import DNS, DNSQR, DNSRR, IP, UDP
from scapy.arch import get_if_addr
import socket


def dns_server():
    # Replace with your server IP address
    server_ip = "127.0.0.1"
    server_port = 1057

    # Create UDP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((server_ip, server_port))

    print(f"DNS Server listening on {server_ip}:{server_port}")

    while True:
        data, addr = server_socket.recvfrom(1024)
        dns_request = DNS(data)

        # Create DNS response with custom resource records
        dns_response = DNS(
            id=dns_request.id,
            qr=1,  # Response
            qd=dns_request.qd,
            an=DNSRR(
                rrname=dns_request.qd.qname, type="A", rdata="1.3.5.7"
            ),  # Answer Section
            ns=[
                DNSRR(
                    rrname=dns_request.qd.qname, type="NS", rdata="ns1.jklu.com"
                ),  # Authority Section
                DNSRR(rrname=dns_request.qd.qname, type="NS", rdata="ns2.jklu.com"),
            ],
            ar=[
                DNSRR(
                    rrname=dns_request.qd.qname, type="A", rdata="5.6.7.8"
                ),  # Additional Section
                DNSRR(rrname=dns_request.qd.qname, type="A", rdata="9.10.11.12"),
            ],
        )

        # Send the DNS response back to the client
        server_socket.sendto(bytes(dns_response), addr)


if __name__ == "__main__":
    dns_server()
