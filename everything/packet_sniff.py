import scapy.all as scapy
from scapy.layers import http

def packet_sniff(interface: str):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print(packet)

packet_sniff("wlan0")
