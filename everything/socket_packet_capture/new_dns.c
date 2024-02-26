#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_BUFFER_SIZE 65536
#define ALL_PROTOCOLS 0x0003
#define DNS_PORT 53

void handle_tcp_packet(const unsigned char *ip_packet, size_t length) {
  struct tcphdr *tcp_header =
      (struct tcphdr *)(ip_packet + sizeof(struct iphdr));

  // Print information about the TCP packet
  printf("TCP Packet captured. Source Port: %u, Destination Port: %u, Length: "
         "%zu\n",
         ntohs(tcp_header->source), ntohs(tcp_header->dest), length);
}

void handle_udp_packet(const unsigned char *ip_packet, size_t length) {
  struct udphdr *udp_header =
      (struct udphdr *)(ip_packet + sizeof(struct iphdr));

  // Print information about the UDP packet
  printf("UDP Packet captured. Source Port: %u, Destination Port: %u, Length: "
         "%zu\n",
         ntohs(udp_header->source), ntohs(udp_header->dest), length);

  // Check if it's a DNS packet (port 53)
  if (ntohs(udp_header->dest) == DNS_PORT) {
    // Handle DNS packet
    printf("DNS Packet captured.\n");
    // Implement DNS packet handling logic here
  }
}

void handle_icmp_packet(const unsigned char *ip_packet, size_t length) {
  struct icmphdr *icmp_header =
      (struct icmphdr *)(ip_packet + sizeof(struct iphdr));

  // Print information about the ICMP packet
  printf("ICMP Packet captured. Type: %u, Code: %u, Length: %zu\n",
         icmp_header->type, icmp_header->code, length);
}

void packet_handler(const unsigned char *buffer, size_t length) {
  struct ethhdr *eth_header = (struct ethhdr *)buffer;
  struct iphdr *ip_header;
  unsigned char *ip_packet;

  // Skip Ethernet header
  ip_packet = buffer + sizeof(struct ethhdr);

  // Check if it's an IPv4 packet
  if (eth_header->h_proto == htons(ETH_P_IP)) {
    ip_header = (struct iphdr *)ip_packet;

    // Check the protocol
    switch (ip_header->protocol) {
    case IPPROTO_TCP:
      handle_tcp_packet(ip_packet, length);
      break;
    case IPPROTO_UDP:
      handle_udp_packet(ip_packet, length);
      break;
    case IPPROTO_ICMP:
      handle_icmp_packet(ip_packet, length);
      break;
    // Add cases for other protocols if needed
    default:
      // Handle other protocols or ignore them
      break;
    }
  }
}

int main() {
  int raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ALL_PROTOCOLS));
  if (raw_socket == -1) {
    perror("Error creating raw socket");
    return 1;
  }

  unsigned char buffer[MAX_BUFFER_SIZE];
  ssize_t packet_size;

  while (1) {
    packet_size = recvfrom(raw_socket, buffer, sizeof(buffer), 0, NULL, NULL);
    if (packet_size == -1) {
      perror("Error receiving packet");
      close(raw_socket);
      return 1;
    }

    // Process the captured packet
    packet_handler(buffer, (size_t)packet_size);
  }

  close(raw_socket);
  return 0;
}
