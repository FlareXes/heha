#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_BUFFER_SIZE 65536
#define ALL_PROTOCOLS 0x0003

void packet_handler(const unsigned char *buffer, size_t length) {
  // Check if it's an IPv4 packet
  struct iphdr *ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));

  if (ip_header->version == 4 && ip_header->protocol == IPPROTO_TCP) {
    // Your TCP packet processing logic here
    printf("TCP Packet captured. Length: %zu\n", length);
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
