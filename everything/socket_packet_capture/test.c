#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

struct dns_query {
    uint16_t qtype;
    uint16_t qclass;
};

void process_dns_response(const u_char *packet, int length) {
    struct dns_header *dns_hdr = (struct dns_header *)(packet + sizeof(struct iphdr) + sizeof(struct udphdr));

    if (ntohs(dns_hdr->ancount) > 0) {
        printf("DNS Response\n");

        const char *dns_response_name = (const char *)(packet + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header));
        printf("Response Name: %s\n", dns_response_name);

        struct dns_query *dns_query = (struct dns_query *)(packet + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header) + strlen(dns_response_name) + 1);
        printf("Response Type: %d\n", ntohs(dns_query->qtype));
        printf("Response Class: %d\n", ntohs(dns_query->qclass));

        // Extract resolved IP addresses
        int offset = sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header) + strlen(dns_response_name) + 1 + sizeof(struct dns_query);
        for (int i = 0; i < ntohs(dns_hdr->ancount); ++i) {
            uint16_t type = ntohs(*(uint16_t *)(packet + offset));
            uint16_t class = ntohs(*(uint16_t *)(packet + offset + sizeof(uint16_t)));
            uint32_t ttl = ntohl(*(uint32_t *)(packet + offset + 2 * sizeof(uint16_t)));
            uint16_t rdlength = ntohs(*(uint16_t *)(packet + offset + 2 * sizeof(uint16_t) + sizeof(uint32_t)));

            if (type == 1 && class == 1 && rdlength == 4) {
                struct in_addr addr;
                memcpy(&addr, packet + offset + 2 * sizeof(uint16_t) + sizeof(uint32_t), sizeof(struct in_addr));
                printf("Resolved IP: %s\n", inet_ntoa(addr));
            }

            offset += 2 * sizeof(uint16_t) + sizeof(uint32_t) + rdlength;
        }
    } else {
        printf("No DNS Response\n");
    }

    printf("*****************************\n");
}

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Assuming the packet is IPv4
    struct iphdr *ip_header = (struct iphdr *)(packet + 14);

    // Check if it's a UDP packet and the destination port is 53 (DNS)
    if (ip_header->protocol == IPPROTO_UDP) {
        struct udphdr *udp_header = (struct udphdr *)(packet + 14 + ip_header->ihl * 4);
        if (ntohs(udp_header->dest) == 53) {
            process_dns_response(packet + 14, pkthdr->len - 14);
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
        return EXIT_FAILURE;
    }

    // Set a filter to capture only DNS packets
    struct bpf_program fp;
    char filter_exp[] = "udp and port 53 and (udp[8] & 0x80 = 0)";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return EXIT_FAILURE;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return EXIT_FAILURE;
    }

    // Start capturing packets and call packet_handler for each captured packet
    pcap_loop(handle, 0, packet_handler, NULL);

    // Close the capture handle
    pcap_close(handle);

    return EXIT_SUCCESS;
}

