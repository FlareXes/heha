#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/in.h>

// DNS header structure
struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

// DNS query structure
struct dns_query {
    uint16_t qtype;
    uint16_t qclass;
};

// Function to handle DNS packets
void handle_dns_packet(const u_char *packet, int length) {
    struct dns_header *dns_hdr = (struct dns_header *)(packet + 14 + sizeof(struct ip));
    
    // Check if it's a DNS query
    if (ntohs(dns_hdr->qdcount) > 0) {
        printf("DNS Query\n");

        // Extract the DNS query name
        const char *dns_query_name = (const char *)(packet + 14 + sizeof(struct ip) + sizeof(struct dns_header));
        printf("Query Name: %s\n", dns_query_name);

        // Extract the DNS query type and class
        struct dns_query *dns_query = (struct dns_query *)(packet + 14 + sizeof(struct ip) + sizeof(struct dns_header) + strlen(dns_query_name) + 1);
        printf("Query Type: %d\n", ntohs(dns_query->qtype));
        printf("Query Class: %d\n", ntohs(dns_query->qclass));
    } else {
        printf("Not a DNS Query\n");
    }

    printf("*****************************\n");
}

// Callback function to handle captured packets
void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    int ip_header_length = ((struct ip *)(packet + 14))->ip_hl * 4; // IPv4 header length
    int protocol = ((struct ip *)(packet + 14))->ip_p;

    if (protocol == IPPROTO_UDP) {
        int udp_header_length = sizeof(struct udphdr);
        int dns_header_offset = 14 + ip_header_length + udp_header_length;

        handle_dns_packet(packet + dns_header_offset, pkthdr->len - dns_header_offset);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Open the network interface for packet capture
    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
        return EXIT_FAILURE;
    }

    // Set a filter to capture only DNS packets
    struct bpf_program fp;
    char filter_exp[] = "udp and port 53";
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

