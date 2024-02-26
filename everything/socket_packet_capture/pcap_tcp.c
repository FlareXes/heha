#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void packet_handler(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    struct ip *iph = (struct ip *)(packet + 14); // Assuming Ethernet header is present
    struct tcphdr *tcph = (struct tcphdr *)(packet + 14 + iph->ip_hl * 4); // Move to TCP header

    // Check if the packet is TCP
    if (iph->ip_p == IPPROTO_TCP) {
        printf("TCP Packet captured. Length: %d\n", pkthdr->len);

        // Print source and destination IP addresses
        printf("Source IP: %s\n", inet_ntoa(iph->ip_src));
        printf("Destination IP: %s\n", inet_ntoa(iph->ip_dst));

        // Print source and destination port numbers
        printf("Source Port: %d\n", ntohs(tcph->th_sport));
        printf("Destination Port: %d\n", ntohs(tcph->th_dport));

        // Add more details as needed

        printf("\n");
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    pcap_if_t *dev_list, *dev;
    const char *dev_name;

    // Find all available network devices
    if (pcap_findalldevs(&dev_list, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return 2;
    }

    // Use the first device in the list
    dev_name = dev_list->name;

    // Open the capture interface
    handle = pcap_open_live(dev_name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev_name, errbuf);
        pcap_freealldevs(dev_list); // Free the device list
        return 2;
    }

    // Start capturing packets
    if (pcap_loop(handle, 0, packet_handler, NULL) < 0) {
        fprintf(stderr, "Error in pcap_loop\n");
        pcap_close(handle);
        pcap_freealldevs(dev_list); // Free the device list
        return 2;
    }

    // Close the capture handle
    pcap_close(handle);
    pcap_freealldevs(dev_list); // Free the device list
    return 0;
}

