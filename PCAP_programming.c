#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

/* TCP Flag Definitions */
#define TH_FIN 0x01 // Finish flag
#define TH_SYN 0x02 // Synchronize flag
#define TH_RST 0x04 // Reset flag
#define TH_PUSH 0x08 // Push flag
#define TH_ACK 0x10 // Acknowledge flag
#define TH_URG 0x20 // Urgent flag
#define TH_ECE 0x40 // Explicit Congestion Notification Echo flag
#define TH_CWR 0x80 // Congestion Window Reduced flag

/* Ethernet Header Structure */
struct ethheader {
    uint8_t ether_dhost[6]; // Destination MAC address
    uint8_t ether_shost[6]; // Source MAC address
    uint16_t ether_type;    // Protocol type (IP, ARP, etc)
};

/* IP Header Structure */
struct ipheader {
    uint8_t iph_ihl:4, iph_ver:4; // IP header length, IP Version
    uint8_t iph_tos; // Type of Service
    uint16_t iph_len; // IP packet length (header + data)
    uint16_t iph_ident; // Identification
    uint16_t iph_flag:3, iph_offset:13; // Fragmentation flags
    uint8_t iph_ttl; // Time to Live
    uint8_t iph_protocol; // Protocol type (e.g., TCP)
    uint16_t iph_checksum; // IP checksum
    struct in_addr iph_sourceip; // Source IP address
    struct in_addr iph_destip; // Destination IP address
};

/* TCP Header Structure */
struct tcpheader {
    uint16_t tcp_sport; // Source port
    uint16_t tcp_dport; // Destination port
    uint32_t tcp_seq; // Sequence number
    uint32_t tcp_ack; // Acknowledgment number
    uint8_t tcp_offx2; // Data offset, reserved bits
    uint8_t tcp_flags; // TCP flags
    uint16_t tcp_win; // Window size
    uint16_t tcp_sum; // Checksum
    uint16_t tcp_urp; // Urgent pointer
};

/* Pseudo TCP Header for Checksum Calculation */
struct pseudo_tcpheader {
    unsigned int saddr; // Source address
    unsigned int daddr; // Destination address
    unsigned char mbz;  // Reserved
    unsigned char ptcl; // Protocol
    unsigned short tcpl; // TCP length
    struct tcpheader tcp; // Actual TCP header
    char payload[1500]; // Payload data
};

/* Function to print MAC address */
void print_mac_address(const uint8_t *mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* Function to print HTTP message */
void print_http_message(const uint8_t *payload, int size_payload) {
    printf("\n[HTTP MESSAGE]\n");
    for (int i = 0; i < size_payload; i++) {
        if (payload[i] == '\r' || payload[i] == '\n') {
            printf("\n");
        } else {
            printf("%c", payload[i]);
        }
    }
    printf("\n------\n");
}

/* Packet processing function */
void got_packet(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    printf("\n[Ethernet Header]\n");
    printf("Src Mac : ");
    print_mac_address(eth->ether_shost); // Print source MAC address
    printf(" -> Dst Mac : ");
    print_mac_address(eth->ether_dhost); // Print destination MAC address
    printf("\n");

    /* Check if it's an IPv4 packet */
    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 represents IPv4
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        unsigned int ip_header_length = ip->iph_ihl * 4; // Calculate IP header length

        printf("\n[IP Header]\n");
        printf("Source IP: %s\n", inet_ntoa(ip->iph_sourceip)); // Print source IP
        printf("Destination IP: %s\n", inet_ntoa(ip->iph_destip)); // Print destination IP
        
        /* Check if it's a TCP packet */
        if (ip->iph_protocol == IPPROTO_TCP) {
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_length);
            unsigned int tcp_header_length = (tcp->tcp_offx2 >> 4) * 4; // Calculate TCP header length

            printf("\n[TCP Header]\n");
            printf("Source Port: %d\n", ntohs(tcp->tcp_sport)); // Print source port
            printf("Destination Port: %d\n", ntohs(tcp->tcp_dport)); // Print destination port

            /* Extract HTTP Payload */
            const uint8_t *payload = packet + sizeof(struct ethheader) + ip_header_length + tcp_header_length;
            int size_payload = header->len - (sizeof(struct ethheader) + ip_header_length + tcp_header_length);
            
            /* Print HTTP message (if it's a GET or POST request) */
            if (size_payload > 0) {
                printf("\n[Payload]\n");
                if (memcmp(payload, "GET", 4) == 0 || memcmp(payload, "POST ", 5) == 0 ||
                    memcmp(payload, "HTTP/1.1", 8) == 0 || memcmp(payload, "HTTP/1.0", 8) == 0) {
                    print_http_message(payload, size_payload); // Print HTTP message
                }
            }
        }
    }


/* Main function */
int main() {
    pcap_t *handle; // Packet capture handle
    char errbuf[PCAP_ERRBUF_SIZE]; // Error message buffer
    struct bpf_program fp; // Filter program structure
    char filter_exp[] = "tcp port 80"; // Filter expression (capture only HTTP traffic)
    bpf_u_int32 net, mask; // Network address and mask
    pcap_if_t *alldevs, *dev; // Network device list

    /* Find all available network devices */
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Error finding devices: %s\n", errbuf);
        return 1; // Return 1 if no devices are found
    }
    dev = alldevs;  // Use the first available device

    if (dev == NULL) {
        printf("No available devices found.\n");
        return 1; // Return 1 if no devices are available
    }

    /* Open the selected network device */
    if (pcap_lookupnet(dev->name, &net, &mask, errbuf) == -1) {
        printf("Error opening pcap: %s\n", errbuf);
        net = 0; // Set network address to 0 if unable to retrieve it
    }

    /* Open the network device for live capture */
    handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Error opening device: %s\n", errbuf);
        return 1; // Return 1 if unable to open device
    }

    /* Compile and set the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        printf("Error compiling filter: %s\n", pcap_geterr(handle));
        return 1; // Return 1 if filter compilation fails
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        printf("Error setting filter: %s\n", pcap_geterr(handle));
        return 1; // Return 1 if filter setting fails
    }

    printf("Starting packet capture...\n");

    /* Start packet capture loop */
    pcap_loop(handle, 0, got_packet, NULL);

    /* Close the pcap handle */
    pcap_close(handle);

    return 0;
}
