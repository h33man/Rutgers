#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h> // For inet_ntoa
#include "sha256.h"    // Using the provided SHA256 implementation

#define IP_OPT_HASH_ID 25  // Custom option identifier used in your XDP program
#define IP_OPT_HASH_LEN 36 // Option length: 4 (header) + 32 (SHA256)

// The same secret key used in your XDP program
static const unsigned char SECRET_KEY[16] = {
    0x4b, 0x75, 0x8f, 0x94, 0x98, 0xd3, 0x31, 0x26,
    0x16, 0xec, 0xc2, 0x61, 0x99, 0x43, 0x76, 0x45
};

// Function to print a hex dump of binary data
void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

#if 1
// Function to dump IP header details
void dump_ip_header(const struct iphdr *ip_header) {
    printf("\n=== IP HEADER DUMP ===\n");
    /*
    new_ip->version = 4;
    new_ip->ihl = (sizeof(struct iphdr) + option_len) / 4;
    new_ip->tos = tos;
    new_ip->tot_len = bpf_htons(tot_len + option_len);
    new_ip->id = id;
    new_ip->frag_off = frag_off;
    new_ip->ttl = ttl;
    new_ip->protocol = protocol;
    new_ip->check = 0; // Checksum will need to be recalculated
    new_ip->saddr = saddr;
    new_ip->daddr = daddr;
    */
    printf("Version: %d\n", ip_header->version);
    printf("Header Length: %d bytes\n", ip_header->ihl * 4);
    printf("Type of Service: 0x%02x\n", ip_header->tos);
    printf("Total Length: %d bytes\n", ntohs(ip_header->tot_len));
    printf("Identification: 0x%04x\n", ntohs(ip_header->id));
    
    // Handle fragmentation flags and offset
    unsigned short frag = ntohs(ip_header->frag_off);
    printf("Fragment Offset: 0x%04x\n", frag);
    //printf("Flags: %s%s\n", 
    //       (frag & IP_DF) ? "DF " : "",
    //       (frag & IP_MF) ? "MF " : "");
    //printf("Fragment Offset: %d\n", frag & IP_OFFMASK);
    
    printf("Time to Live: %d\n", ip_header->ttl);
    printf("Protocol: %d", ip_header->protocol);
    
    // Add protocol name for common protocols
    switch(ip_header->protocol) {
        case IPPROTO_TCP:  printf(" (TCP)"); break;
        case IPPROTO_UDP:  printf(" (UDP)"); break;
        case IPPROTO_ICMP: printf(" (ICMP)"); break;
    }
    printf("\n");
    
    printf("Header Checksum: 0x%04x\n", ntohs(ip_header->check));
    printf("Source IP: 0x%04x\n", ip_header->saddr);
    printf("Destination IP: 0x%04x\n", ip_header->daddr);
    //printf("Source IP: %s\n", inet_ntoa((ip_header->saddr)));
    //printf("Destination IP: %s\n", inet_ntoa(ip_header->daddr));
    
    // Print options if present
    if (ip_header->ihl > 5) {
        printf("IP Options Present: %d bytes of options\n", (ip_header->ihl - 5) * 4);
        const unsigned char *options = (const unsigned char *)ip_header + 20;
        size_t opt_len = (ip_header->ihl - 5) * 4;
        printf("Options (hex): ");
        print_hex(options, opt_len);
    }
    
    printf("=== END IP HEADER ===\n\n");
}
#else

// Function to dump IP header details
void dump_ip_header(const struct ip *ip_header) {
    printf("\n=== IP HEADER DUMP ===\n");
    printf("Version: %d\n", ip_header->ip_v);
    printf("Header Length: %d bytes\n", ip_header->ip_hl * 4);
    printf("Type of Service: 0x%02x\n", ip_header->ip_tos);
    printf("Total Length: %d bytes\n", ntohs(ip_header->ip_len));
    printf("Identification: 0x%04x\n", ntohs(ip_header->ip_id));
    
    // Handle fragmentation flags and offset
    unsigned short frag = ntohs(ip_header->ip_off);
    printf("Flags: %s%s\n", 
           (frag & IP_DF) ? "DF " : "",
           (frag & IP_MF) ? "MF " : "");
    printf("Fragment Offset: %d\n", frag & IP_OFFMASK);
    
    printf("Time to Live: %d\n", ip_header->ip_ttl);
    printf("Protocol: %d", ip_header->ip_p);
    
    // Add protocol name for common protocols
    switch(ip_header->ip_p) {
        case IPPROTO_TCP:  printf(" (TCP)"); break;
        case IPPROTO_UDP:  printf(" (UDP)"); break;
        case IPPROTO_ICMP: printf(" (ICMP)"); break;
    }
    printf("\n");
    
    printf("Header Checksum: 0x%04x\n", ntohs(ip_header->ip_sum));
    printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
    
    // Print options if present
    if (ip_header->ip_hl > 5) {
        printf("IP Options Present: %d bytes of options\n", (ip_header->ip_hl - 5) * 4);
        const unsigned char *options = (const unsigned char *)ip_header + 20;
        size_t opt_len = (ip_header->ip_hl - 5) * 4;
        printf("Options (hex): ");
        print_hex(options, opt_len);
    }
    
    printf("=== END IP HEADER ===\n\n");
}
#endif

// Modified function to compute the SHA256 hash in the same way as the eBPF code
void compute_keyed_hash(const unsigned char *data, size_t data_len, unsigned char *hash) {
    unsigned char buffer[128]; // Buffer for key + data
    SHA256_CTX sha256;
    
    // Copy key to buffer
    memcpy(buffer, SECRET_KEY, sizeof(SECRET_KEY));
    
    // Copy data to buffer after key
    // NOTE: Using exact header size like in eBPF (important!)
    size_t max_copy = data_len > 20 ? 20 : data_len; // Limit to 20 bytes (standard IP header)
    memcpy(buffer + sizeof(SECRET_KEY), data, max_copy);
    
    // Compute hash using provided SHA256 implementation
    sha256_init(&sha256);
    sha256_update(&sha256, buffer, sizeof(SECRET_KEY) + max_copy);
    sha256_final(&sha256, hash);
}

// Packet processing callback function
void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth = (struct ether_header *)packet;
    
    // Check if it's an IP packet
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return;
    
    // Get IP header
    //struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    //size_t ip_header_len = ip_header->ip_hl * 4;

    struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ether_header));
    int ip_header_len = ip_header->ihl * 4;

    
    // Check if this packet has options (IHL > 5)
    if (ip_header->ihl <= 5) {
        printf("No IP options present (IHL = %d)\n", ip_header->ihl);
        return;
    }
    
    // Look for our custom option
    unsigned char *options = (unsigned char *)ip_header + 20; // Standard IP header size
    unsigned char *end_options = (unsigned char *)ip_header + ip_header_len;
    unsigned char *received_hash = NULL;
    
    // Parse IP options
    while (options < end_options) {
        // Check for end of options
        if (*options == 0)
            break;
        
        // Single byte options
        if (*options == 1) {
            options++;
            continue;
        }
        
        // Check if this is our hash option
        if (*options == IP_OPT_HASH_ID && options + 1 < end_options) {
            size_t opt_len = options[1];
            if (opt_len == IP_OPT_HASH_LEN && options + opt_len <= end_options) {
                received_hash = options + 4; // Skip option header (4 bytes)
                break;
            }
        }
        
        // Move to next option
        if (options + 1 >= end_options)
            break;
        size_t opt_len = (options[1] == 0) ? 1 : options[1];
        options += opt_len; // Move by option length
    }
    
    // If no hash found, return
    if (!received_hash) {
        printf("No hash option found in packet\n");
        printf("------------------------------------------------------\n");
        return;
    }
    
    // Create a normalized copy of the IP header for hash calculation
    // IMPORTANT: Create a raw header buffer exactly as it would appear in the packet
    // This is crucial to match the eBPF hash calculation
    unsigned char ip_raw[20]; // Standard IP header size
    
    // Copy the header bytes directly
    memcpy(ip_raw, ip_header, 20);
    
    // Now normalize specific fields to match how eBPF would see them
    
    // 1. Set the IHL to standard (no options) - 5 words = 20 bytes
    ip_raw[0] = (ip_raw[0] & 0xF0) | 5;
    
    // 2. Fix the total length (original length minus options)
    uint16_t new_len = htons(ntohs(ip_header->tot_len) - (ip_header_len - 20));
    memcpy(&ip_raw[2], &new_len, 2);
    
    // 3. Zero the checksum field (bytes 10-11)
    ip_raw[10] = 0;
    ip_raw[11] = 0;
    
    // Compute hash of the normalized header
    unsigned char computed_hash[32];
    //unsigned char raw_hash[32];
    //memset(raw_hash, 0, 32);
    //compute_keyed_hash((const unsigned char *)ip_header, ip_header_len, computed_hash);
    compute_keyed_hash(ip_raw, 20, computed_hash);
    
    //ip_header->check = 0;
    //ip_header->ihl = 5;
    //ip_header->tot_len = htons(ntohs(ip_header->tot_len) - (ip_header_len - 20));

    // Dump the IP header
    //dump_ip_header(ip_header);
    dump_ip_header((const struct iphdr *)ip_raw);

    // Print the results
    printf("Received hash:  ");
    print_hex(received_hash, 32);
    
    printf("Computed hash:  ");
    print_hex(computed_hash, 32);
    
    //printf("Computed Raw hash:  ");
    //print_hex(raw_hash, 32);
    
    // Compare the hashes
    if (memcmp(received_hash, computed_hash, 32) == 0) {
        printf("HASH MATCH - packet is authentic\n");
    } else {
        printf("HASH MISMATCH - packet may be tampered\n");
        
        // Print raw IP header bytes for debugging
        printf("Raw IP header bytes used for hash calculation:\n");
        print_hex((const unsigned char *)ip_header, 20);
        //print_hex(ip_raw, 20);
    }
    
    printf("------------------------------------------------------\n");
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "ip";  // Only capture IP packets
    bpf_u_int32 net, mask;
    
    if (argc != 2) {
        printf("Usage: %s <interface>\n", argv[0]);
        return 1;
    }
    
    // Get network interface properties
    if (pcap_lookupnet(argv[1], &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s: %s\n", argv[1], errbuf);
        net = 0;
        mask = 0;
    }
    
    // Open the network interface for packet capture
    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
        return 2;
    }
    
    // Compile and apply the filter
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 3;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 4;
    }
    
    printf("Listening on %s for IP packets with SHA256 hash options...\n", argv[1]);
    
    // Start capturing packets
    pcap_loop(handle, 0, packet_handler, NULL);
    
    // Clean up
    pcap_freecode(&fp);
    pcap_close(handle);
    
    return 0;
}
