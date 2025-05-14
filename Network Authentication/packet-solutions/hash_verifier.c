#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
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

// Modified function to compute the SHA256 hash in the same way as the eBPF code
void compute_keyed_hash(const unsigned char *data, size_t data_len, unsigned char *hash) {
    unsigned char buffer[128]; // Buffer for key + data
    SHA256_CTX sha256;
    
    // Copy key to buffer
    memcpy(buffer, SECRET_KEY, sizeof(SECRET_KEY));
    
    // Copy data to buffer after key
    // NOTE: Using the actual header size as in eBPF
    size_t header_size = data_len;
    memcpy(buffer + sizeof(SECRET_KEY), data, header_size);
    
    // Compute hash using provided SHA256 implementation
    sha256_init(&sha256);
    sha256_update(&sha256, buffer, sizeof(SECRET_KEY) + header_size);
    sha256_final(&sha256, hash);
}

// Packet processing callback function
void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth = (struct ether_header *)packet;
    
    // Check if it's an IP packet
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return;
    
    // Get IP header
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    size_t ip_header_len = ip_header->ip_hl * 4;
    
    // Dump the IP header
    dump_ip_header(ip_header);
    
    // Check if this packet has options (IHL > 5)
    if (ip_header->ip_hl <= 5) {
        printf("No IP options present (IHL = %d)\n", ip_header->ip_hl);
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
    
    // Create a temporary copy of the IP header without our hash option
    // This is crucial to match the eBPF hash calculation
    unsigned char original_header[60]; // Maximum IP header size
    struct ip *modified_header = (struct ip *)original_header;
    
    // First, copy the entire header
    memcpy(original_header, ip_header, ip_header_len);
    
    // Calculate the true header size excluding our hash option
    size_t true_header_size = ip_header_len;
    
    // Check if the hash option exists and adjust the header accordingly
    unsigned char *mod_options = original_header + 20;
    unsigned char *mod_end_options = original_header + ip_header_len;
    
    // Adjust IHL to not include our hash option
    uint8_t old_ihl = modified_header->ip_hl;
    uint8_t new_ihl = old_ihl - (IP_OPT_HASH_LEN / 4);
    modified_header->ip_hl = new_ihl;
    
    // Adjust total length field
    uint16_t old_len = ntohs(modified_header->ip_len);
    uint16_t new_len = old_len - IP_OPT_HASH_LEN;
    modified_header->ip_len = htons(new_len);
    
    // Zero the checksum field (bytes 10-11) 
    // The eBPF code doesn't include the checksum in its hash calculation
    modified_header->ip_sum = 0;
    
    // Compute the true header size
    true_header_size = new_ihl * 4;
    
    // Remove our hash option by shifting other options if any
    bool found_option = false;
    while (mod_options < mod_end_options) {
        if (*mod_options == IP_OPT_HASH_ID && mod_options + 1 < mod_end_options) {
            size_t opt_len = mod_options[1];
            if (opt_len == IP_OPT_HASH_LEN && mod_options + opt_len <= mod_end_options) {
                // Found our option, remove it by shifting remaining data
                size_t remaining = mod_end_options - (mod_options + opt_len);
                if (remaining > 0) {
                    memmove(mod_options, mod_options + opt_len, remaining);
                }
                found_option = true;
                break;
            }
        }
        
        // Next option
        if (mod_options + 1 >= mod_end_options)
            break;
        size_t opt_len = (mod_options[1] == 0) ? 1 : mod_options[1];
        mod_options += opt_len;
    }
    
    // Compute hash of the modified header
    unsigned char computed_hash[32];
    compute_keyed_hash(original_header, true_header_size, computed_hash);
    
    // Print the results
    printf("Received hash:  ");
    print_hex(received_hash, 32);
    
    printf("Computed hash:  ");
    print_hex(computed_hash, 32);
    
    // Compare the hashes
    if (memcmp(received_hash, computed_hash, 32) == 0) {
        printf("HASH MATCH - packet is authentic\n");
    } else {
        printf("HASH MISMATCH - packet may be tampered\n");
        
        // Print raw IP header bytes for debugging
        printf("Raw IP header bytes used for hash calculation:\n");
        print_hex(original_header, true_header_size);
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
