/*********************************************************************
* Filename:   sha256.c
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Implementation of the SHA-256 hashing algorithm.
              SHA-256 is one of the three algorithms in the SHA2
              specification. The others, SHA-384 and SHA-512, are not
              offered in this implementation.
              Algorithm specification can be found here:
               * http://csrc.nist.gov/publications/fips/fips180-2/fips180-2withchangenotice.pdf
              This implementation uses little endian byte order.
*********************************************************************/

/*************************** HEADER FILES ***************************/
/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/types.h>
#include <stdint.h>
#include <stdio.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

#if 1
#include "sha256.h"

/****************************** MACROS ******************************/
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

/* IP Options for hash storage */
#define IP_OPT_HASH_ID 25  /* Custom option identifier */
#define IP_OPT_HASH_LEN 36 /* Option length: 4 (header) + 32 (SHA256) */

/* Define Ethernet header size */
#define ETHERNET_HEADER_SIZE 14 /* Standard Ethernet header size is 14 bytes */

#define ntohs(x) ((((x) >> 8) & 0xff) | (((x) & 0xff) << 8))

/**************************** VARIABLES *****************************/
static const WORD k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/* Secret key for HMAC-like functionality */
static const BYTE SECRET_KEY[16] = {
    0x4b, 0x75, 0x8f, 0x94, 0x98, 0xd3, 0x31, 0x26,
    0x16, 0xec, 0xc2, 0x61, 0x99, 0x43, 0x76, 0x45
};

// Define a BPF map to store the SHA256 context
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, SHA256_CTX);
} sha256_ctx_map SEC(".maps");

// Define a map for temporary data buffers
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct {
        BYTE buffer[128];
        WORD m[64];
    });
} sha256_temp_map SEC(".maps");

static __always_inline int sha256_transform(const BYTE data[])
{
    __u32 key = 0;
    SHA256_CTX *ctx;
    struct {WORD m[64];} *temp;
    WORD a, b, c, d, e, f, g, h, i, t1, t2;

    // Get context from map
    ctx = bpf_map_lookup_elem(&sha256_ctx_map, &key);
    if (!ctx)
        return -1;

    // Get temp buffer from map
    temp = bpf_map_lookup_elem(&sha256_temp_map, &key);
    if (!temp)
        return -1;

    // Copy data into the message schedule array (m)
    for (i = 0; i < 16; ++i) {
        if (i >= 16) break; // eBPF verifier needs this boundary check
        int j = i * 4;
        if (j + 3 >= 64) break; // Boundary check
        temp->m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    }

    // Extend the first 16 words into the remaining 48 words of the message schedule array
    for (i = 16; i < 64; ++i) {
        if (i >= 64) break; // eBPF verifier needs this boundary check
        if (i - 2 < 0 || i - 7 < 0 || i - 15 < 0 || i - 16 < 0) break; // Boundary check
        temp->m[i] = SIG1(temp->m[i - 2]) + temp->m[i - 7] + SIG0(temp->m[i - 15]) + temp->m[i - 16];
    }

    // Initialize working variables
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    // Main compression loop
    for (i = 0; i < 64; ++i) {
        if (i >= 64) break; // eBPF verifier needs this
        t1 = h + EP1(e) + CH(e,f,g) + k[i] + temp->m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    // Update state
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;

    return 0; // Success
}

static __always_inline int sha256_init(void)
{
    __u32 key = 0;
    SHA256_CTX *ctx;

    ctx = bpf_map_lookup_elem(&sha256_ctx_map, &key);
    if (!ctx)
        return -1;

    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;

    return 0;
}

static __always_inline int sha256_update(const BYTE data[], size_t len)
{
    __u32 key = 0;
    SHA256_CTX *ctx;
    WORD i;

    // Get context from map
    ctx = bpf_map_lookup_elem(&sha256_ctx_map, &key);
    if (!ctx)
        return -1;

    // Process data in chunks
    for (i = 0; i < len; ++i) {
        if (i >= len) break; // Explicit boundary check for eBPF verifier

        // Make sure we don't go out of bounds
        if (ctx->datalen >= 64) break;

        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;

        if (ctx->datalen == 64) {
            sha256_transform(ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
    return 0;
}

static __always_inline int sha256_final(BYTE hash[])
{
    __u32 key = 0;
    SHA256_CTX *ctx;
    WORD i;

    // Get context from map
    ctx = bpf_map_lookup_elem(&sha256_ctx_map, &key);
    if (!ctx)
        return -1;

    i = ctx->datalen;

    // Make sure we don't go out of bounds
    if (i >= 64) {
        i = 0;
    }

    // Pad whatever data is left in the buffer.
    if (ctx->datalen < 56) {
        if (i < 64) {
            ctx->data[i++] = 0x80;
        }

        // Ensure i stays within bounds
        while (i < 56) {
            if (i >= 64) break; // Safety check for eBPF verifier
            ctx->data[i] = 0x00;
            i++;  // Move increment here to avoid off-by-one
        }
    }
    else {
        if (i < 64) {
            ctx->data[i++] = 0x80;
        }

        // Ensure i stays within bounds
        while (i < 64) {
            if (i >= 64) break; // Safety check for eBPF verifier
            ctx->data[i] = 0x00;
            i++;  // Move increment here to avoid off-by-one
        }

        sha256_transform(ctx->data);

        for (i = 0; i < 56; i++) {
            if (i >= 64) break; // Safety check for eBPF verifier
            ctx->data[i] = 0x00;
        }
    }

    // Append to the padding the total message's length in bits and transform.
    ctx->bitlen += ctx->datalen * 8;

    // Ensure we don't exceed array bounds
    if (56 < 64) ctx->data[56] = ctx->bitlen >> 56;
    if (57 < 64) ctx->data[57] = ctx->bitlen >> 48;
    if (58 < 64) ctx->data[58] = ctx->bitlen >> 40;
    if (59 < 64) ctx->data[59] = ctx->bitlen >> 32;
    if (60 < 64) ctx->data[60] = ctx->bitlen >> 24;
    if (61 < 64) ctx->data[61] = ctx->bitlen >> 16;
    if (62 < 64) ctx->data[62] = ctx->bitlen >> 8;
    if (63 < 64) ctx->data[63] = ctx->bitlen;

    sha256_transform(ctx->data); 

    // Since this implementation uses little endian byte ordering and SHA uses big endian,
    // reverse all the bytes when copying the final state to the output hash.
    for (i = 0; i < 4; ++i) {
        if (i >= 4) break; // eBPF verifier needs explicit bounds check

        if (i < 32 && i + 4 < 32 && i + 8 < 32 && i + 12 < 32 &&
            i + 16 < 32 && i + 20 < 32 && i + 24 < 32 && i + 28 < 32) {
            hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
        }
    }
    return 0;
}

/**
 * Calculate the IP header checksum correctly
 *
 * @param header Pointer to the IP header bytes
 * @param len Length of the header in bytes
 * @return The calculated checksum
 */
static __always_inline uint16_t calculate_ip_checksum(const void *header, int len) {
    const uint16_t *buf = header;
    uint32_t sum = 0;

    // Sum all 16-bit words
    for (int i = 0; i < len / 2; i++) {
        if (i >= len / 2) break; // Explicit boundary check for verifier
        sum += buf[i];
    }

    // Add odd byte if present (should not happen with IP headers)
    if (len % 2) {
        sum += ((const uint8_t *)header)[len - 1];
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Return one's complement
    return ~sum;
}

static __always_inline int add_ip_option_hash(struct xdp_md *ctx,
        struct iphdr *ip_orig, BYTE hash[SHA256_BLOCK_SIZE])
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    uint8_t headers_copy[ETHERNET_HEADER_SIZE + sizeof(struct iphdr)];
    uint8_t option_len = IP_OPT_HASH_LEN;
    int i;

    // Save the original headers (Ethernet + IP)
    if ((void *)data + sizeof(headers_copy) > data_end)
        return -1;

    __builtin_memcpy(headers_copy, data, sizeof(headers_copy));

    // Add space for the IP option
    if (bpf_xdp_adjust_head(ctx, 0 - (int)IP_OPT_HASH_LEN))
        return -1;

    // After adjust_head, all previous pointers are invalidated
    data_end = (void *)(long)ctx->data_end;
    data = (void *)(long)ctx->data;

    // Ensure we have enough space for the headers
    if ((void *)data + sizeof(headers_copy) > data_end)
        return -1;

    // Copy back the original headers
    __builtin_memcpy(data, headers_copy, sizeof(headers_copy));

    // Get pointer to the new IP header
    struct iphdr *new_ip = (struct iphdr *)(data + ETHERNET_HEADER_SIZE);
    if ((void *)(new_ip + 1) > data_end)
        return -1;

    // Update the IP header
    new_ip->ihl = (sizeof(struct iphdr) + IP_OPT_HASH_LEN) / 4;
    new_ip->tot_len = bpf_htons(bpf_ntohs(new_ip->tot_len) + IP_OPT_HASH_LEN);
    
    // Reset checksum field to zero before calculating new checksum
    new_ip->check = 0;

    // Now add our option after the IP header
    uint8_t *options = (uint8_t *)(new_ip + 1);
    if ((void *)(options + option_len) > data_end)
        return -1;

    // Set up the IP option
    options[0] = IP_OPT_HASH_ID;    // Option ID
    options[1] = option_len;         // Option length
    options[2] = 0x12;               // Magic value 1
    options[3] = 0x34;               // Magic value 2

    // Copy the hash value in chunks of 4 bytes
    #pragma unroll
    for (i = 0; i < 32; i += 4) {
        if (i + 3 < 32 && 4 + i + 3 < option_len) {
            options[4 + i] = hash[i];
            options[4 + i + 1] = hash[i + 1];
            options[4 + i + 2] = hash[i + 2];
            options[4 + i + 3] = hash[i + 3];
        }
    }

    // Calculate checksum on the entire IP header including options
    int header_len = new_ip->ihl * 4;
    new_ip->check = calculate_ip_checksum((const void *)new_ip, header_len);
    
    // Debug: Print calculated checksum
    bpf_printk("New IP header length: %d bytes\n", header_len);
    bpf_printk("New IP checksum: 0x%04x\n", new_ip->check);

    return 0;
}

// Function to print a hex dump of binary data
void print_hex(const unsigned char *data, int len) {
    if (len > 20) return;
    for (int i = 0; i < len; i++)
        bpf_printk("%02x", data[i++]);
    bpf_printk("\n");
}

// Function to dump IP header details
void dump_ip_header(const struct iphdr *ip_header) {
    bpf_printk("\n=== IP HEADER DUMP ===\n");
    bpf_printk("Version: %d\n", ip_header->version);
    bpf_printk("Header Length: %d bytes\n", ip_header->ihl * 4);
    bpf_printk("Type of Service: 0x%02x\n", ip_header->tos);
    bpf_printk("Total Length: %d bytes\n", __builtin_bswap16(ip_header->tot_len));
    bpf_printk("Identification: 0x%04x\n", __builtin_bswap16(ip_header->id));
    
    // Handle fragmentation flags and offset
    unsigned short frag = __builtin_bswap16(ip_header->frag_off);
    bpf_printk("Fragment Offset: 0x%04x\n", frag);
    
    bpf_printk("Time to Live: %d\n", ip_header->ttl);
    bpf_printk("Protocol: %d", ip_header->protocol);
    bpf_printk("Header Checksum: 0x%04x\n", __builtin_bswap16(ip_header->check));
    bpf_printk("Source IP: 0x%04x\n", ip_header->saddr);
    bpf_printk("Destination IP: 0x%04x\n", ip_header->daddr);
    /*
    // Print options if present
    if (ip_header->ihl > 5) {
        bpf_printk("IP Options Present: %d bytes of options\n", (ip_header->ihl - 5) * 4);
        const unsigned char *options = (const unsigned char *)ip_header + 20;
        size_t opt_len = (ip_header->ihl - 5) * 4;
        bpf_printk("Options (hex): ");
        print_hex(options, opt_len);
    }
    */
    bpf_printk("=== END IP HEADER ===\n\n");
}

static __always_inline int compute_keyed_hash(struct xdp_md *ctx, const BYTE *data, size_t data_len, BYTE hash[SHA256_BLOCK_SIZE])
{
    __u32 key = 0;
    struct {BYTE buffer[128];} *temp;
    void *data_end = (void *)(long)ctx->data_end;

    // Verify data pointer is within packet bounds
    if ((void *)data + data_len > data_end) {
        return -1;  // Data extends beyond packet bounds
    }

    // Get temp buffer from map
    temp = bpf_map_lookup_elem(&sha256_temp_map, &key);
    if (!temp)
        return -1;

    // Initialize buffer with key using explicit assignments
    temp->buffer[0] = SECRET_KEY[0];
    temp->buffer[1] = SECRET_KEY[1];
    temp->buffer[2] = SECRET_KEY[1];
    temp->buffer[3] = SECRET_KEY[1];
    temp->buffer[4] = SECRET_KEY[1];
    temp->buffer[5] = SECRET_KEY[1];
    temp->buffer[6] = SECRET_KEY[1];
    temp->buffer[7] = SECRET_KEY[1];
    temp->buffer[8] = SECRET_KEY[1];
    temp->buffer[9] = SECRET_KEY[1];
    temp->buffer[10] = SECRET_KEY[1];
    temp->buffer[11] = SECRET_KEY[1];
    temp->buffer[12] = SECRET_KEY[1];
    temp->buffer[13] = SECRET_KEY[1];
    temp->buffer[14] = SECRET_KEY[1];
    temp->buffer[15] = SECRET_KEY[1];

    // Limit copy size to prevent buffer overflow and verifier issues
    size_t max_copy = data_len;
    if (max_copy > 20)  // Standard IPv4 header is 20 bytes
        max_copy = 20;

    // Copy data bytes one by one with explicit bounds checking
    if (max_copy >= 1 && (void *)data + 0 < data_end) temp->buffer[16 + 0] = data[0];
    if (max_copy >= 2 && (void *)data + 1 < data_end) temp->buffer[16 + 1] = data[1];
    if (max_copy >= 3 && (void *)data + 2 < data_end) temp->buffer[16 + 2] = data[2];
    if (max_copy >= 4 && (void *)data + 3 < data_end) temp->buffer[16 + 3] = data[3];
    if (max_copy >= 5 && (void *)data + 4 < data_end) temp->buffer[16 + 4] = data[4];
    if (max_copy >= 6 && (void *)data + 5 < data_end) temp->buffer[16 + 5] = data[5];
    if (max_copy >= 7 && (void *)data + 6 < data_end) temp->buffer[16 + 6] = data[6];
    if (max_copy >= 8 && (void *)data + 7 < data_end) temp->buffer[16 + 7] = data[7];
    if (max_copy >= 9 && (void *)data + 8 < data_end) temp->buffer[16 + 8] = data[8];
    if (max_copy >= 10 && (void *)data + 9 < data_end) temp->buffer[16 + 9] = data[9];
    if (max_copy >= 11 && (void *)data + 10 < data_end) temp->buffer[16 + 10] = data[10];
    if (max_copy >= 12 && (void *)data + 11 < data_end) temp->buffer[16 + 11] = data[11];
    if (max_copy >= 13 && (void *)data + 12 < data_end) temp->buffer[16 + 12] = data[12];
    if (max_copy >= 14 && (void *)data + 13 < data_end) temp->buffer[16 + 13] = data[13];
    if (max_copy >= 15 && (void *)data + 14 < data_end) temp->buffer[16 + 14] = data[14];
    if (max_copy >= 16 && (void *)data + 15 < data_end) temp->buffer[16 + 15] = data[15];
    if (max_copy >= 17 && (void *)data + 16 < data_end) temp->buffer[16 + 16] = data[16];
    if (max_copy >= 18 && (void *)data + 17 < data_end) temp->buffer[16 + 17] = data[17];
    if (max_copy >= 19 && (void *)data + 18 < data_end) temp->buffer[16 + 18] = data[18];
    if (max_copy >= 20 && (void *)data + 19 < data_end) temp->buffer[16 + 19] = data[19];

    // Compute hash
    sha256_init();
    sha256_update(temp->buffer, 16 + max_copy);
    sha256_final(hash);

    return 0; // Success
}

SEC("xdp_ip_hash")
int xdp_ip_hash_func(struct xdp_md *ctx)
{
    int action = XDP_PASS;
    int eth_type, ip_type;
    struct ethhdr *eth;
    struct iphdr *iphdr;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct hdr_cursor nh = { .pos = data };
    BYTE hash_result[SHA256_BLOCK_SIZE];

    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type < 0) {
        action = XDP_ABORTED;
        goto out;
    }

    // We only process IPv4 packets
    if (eth_type == bpf_htons(ETH_P_IP)) {
        ip_type = parse_iphdr(&nh, data_end, &iphdr);
        if (ip_type < 0) {
            action = XDP_ABORTED;
            goto out;
        }

        // Make sure we can access the full header
        if ((void *)(iphdr + 1) > data_end) {
            action = XDP_ABORTED;
            goto out;
        }

        // Calculate size of IP header content
        int header_size = iphdr->ihl * 4;
        if ((void *)iphdr + header_size > data_end) {
            action = XDP_ABORTED;
            goto out;
        }

        iphdr->check = 0;
        //bpf_printk("IP Header dump:\n");
        //bpf_printk("IP Header size:%d\n", header_size);
        //print_hex((const unsigned char *)iphdr, header_size);
        //dump_ip_header(iphdr);
        //print_hex((const unsigned char *)iphdr, 20);

        // Calculate hash of IP header with secret key
        int ret = compute_keyed_hash(ctx, (BYTE *)iphdr, header_size, hash_result);
        //bpf_printk("Hash result:");
        //print_hex((const unsigned char *) hash_result, SHA256_BLOCK_SIZE);


        // Check if hash calculation succeeded
        if (ret == 0) {
            // Add the hash as an IP option
            if (add_ip_option_hash(ctx, iphdr, hash_result) < 0) {
                action = XDP_PASS;
            }
        } else {
            // Hash calculation failed
            action = XDP_PASS;
        }
    } else if (eth_type == bpf_htons(ETH_P_IPV6)) {
        // IPv6 processing not implemented in this example
        action = XDP_PASS;
    }

out:
    return xdp_stats_record_action(ctx, action);
}

#else

SEC("xdp_patch_ports")
int xdp_patch_ports_func(struct xdp_md *ctx)
{
	int action = XDP_PASS;
	int eth_type, ip_type;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	struct udphdr *udphdr;
	struct tcphdr *tcphdr;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0) {
		action = XDP_ABORTED;
		goto out;
	}

	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
	} else {
		goto out;
	}

	if (ip_type == IPPROTO_UDP) {
		if (parse_udphdr(&nh, data_end, &udphdr) < 0) {
			action = XDP_ABORTED;
			goto out;
		}

		/*
		 * We need to update the packet checksum when modifying the header.
		 * RFC1071 contains an algorithm for in-place updating, which is what we use here
		 * since we're always just decrementing the port number. Another option would be
		 * to recompute the full checksum, like:
		 *
		 * struct udphdr udphdr_old;
		 * __u32 csum = udphdr->check;
		 * udphdr_old = *udphdr;
		 * udphdr->dest = bpf_htons(bpf_ntohs(udphdr->dest) - 1);
		 * csum = bpf_csum_diff((__be32 *)&udphdr_old, 4, (__be32 *)udphdr, 4, ~csum);
		 * udphdr->check = csum_fold_helper(csum);
		 */

		udphdr->dest = bpf_htons(bpf_ntohs(udphdr->dest) - 1);
		udphdr->check += bpf_htons(1);
		if (!udphdr->check)
			udphdr->check += bpf_htons(1);
	} else if (ip_type == IPPROTO_TCP) {
		if (parse_tcphdr(&nh, data_end, &tcphdr) < 0) {
			action = XDP_ABORTED;
			goto out;
		}
		tcphdr->dest = bpf_htons(bpf_ntohs(tcphdr->dest) - 1);
		tcphdr->check += bpf_htons(1);
		if (!tcphdr->check)
			tcphdr->check += bpf_htons(1);
	}

out:
	return xdp_stats_record_action(ctx, action);
}

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx)
{
    return XDP_PASS;
}
#endif

char _license[] SEC("license") = "GPL";
