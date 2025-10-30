/*********************************************************************
* XDP Program for SHA256-Hash key Source IP lookup and HMAC computation
* 
* Author: Himanshu Chandra 
* Email:  himanshu.chandra@rutgers.edu
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details: Implementation of IP packet authentication using SHA-256 hashing.
*          Includes LPM trie-based key lookup for per-source-IP authentication.
*          Custom SHA-256 implementation in eBPF and kernel, runtime selection via use_kfunc flag.
*********************************************************************/
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
#include "sha256.h"

#ifdef BPF_DEBUG
    __u8 debug = 1;
#else
    __u8 debug = 0;
#endif

#if 0
/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The parsing helper functions
#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

#include "sha256_kfunc.h"

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
#define IP_OPT_HASH_ID 25
#define IP_OPT_HASH_LEN 36
#define ETHERNET_HEADER_SIZE 14

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

/****************************** COMMON STRUCTURES ******************************/

// Authentication data structure for IP header authentication
struct ip_auth_data {
    __u32 field_mask;
    __u8 key[16];
    __u8 action;
};

// IPv4 LPM key structure
struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 data;
};

// Action definitions
#define ACTION_DROP      0
#define ACTION_ALLOW     1
#define ACTION_MARK      2

// Statistics indices
#define STAT_TOTAL_PACKETS         0
#define STAT_AUTH_SUCCESS          1
#define STAT_AUTH_FAILURE          2
#define STAT_NO_AUTH_RULE          3
#define STAT_DROPPED_PACKETS       4
#define STAT_KEY_LOOKUP_SUCCESS    5
#define STAT_KEY_LOOKUP_FAILURE    6

/****************************** BPF MAPS ******************************/

// LPM trie map for source IP authentication keys
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct ip_auth_data);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 1000);
} src_ip_key_map SEC(".maps");

// Statistics map for tracking authentication results
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 10);
} auth_stats_map SEC(".maps");

// BPF map to store the SHA256 context (for custom implementation)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, SHA256_CTX);
} sha256_ctx_map SEC(".maps");

// Map for temporary data buffers (for custom implementation)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct {
        BYTE buffer[128];
        WORD m[64];
    });
} sha256_temp_map SEC(".maps");

// Map for kfunc hash computation
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct {
        __u8 hash_output[SHA256_BLOCK_SIZE];
    });
} kfunc_hash_map SEC(".maps");

// Separate config map for runtime flags
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct {
        __u8 use_kfunc;  // Runtime flag: 0 = custom SHA256, 1 = kfunc SHA256
    });
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} config_map SEC(".maps");
#endif

// Map for verification to avoid stack overflow
// Extended with use_kfunc flag for runtime selection
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct {
        BYTE extracted_hash[SHA256_BLOCK_SIZE];
        BYTE computed_hash[SHA256_BLOCK_SIZE];
        struct iphdr original_header;
        uint8_t headers_buffer[ETHERNET_HEADER_SIZE + 60];
    });
} verify_map SEC(".maps");

#if 0
/****************************** CUSTOM SHA256 IMPLEMENTATION ******************************/

static __always_inline int sha256_transform(const BYTE data[])
{
    __u32 key = 0;
    SHA256_CTX *ctx;
    struct {WORD m[64];} *temp;
    WORD a, b, c, d, e, f, g, h, i, t1, t2;

    ctx = bpf_map_lookup_elem(&sha256_ctx_map, &key);
    if (!ctx)
        return -1;

    temp = bpf_map_lookup_elem(&sha256_temp_map, &key);
    if (!temp)
        return -1;

    for (i = 0; i < 16; ++i) {
        if (i >= 16) break;
        int j = i * 4;
        if (j + 3 >= 64) break;
        temp->m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    }

    for (i = 16; i < 64; ++i) {
        if (i >= 64) break;
        if (i - 2 < 0 || i - 7 < 0 || i - 15 < 0 || i - 16 < 0) break;
        temp->m[i] = SIG1(temp->m[i - 2]) + temp->m[i - 7] + SIG0(temp->m[i - 15]) + temp->m[i - 16];
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        if (i >= 64) break;
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

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;

    return 0;
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

    ctx = bpf_map_lookup_elem(&sha256_ctx_map, &key);
    if (!ctx)
        return -1;

    for (i = 0; i < len; ++i) {
        if (i >= len) break;
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

    ctx = bpf_map_lookup_elem(&sha256_ctx_map, &key);
    if (!ctx)
        return -1;

    i = ctx->datalen;

    if (i >= 64) {
        i = 0;
    }

    if (ctx->datalen < 56) {
        if (i < 64) {
            ctx->data[i++] = 0x80;
        }

        #pragma unroll
        for (int j = 0; j < 56; j++) {
            if (i < 56 && i < 64) {
                ctx->data[i] = 0x00;
                i++;
            }
        }
    }
    else {
        if (i < 64) {
            ctx->data[i++] = 0x80;
        }

        #pragma unroll
        for (int j = 0; j < 64; j++) {
            if (i < 64) {
                ctx->data[i] = 0x00;
                i++;
            }
        }

        sha256_transform(ctx->data);

        #pragma unroll
        for (int j = 0; j < 56; j++) {
            if (j < 56 && j < 64) {
                ctx->data[j] = 0x00;
            }
        }
        i = 56;
    }

    ctx->bitlen += ctx->datalen * 8;

    if (56 < 64) ctx->data[56] = ctx->bitlen >> 56;
    if (57 < 64) ctx->data[57] = ctx->bitlen >> 48;
    if (58 < 64) ctx->data[58] = ctx->bitlen >> 40;
    if (59 < 64) ctx->data[59] = ctx->bitlen >> 32;
    if (60 < 64) ctx->data[60] = ctx->bitlen >> 24;
    if (61 < 64) ctx->data[61] = ctx->bitlen >> 16;
    if (62 < 64) ctx->data[62] = ctx->bitlen >> 8;
    if (63 < 64) ctx->data[63] = ctx->bitlen;

    sha256_transform(ctx->data); 

    for (i = 0; i < 4; ++i) {
        if (i >= 4) break;

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

/****************************** COMMON HELPER FUNCTIONS ******************************/

/**
 * Lookup authentication key for source IP using LPM trie
 */
static __always_inline struct ip_auth_data* lookup_auth_key(__u32 src_ip) {
    struct ipv4_lpm_key src_key;
    struct ip_auth_data *auth_data;

    __u64 start_time = bpf_ktime_get_ns();
    __u64 end_time;
    __u64 total_latency;

    // Try exact match first (32-bit prefix)
    src_key.prefixlen = 32;
    src_key.data = src_ip;
    auth_data = bpf_map_lookup_elem(&src_ip_key_map, &src_key);

    if (auth_data) {
        goto out;
    }

    // Try /24 subnet match
    src_key.prefixlen = 24;
    src_key.data = src_ip & bpf_htonl(0xFFFFFF00);
    auth_data = bpf_map_lookup_elem(&src_ip_key_map, &src_key);

    if (auth_data) {
        goto out;
    }

    // Try /16 subnet match
    src_key.prefixlen = 16;
    src_key.data = src_ip & bpf_htonl(0xFFFF0000);
    auth_data = bpf_map_lookup_elem(&src_ip_key_map, &src_key);

    if (auth_data) {
        goto out;
    }

    // Try /8 subnet match
    src_key.prefixlen = 8;
    src_key.data = src_ip & bpf_htonl(0xFF000000);
    auth_data = bpf_map_lookup_elem(&src_ip_key_map, &src_key);

out:
    if (auth_data) {
	    end_time = bpf_ktime_get_ns();
	    total_latency = end_time - start_time;

	    bpf_printk("Key lookup time: %llu ns\n", total_latency);
    }
    
    return auth_data;
}

/**
 * Calculate the IP header checksum
 */
static __always_inline uint16_t calculate_ip_checksum(const void *header, int len) {
    const uint16_t *buf = header;
    uint32_t sum = 0;

    for (int i = 0; i < len / 2; i++) {
        if (i >= len / 2) break;
        sum += buf[i];
    }

    if (len % 2) {
        sum += ((const uint8_t *)header)[len - 1];
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

/**
 * Compute hash from map data with dynamic key (custom SHA256)
 */
static __always_inline int compute_keyed_hash_from_map_dynamic(const BYTE *data,
        size_t data_len, BYTE hash[SHA256_BLOCK_SIZE], const BYTE *dynamic_key)
{
    __u32 key = 0;
    struct {BYTE buffer[128];} *temp;

    temp = bpf_map_lookup_elem(&sha256_temp_map, &key);
    if (!temp)
        return -1;

    // Initialize buffer with dynamic key
    temp->buffer[0] = dynamic_key[0];
    temp->buffer[1] = dynamic_key[1];
    temp->buffer[2] = dynamic_key[2];
    temp->buffer[3] = dynamic_key[3];
    temp->buffer[4] = dynamic_key[4];
    temp->buffer[5] = dynamic_key[5];
    temp->buffer[6] = dynamic_key[6];
    temp->buffer[7] = dynamic_key[7];
    temp->buffer[8] = dynamic_key[8];
    temp->buffer[9] = dynamic_key[9];
    temp->buffer[10] = dynamic_key[10];
    temp->buffer[11] = dynamic_key[11];
    temp->buffer[12] = dynamic_key[12];
    temp->buffer[13] = dynamic_key[13];
    temp->buffer[14] = dynamic_key[14];
    temp->buffer[15] = dynamic_key[15];

    size_t max_copy = data_len;
    if (max_copy > 20)
        max_copy = 20;

    // Copy data bytes
    if (max_copy >= 1) temp->buffer[16 + 0] = data[0];
    if (max_copy >= 2) temp->buffer[16 + 1] = data[1];
    if (max_copy >= 3) temp->buffer[16 + 2] = data[2];
    if (max_copy >= 4) temp->buffer[16 + 3] = data[3];
    if (max_copy >= 5) temp->buffer[16 + 4] = data[4];
    if (max_copy >= 6) temp->buffer[16 + 5] = data[5];
    if (max_copy >= 7) temp->buffer[16 + 6] = data[6];
    if (max_copy >= 8) temp->buffer[16 + 7] = data[7];
    if (max_copy >= 9) temp->buffer[16 + 8] = data[8];
    if (max_copy >= 10) temp->buffer[16 + 9] = data[9];
    if (max_copy >= 11) temp->buffer[16 + 10] = data[10];
    if (max_copy >= 12) temp->buffer[16 + 11] = data[11];
    if (max_copy >= 13) temp->buffer[16 + 12] = data[12];
    if (max_copy >= 14) temp->buffer[16 + 13] = data[13];
    if (max_copy >= 15) temp->buffer[16 + 14] = data[14];
    if (max_copy >= 16) temp->buffer[16 + 15] = data[15];
    if (max_copy >= 17) temp->buffer[16 + 16] = data[16];
    if (max_copy >= 18) temp->buffer[16 + 17] = data[17];
    if (max_copy >= 19) temp->buffer[16 + 18] = data[18];
    if (max_copy >= 20) temp->buffer[16 + 19] = data[19];

    sha256_init();
    sha256_update(temp->buffer, 16 + max_copy);
    sha256_final(hash);

    return 0;
}
#endif

/****************************** HASH VERIFICATION AND COMPUTATION ******************************/

/**
 * Verify IP hash with runtime selection (custom or kfunc)
 * Reads use_kfunc flag from verify_map to decide which implementation to use
 */
static __always_inline int verify_ip_hash_with_key(struct xdp_md *ctx, 
                                                    const BYTE *dynamic_key)
{
    __u32 key = 0;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct {
        __u8 use_kfunc;  // Runtime flag: 0 = custom SHA256, 1 = kfunc SHA256
    } *config_ctx;

    config_ctx = bpf_map_lookup_elem(&config_map, &key);
    if (!config_ctx)
        return -1;

    struct {
        BYTE extracted_hash[SHA256_BLOCK_SIZE];
        BYTE computed_hash[SHA256_BLOCK_SIZE];
        struct iphdr original_header;
        uint8_t headers_buffer[ETHERNET_HEADER_SIZE + 60];
    } *verify_ctx;

    verify_ctx = bpf_map_lookup_elem(&verify_map, &key);
    if (!verify_ctx)
        return -1;

    struct iphdr *ip_header = (struct iphdr *)(data + ETHERNET_HEADER_SIZE);
    if ((void *)(ip_header + 1) > data_end)
        return -1;

    int header_size = ip_header->ihl * 4;
    int options_len = header_size - sizeof(struct iphdr);

    if (header_size < 20 || header_size > 60 || options_len <= 0) {
        return -1;
    }

    if ((void *)ip_header + header_size > data_end) {
        return -1;
    }

    uint8_t *safe_ip_header = verify_ctx->headers_buffer + ETHERNET_HEADER_SIZE;

    #pragma unroll
    for (int i = 0; i < 60; i++) {
        if (i < header_size && (void *)ip_header + i < data_end) {
            safe_ip_header[i] = *((uint8_t *)ip_header + i);
        } else if (i < 60) {
            safe_ip_header[i] = 0;
        }
    }

    struct iphdr *safe_ip = (struct iphdr *)safe_ip_header;
    uint8_t *options = safe_ip_header + sizeof(struct iphdr);

    #pragma unroll
    for (int x = 0; x < 32; x++) {
        verify_ctx->extracted_hash[x] = 0;
        verify_ctx->computed_hash[x] = 0;
    }

    int found_hash = 0;

    #pragma unroll
    for (int start_pos = 0; start_pos <= 4 && !found_hash; start_pos++) {
        if (start_pos >= options_len) continue;
        if (start_pos + IP_OPT_HASH_LEN > options_len) continue;

        uint8_t opt_type = options[start_pos];
        if (opt_type == 0) break;
        if (opt_type == 1) continue;

        if (start_pos + 1 < options_len) {
            uint8_t opt_len = options[start_pos + 1];

            if (opt_type == IP_OPT_HASH_ID && opt_len == IP_OPT_HASH_LEN) {
                if (start_pos + 3 < options_len &&
                    options[start_pos + 2] == 0x12 &&
                    options[start_pos + 3] == 0x34) {

                    if (debug)
                        bpf_printk("Found hash option for verification at pos %d\n", start_pos);

                    #pragma unroll
                    for (int j = 0; j < 32; j++) {
                        if (start_pos + 4 + j < options_len && j < SHA256_BLOCK_SIZE) {
                            verify_ctx->extracted_hash[j] = options[start_pos + 4 + j];
                        }
                    }

                    found_hash = 1;
                }
            }
        }
    }

    if (!found_hash) {
        bpf_printk("Hash option not found\n");
        return -1;
    }

    verify_ctx->original_header = *safe_ip;
    verify_ctx->original_header.ihl = 5;
    verify_ctx->original_header.tot_len = bpf_htons(bpf_ntohs(verify_ctx->original_header.tot_len) - options_len);
    verify_ctx->original_header.check = 0;

    // Runtime selection: use kfunc or custom SHA256 based on use_kfunc flag
    int ret;
    if (config_ctx->use_kfunc) {
        // Use kernel SHA256 kfunc
        bpf_printk("Using kfunc SHA256 for verification\n");
        ret = bpf_sha256_keyed_hash(dynamic_key, 16,
                                   (const __u8 *)&verify_ctx->original_header,
                                   sizeof(struct iphdr), 
                                   verify_ctx->computed_hash);
    } else {
        // Use custom SHA256 implementation
        bpf_printk("Using custom SHA256 for verification\n");
        ret = compute_keyed_hash_from_map_dynamic((BYTE *)&verify_ctx->original_header,
                                            sizeof(struct iphdr), verify_ctx->computed_hash, dynamic_key);
    }

    if (ret != 0) {
        bpf_printk("Failed to compute hash for verification\n");
        return -1;
    }

    int hash_match = 1;
    #pragma unroll
    for (int k = 0; k < 32; k++) {
        if (k < SHA256_BLOCK_SIZE &&
            verify_ctx->extracted_hash[k] != verify_ctx->computed_hash[k]) {
            hash_match = 0;
            break;
        }
    }

    if (hash_match) {
        if (debug)
            bpf_printk("Hash verification PASSED with dynamic key\n");
        return 0;
    } else {
        bpf_printk("Hash verification FAILED with dynamic key\n");
        return -2;
    }
}

/****************************** IP OPTION MANIPULATION ******************************/

/**
 * Remove IP option hash from packet
 */
static __always_inline int remove_ip_option_hash(struct xdp_md *ctx,
                                                  struct iphdr *ip_orig)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    uint8_t headers_copy[ETHERNET_HEADER_SIZE + sizeof(struct iphdr)];

    if ((void *)data + sizeof(headers_copy) > data_end)
        return -1;

    __builtin_memcpy(headers_copy, data, sizeof(headers_copy));

    if (bpf_xdp_adjust_head(ctx, (int)IP_OPT_HASH_LEN))
        return -1;

    data_end = (void *)(long)ctx->data_end;
    data = (void *)(long)ctx->data;

    if ((void *)data + sizeof(headers_copy) > data_end)
        return -1;

    __builtin_memcpy(data, headers_copy, sizeof(headers_copy));

    struct iphdr *new_ip = (struct iphdr *)(data + ETHERNET_HEADER_SIZE);
    if ((void *)(new_ip + 1) > data_end)
        return -1;

    new_ip->ihl = (sizeof(struct iphdr)) / 4;
    new_ip->tot_len = bpf_htons(bpf_ntohs(new_ip->tot_len) - IP_OPT_HASH_LEN);
    new_ip->check = 0;

    int header_len = new_ip->ihl * 4;
    new_ip->check = calculate_ip_checksum((const void *)new_ip, header_len);

    if (debug)
        bpf_printk("Hash option removed, new checksum: 0x%04x\n", new_ip->check);

    return 0;
}

/**
 * Add IP option with hash with runtime selection (custom or kfunc)
 */
static __always_inline int add_ip_option_hash(struct xdp_md *ctx,
                                              struct iphdr *ip_orig,
                                              const BYTE *hash,
                                              const __u8 *dynamic_key)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    uint8_t headers_copy[ETHERNET_HEADER_SIZE + sizeof(struct iphdr)];
    uint8_t option_len = IP_OPT_HASH_LEN;
    int ret = -1;

    if ((void *)data + sizeof(headers_copy) > data_end)
        return -1;

    __builtin_memcpy(headers_copy, data, sizeof(headers_copy));

    // Check if we should use kfunc or custom implementation
    __u32 key = 0;
    struct {
        __u8 hash_output[SHA256_BLOCK_SIZE];
    } *hash_ctx;

    hash_ctx = bpf_map_lookup_elem(&kfunc_hash_map, &key);
    if (hash_ctx) {
        // Try to use kfunc - if available, compute hash using kfunc
        if (debug)
            bpf_printk("Attempting to compute hash using kfunc\n");
        struct iphdr *header_copy = (struct iphdr *)(headers_copy + ETHERNET_HEADER_SIZE);
        header_copy->check = 0;

        ret = bpf_sha256_keyed_hash(dynamic_key, 16, 
                                    (const __u8 *)header_copy, sizeof(*header_copy), 
                                    hash_ctx->hash_output);
        if (ret == 0) {
            if (debug)
                bpf_printk("Using kfunc SHA256 for hash addition\n");
            // Use hash computed by kfunc
            if (bpf_xdp_adjust_head(ctx, 0 - (int)IP_OPT_HASH_LEN))
                return -1;

            data_end = (void *)(long)ctx->data_end;
            data = (void *)(long)ctx->data;

            if ((void *)data + sizeof(headers_copy) > data_end)
                return -1;

            __builtin_memcpy(data, headers_copy, sizeof(headers_copy));

            struct iphdr *new_ip = (struct iphdr *)(data + ETHERNET_HEADER_SIZE);
            if ((void *)(new_ip + 1) > data_end)
                return -1;

            new_ip->ihl = (sizeof(struct iphdr) + IP_OPT_HASH_LEN) / 4;
            new_ip->tot_len = bpf_htons(bpf_ntohs(new_ip->tot_len) + IP_OPT_HASH_LEN);
            new_ip->check = 0;

            uint8_t *options = (uint8_t *)(new_ip + 1);
            if ((void *)(options + option_len) > data_end)
                return -1;

            options[0] = IP_OPT_HASH_ID;
            options[1] = option_len;
            options[2] = 0x12;
            options[3] = 0x34;

            #pragma unroll
            for (int i = 0; i < 32; i += 4) {
                if (i + 3 < 32 && 4 + i + 3 < option_len) {
                    options[4 + i] = hash_ctx->hash_output[i];
                    options[4 + i + 1] = hash_ctx->hash_output[i + 1];
                    options[4 + i + 2] = hash_ctx->hash_output[i + 2];
                    options[4 + i + 3] = hash_ctx->hash_output[i + 3];
                }
            }

            int header_len = new_ip->ihl * 4;
            new_ip->check = calculate_ip_checksum((const void *)new_ip, header_len);
            
            if (debug)
                bpf_printk("Hash added successfully (kfunc), new checksum: 0x%04x\n", new_ip->check);
            return 0;
        }
    }

    // If kfunc failed or not available, use custom SHA256
    if (debug)
        bpf_printk("Using custom SHA256 for hash addition\n");
    
    if (bpf_xdp_adjust_head(ctx, 0 - (int)IP_OPT_HASH_LEN))
        return -1;

    data_end = (void *)(long)ctx->data_end;
    data = (void *)(long)ctx->data;

    if ((void *)data + sizeof(headers_copy) > data_end)
        return -1;

    __builtin_memcpy(data, headers_copy, sizeof(headers_copy));

    struct iphdr *new_ip = (struct iphdr *)(data + ETHERNET_HEADER_SIZE);
    if ((void *)(new_ip + 1) > data_end)
        return -1;

    new_ip->ihl = (sizeof(struct iphdr) + IP_OPT_HASH_LEN) / 4;
    new_ip->tot_len = bpf_htons(bpf_ntohs(new_ip->tot_len) + IP_OPT_HASH_LEN);
    new_ip->check = 0;

    uint8_t *options = (uint8_t *)(new_ip + 1);
    if ((void *)(options + option_len) > data_end)
        return -1;

    options[0] = IP_OPT_HASH_ID;
    options[1] = option_len;
    options[2] = 0x12;
    options[3] = 0x34;

    #pragma unroll
    for (int i = 0; i < 32; i += 4) {
        if (i + 3 < 32 && 4 + i + 3 < option_len) {
            options[4 + i] = hash[i];
            options[4 + i + 1] = hash[i + 1];
            options[4 + i + 2] = hash[i + 2];
            options[4 + i + 3] = hash[i + 3];
        }
    }

    int header_len = new_ip->ihl * 4;
    new_ip->check = calculate_ip_checksum((const void *)new_ip, header_len);
    
    if (debug)
        bpf_printk("Hash added successfully (custom), new checksum: 0x%04x\n", new_ip->check);

    return 0;
}

/****************************** XDP PROGRAMS ******************************/

/**
 * XDP program for hash verification and removal with runtime selection
 */
SEC("xdp_ip_hash_verify")
int xdp_ip_hash_verify_func(struct xdp_md *ctx)
{
    int action = XDP_PASS;
    int eth_type, ip_type;
    struct ethhdr *eth;
    struct iphdr *iphdr;
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
        if (ip_type < 0) {
            action = XDP_ABORTED;
            goto out;
        }

        // Only processing UDP
        if (iphdr->protocol != IPPROTO_UDP) {
            if (debug)
                bpf_printk("Not a UDP packet, passing through\n");
            action = XDP_PASS;
            goto out;
        }

        int header_size = iphdr->ihl * 4;
        if ((void *)iphdr + header_size > data_end) {
            action = XDP_ABORTED;
            goto out;
        }

        struct ip_auth_data *auth_data = lookup_auth_key(iphdr->saddr);
        if (!auth_data) {
            if (debug)
                bpf_printk("No authentication key found for source IP %s\n", iphdr->saddr);
            action = XDP_PASS;
            goto out;
        }

        if (debug)
            bpf_printk("Found authentication key for source IP\n");

        if (iphdr->ihl > 5) {
            if (debug)
                bpf_printk("IP options present, attempting hash verification with dynamic key\n");

            int verify_result = verify_ip_hash_with_key(ctx, auth_data->key);

            if (verify_result == 0) {
                bpf_printk("Hash verification passed with dynamic key\n");

                switch (auth_data->action) {
                    case ACTION_ALLOW:
                        if (debug)
                            bpf_printk("Action: ALLOW - removing hash option\n");
                        if (remove_ip_option_hash(ctx, iphdr) == 0) {
                            if (debug)
                                bpf_printk("Hash option removed successfully\n");
                        } else {
                            bpf_printk("Failed to remove hash option\n");
                        }
                        action = XDP_PASS;
                        break;
                    case ACTION_MARK:
                        if (debug)
                            bpf_printk("Action: MARK - passing with mark\n");
                        action = XDP_PASS;
                        break;
                    case ACTION_DROP:
                        if (debug)
                            bpf_printk("Action: DROP - dropping authenticated packet\n");
                        action = XDP_DROP;
                        break;
                    default:
                        action = XDP_PASS;
                        break;
                }
            } else if (verify_result == -2) {
                bpf_printk("SECURITY: Hash verification failed - dropping packet\n");
                action = XDP_DROP;
            } else {
                bpf_printk("Hash option not found or verification error, passing packet\n");
                action = XDP_PASS;
            }
        } else {
            bpf_printk("No IP options found, passing packet through\n");
            action = XDP_PASS;
        }
    } else if (eth_type == bpf_htons(ETH_P_IPV6)) {
        action = XDP_PASS;
    }

out:
    return xdp_stats_record_action(ctx, action);
}

/**
 * XDP program for adding hash to packets with runtime selection
 */
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

    __u32 key = 0;
    struct {
        __u8 use_kfunc;  // Runtime flag: 0 = custom SHA256, 1 = kfunc SHA256
    } *config_ctx;

    config_ctx = bpf_map_lookup_elem(&config_map, &key);
    if (!config_ctx)
        return -1;

    struct {
        BYTE extracted_hash[SHA256_BLOCK_SIZE];
        BYTE computed_hash[SHA256_BLOCK_SIZE];
        struct iphdr original_header;
        uint8_t headers_buffer[ETHERNET_HEADER_SIZE + 60];
    } *verify_ctx;

    verify_ctx = bpf_map_lookup_elem(&verify_map, &key);
    if (!verify_ctx)
        return -1;

    __builtin_memset(hash_result, 0, SHA256_BLOCK_SIZE);

    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type < 0) {
        action = XDP_ABORTED;
        goto out;
    }

    if (eth_type == bpf_htons(ETH_P_IP)) {
        ip_type = parse_iphdr(&nh, data_end, &iphdr);
        if (ip_type < 0) {
            action = XDP_ABORTED;
            goto out;
        }

        // Only processing UDP
        if (iphdr->protocol != IPPROTO_UDP) {
            bpf_printk("Not a UDP packet, passing through\n");
            action = XDP_PASS;
            goto out;
        }

        if ((void *)(iphdr + 1) > data_end) {
            action = XDP_ABORTED;
            goto out;
        }

        int header_size = iphdr->ihl * 4;
        if ((void *)iphdr + header_size > data_end) {
            action = XDP_ABORTED;
            goto out;
        }

        struct ip_auth_data *auth_data = lookup_auth_key(iphdr->saddr);
        if (!auth_data) {
            bpf_printk("No authentication key found for source IP, passing without hash\n");
            action = XDP_PASS;
            goto out;
        }

        if (debug)
            bpf_printk("Found authentication key for source IP\n");

        iphdr->check = 0;

        if (debug)
            bpf_printk("=== Processing packet for hash addition with dynamic key ===\n");

        // Compute hash using custom implementation (fallback available in add_ip_option_hash)
        //int ret = compute_keyed_hash_from_map_dynamic((BYTE *)iphdr, header_size,
        //                                               hash_result, auth_data->key);

	// Runtime selection: use kfunc or custom SHA256 based on use_kfunc flag
	int ret;
	if (config_ctx->use_kfunc) {
	    // Use kernel SHA256 kfunc
	    bpf_printk("Using kfunc SHA256 for verification\n");
	    ret = bpf_sha256_keyed_hash(auth_data->key, 16, //dynamic_key, 16,
				       (BYTE *)iphdr, //(const __u8 *)&verify_ctx->original_header,
				       header_size, //sizeof(struct iphdr), 
				       hash_result);
	} else {
	    // Use custom SHA256 implementation
	    bpf_printk("Using custom SHA256 for verification\n");
	    ret = compute_keyed_hash_from_map_dynamic((BYTE *)iphdr, header_size,
	                                                   hash_result, auth_data->key);
	}

        if (ret == 0) {
            if (add_ip_option_hash(ctx, iphdr, hash_result, auth_data->key) < 0) {
                bpf_printk("Failed to add hash option\n");
                action = XDP_PASS;
            } else {
                if (debug)
                    bpf_printk("Hash option added successfully with dynamic key\n");
            }
        } else {
            bpf_printk("Failed to compute hash\n");
            action = XDP_PASS;
        }
    } else if (eth_type == bpf_htons(ETH_P_IPV6)) {
        action = XDP_PASS;
    }

out:
    return xdp_stats_record_action(ctx, action);
}

/**
 * Simple pass-through XDP program
 */
SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx)
{
    // TIMING: Calculate total latency for baseline measurement
    __u64 start_time = bpf_ktime_get_ns();
    artificial_latency_compute_ops();

    __u64 end_time = bpf_ktime_get_ns();
    __u64 total_latency = end_time - start_time;

    bpf_printk("Latency in XDP: %d ns\n", total_latency);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
//__uint(xdp_flags, XDP_FLAGS_MULTI_BUFFER);

