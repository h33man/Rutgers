/*********************************************************************
* Filename:   tc_prog_kern_02.c
* Author:     Converted from XDP to TC with kfunc support
* Description: TC version of IP hash program with SHA-256 functionality
*              Supports runtime selection between custom and kfunc SHA256
*********************************************************************/

/*************************** HEADER FILES ***************************/
#if 0
/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/types.h>
#include <linux/pkt_cls.h>
#include <stdint.h>
#include <stdio.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The parsing helper functions
#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"
#endif

#include "sha256.h"
#include "sha256_kfunc.h"

#ifdef BPF_DEBUG
    __u8 debug = 1;
#else
    __u8 debug = 0;
#endif


/* Defines tc_stats_map instead of xdp_stats_map */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, struct datarec);
} tc_stats_map SEC(".maps");

#if 0
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

/* Secret key for HMAC-like functionality */
static const BYTE SECRET_KEY[16] = {
    0x4b, 0x75, 0x8f, 0x94, 0x98, 0xd3, 0x31, 0x26,
    0x16, 0xec, 0xc2, 0x61, 0x99, 0x43, 0x76, 0x45
};
#endif
/****************************** BPF MAPS ******************************/

#if 0
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

/****************************** HELPER FUNCTIONS ******************************/

// TC stats recording function
static __always_inline __u32 tc_stats_record_action(struct __sk_buff *ctx, __u32 action)
{
    if (action >= 5)
        return action;

    __u32 key = action;
    struct datarec *rec = bpf_map_lookup_elem(&tc_stats_map, &key);
    if (!rec)
        return action;

    rec->rx_packets++;
    rec->rx_bytes += (ctx->data_end - ctx->data);

    return action;
}

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

/****************************** IP CHECKSUM ******************************/

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

/****************************** HASH COMPUTATION WITH RUNTIME SELECTION ******************************/

static __always_inline int compute_keyed_hash_tc(struct __sk_buff *skb, const BYTE *data, 
                                                  size_t data_len, BYTE hash[SHA256_BLOCK_SIZE])
{
    __u32 key = 0;
    void *data_end = (void *)(long)skb->data_end;

    // Get config to check use_kfunc flag
    struct {
        __u8 use_kfunc;
    } *config_ctx;

    config_ctx = bpf_map_lookup_elem(&config_map, &key);
    if (!config_ctx)
        return -1;

    // Verify data pointer is within packet bounds
    if ((void *)data + data_len > data_end) {
        return -1;
    }

    // Runtime selection: use kfunc or custom SHA256 based on use_kfunc flag
    if (config_ctx->use_kfunc) {
        // Use kernel SHA256 kfunc
        bpf_printk("TC: Using kfunc SHA256\n");
        int ret = bpf_sha256_keyed_hash(SECRET_KEY, 16,
                                       (const __u8 *)data,
                                       data_len,
                                       hash);
        return ret;
    } else {
        // Use custom SHA256 implementation
        bpf_printk("TC: Using custom SHA256\n");
        
        struct {BYTE buffer[128];} *temp;
        temp = bpf_map_lookup_elem(&sha256_temp_map, &key);
        if (!temp)
            return -1;

        // Initialize buffer with key
        temp->buffer[0] = SECRET_KEY[0];
        temp->buffer[1] = SECRET_KEY[1];
        temp->buffer[2] = SECRET_KEY[2];
        temp->buffer[3] = SECRET_KEY[3];
        temp->buffer[4] = SECRET_KEY[4];
        temp->buffer[5] = SECRET_KEY[5];
        temp->buffer[6] = SECRET_KEY[6];
        temp->buffer[7] = SECRET_KEY[7];
        temp->buffer[8] = SECRET_KEY[8];
        temp->buffer[9] = SECRET_KEY[9];
        temp->buffer[10] = SECRET_KEY[10];
        temp->buffer[11] = SECRET_KEY[11];
        temp->buffer[12] = SECRET_KEY[12];
        temp->buffer[13] = SECRET_KEY[13];
        temp->buffer[14] = SECRET_KEY[14];
        temp->buffer[15] = SECRET_KEY[15];

        // Limit copy size
        size_t max_copy = data_len;
        if (max_copy > 20)
            max_copy = 20;

        // Copy data bytes
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

        return 0;
    }
}
#endif

/****************************** IP OPTION MANIPULATION ******************************/

static __always_inline int add_ip_option_hash_tc(struct __sk_buff *skb,
        struct iphdr *ip_orig, BYTE hash[SHA256_BLOCK_SIZE])
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    uint8_t option_len = IP_OPT_HASH_LEN;
    int i;

    // Save original headers before bpf_skb_change_head invalidates pointers
    struct ethhdr *orig_eth = (struct ethhdr *)data;
    if ((void *)(orig_eth + 1) > data_end)
        return -1;

    struct iphdr *orig_ip = (struct iphdr *)(data + ETHERNET_HEADER_SIZE);
    if ((void *)(orig_ip + 1) > data_end)
        return -1;

    struct ethhdr saved_eth = *orig_eth;
    struct iphdr saved_ip = *orig_ip;

    // Use bpf_skb_change_head to add space
    if (bpf_skb_change_head(skb, IP_OPT_HASH_LEN, 0))
        return -1;

    // After change_head, all previous pointers are invalidated
    data_end = (void *)(long)skb->data_end;
    data = (void *)(long)skb->data;

    // Restore Ethernet header
    struct ethhdr *new_eth = (struct ethhdr *)data;
    if ((void *)(new_eth + 1) > data_end)
        return -1;
    *new_eth = saved_eth;

    // Restore and update IP header
    struct iphdr *new_ip = (struct iphdr *)(data + ETHERNET_HEADER_SIZE);
    if ((void *)(new_ip + 1) > data_end)
        return -1;
    *new_ip = saved_ip;

    new_ip->ihl = (sizeof(struct iphdr) + IP_OPT_HASH_LEN) / 4;
    new_ip->tot_len = bpf_htons(bpf_ntohs(new_ip->tot_len) + IP_OPT_HASH_LEN);
    new_ip->check = 0;

    // Add option after IP header
    uint8_t *options = (uint8_t *)(new_ip + 1);
    if ((void *)(options + option_len) > data_end)
        return -1;

    options[0] = IP_OPT_HASH_ID;
    options[1] = option_len;
    options[2] = 0x12;
    options[3] = 0x34;

    // Copy hash value
    #pragma unroll
    for (i = 0; i < 32; i += 4) {
        if (i + 3 < 32 && 4 + i + 3 < option_len) {
            options[4 + i] = hash[i];
            options[4 + i + 1] = hash[i + 1];
            options[4 + i + 2] = hash[i + 2];
            options[4 + i + 3] = hash[i + 3];
        }
    }

    // Calculate checksum
    int header_len = new_ip->ihl * 4;
    new_ip->check = calculate_ip_checksum((const void *)new_ip, header_len);

    bpf_printk("TC: Hash added, checksum: 0x%04x\n", new_ip->check);

    return 0;
}

/****************************** TC PROGRAMS ******************************/

/**
 * TC program to add hash to IP packets with runtime selection
 */
#if 0
SEC("tc_ip_hash")
int tc_ip_hash_func(struct __sk_buff *ctx)
{
    int action = TC_ACT_OK;
    int eth_type, ip_type;
    struct ethhdr *eth;
    struct iphdr *iphdr;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct hdr_cursor nh = { .pos = data };
    BYTE hash_result[SHA256_BLOCK_SIZE];

    __builtin_memset(hash_result, 0, SHA256_BLOCK_SIZE);

    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type < 0) {
        action = TC_ACT_SHOT;
        goto out;
    }

    // Process IPv4 packets
    if (eth_type == bpf_htons(ETH_P_IP)) {
        ip_type = parse_iphdr(&nh, data_end, &iphdr);
        if (ip_type < 0) {
            action = TC_ACT_SHOT;
            goto out;
        }

        if ((void *)(iphdr + 1) > data_end) {
            action = TC_ACT_SHOT;
            goto out;
        }

        int header_size = iphdr->ihl * 4;
        if ((void *)iphdr + header_size > data_end) {
            action = TC_ACT_SHOT;
            goto out;
        }

        iphdr->check = 0;

        bpf_printk("TC: Processing packet for hash addition\n");

        // Calculate hash with runtime selection (custom or kfunc)
        int ret = compute_keyed_hash_tc(ctx, (BYTE *)iphdr, header_size, hash_result);

        if (ret == 0) {
            // Add the hash as an IP option
            if (add_ip_option_hash_tc(ctx, iphdr, hash_result) < 0) {
                bpf_printk("TC: Failed to add hash option\n");
                action = TC_ACT_OK;
            } else {
                bpf_printk("TC: Hash option added successfully\n");
            }
        } else {
            bpf_printk("TC: Hash calculation failed\n");
            action = TC_ACT_OK;
        }
    } else if (eth_type == bpf_htons(ETH_P_IPV6)) {
        action = TC_ACT_OK;
    }

out:
    return tc_stats_record_action(ctx, action);
}
#endif

/**
 * TC program for adding hash to packets with runtime selection
 */
SEC("tc_ip_hash")
int tc_ip_hash_func(struct __sk_buff *ctx)
{
    int action = TC_ACT_OK;
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

#if 0
    struct {
        BYTE extracted_hash[SHA256_BLOCK_SIZE];
        BYTE computed_hash[SHA256_BLOCK_SIZE];
        struct iphdr original_header;
        uint8_t headers_buffer[ETHERNET_HEADER_SIZE + 60];
    } *verify_ctx;

    verify_ctx = bpf_map_lookup_elem(&verify_map, &key);
    if (!verify_ctx)
        return -1;
#endif

    __builtin_memset(hash_result, 0, SHA256_BLOCK_SIZE);

    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type < 0) {
        action = TC_ACT_SHOT;
        goto out;
    }

    if (eth_type == bpf_htons(ETH_P_IP)) {
        ip_type = parse_iphdr(&nh, data_end, &iphdr);
        if (ip_type < 0) {
            action = TC_ACT_SHOT;
            goto out;
        }

        // Only processing UDP
        if (iphdr->protocol != IPPROTO_UDP) {
            bpf_printk("Not a UDP packet, passing through\n");
            action = TC_ACT_OK;
            goto out;
        }

        if ((void *)(iphdr + 1) > data_end) {
            action = TC_ACT_SHOT;
            goto out;
        }

        int header_size = iphdr->ihl * 4;
        if ((void *)iphdr + header_size > data_end) {
            action = TC_ACT_SHOT;
            goto out;
        }

        struct ip_auth_data *auth_data = lookup_auth_key(iphdr->saddr);
        if (!auth_data) {
            bpf_printk("No authentication key found for source IP, passing without hash\n");
            action = TC_ACT_OK;
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
	    bpf_printk("Using kfunc SHA256 for hash\n");
	    ret = bpf_sha256_keyed_hash(auth_data->key, 16, //dynamic_key, 16,
				       (BYTE *)iphdr, //(const __u8 *)&verify_ctx->original_header,
				       header_size, //sizeof(struct iphdr), 
				       hash_result);
	} else {
	    // Use custom SHA256 implementation
	    bpf_printk("Using custom SHA256 for hash\n");
	    ret = compute_keyed_hash_from_map_dynamic((BYTE *)iphdr, header_size,
	                                                   hash_result, auth_data->key);
	}

        if (ret == 0) {
            if (add_ip_option_hash_tc(ctx, iphdr, hash_result) < 0) {
                bpf_printk("Failed to add hash option\n");
                action = TC_ACT_OK;
            } else {
                if (debug)
                    bpf_printk("Hash option added successfully with dynamic key\n");
            }
        } else {
            bpf_printk("Failed to compute hash\n");
            action = TC_ACT_OK;
        }
    } else if (eth_type == bpf_htons(ETH_P_IPV6)) {
        action = TC_ACT_OK;
    }

out:
    return tc_stats_record_action(ctx, action);
}


SEC("tc_pass")
int tc_pass_func(struct __sk_buff *ctx)
{
    // TIMING: Calculate total latency for baseline measurement
    __u64 start_time = bpf_ktime_get_ns();
    artificial_latency_compute_ops();

    __u64 end_time = bpf_ktime_get_ns();
    __u64 total_latency = end_time - start_time;

    bpf_printk("Latency in TC: %d ns\n", total_latency);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
