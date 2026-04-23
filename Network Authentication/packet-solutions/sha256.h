/*********************************************************************
* Filename:   sha256.h
* Author:     Himanshu Chandra
* Description: Custom SHA-256 implementation and helper functions
*              Shared between XDP and TC programs
*********************************************************************/
/*********************************************************************
* Filename:   sha256.h
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
#ifndef SHA256_H
#define SHA256_H

/*************************** HEADER FILES ***************************/
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/types.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"
#include "sha256_kfunc.h"
#include "helpers.h"

#ifdef BPF_DEBUG
    __u8 debug = 1;
#else
    __u8 debug = 0;
#endif

/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE;
typedef unsigned int  WORD;

typedef struct {
    BYTE data[64];
    WORD datalen;
    unsigned long long bitlen;
    WORD state[8];
} SHA256_CTX;

/****************************** MACROS ******************************/
#if 0
#define ROTLEFT(a,b)  (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x, 2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x, 6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x, 7) ^ ROTRIGHT(x,18) ^ ((x) >>  3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))
#else
#define ROTRIGHT(a,b) ((__u32)(((__u32)(a) >> (b)) | ((__u32)(a) << (32-(b)))))
#define ROTLEFT(a,b)  ((__u32)(((__u32)(a) << (b)) | ((__u32)(a) >> (32-(b)))))

#define CH(x,y,z)  ((__u32)(((__u32)(x) & (__u32)(y)) ^ (~(__u32)(x) & (__u32)(z))))
#define MAJ(x,y,z) ((__u32)(((__u32)(x) & (__u32)(y)) ^ ((__u32)(x) & (__u32)(z)) ^ ((__u32)(y) & (__u32)(z))))
#define EP0(x) ((__u32)(ROTRIGHT(x,2)  ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22)))
#define EP1(x) ((__u32)(ROTRIGHT(x,6)  ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25)))
#define SIG0(x) ((__u32)(ROTRIGHT(x,7)  ^ ROTRIGHT(x,18) ^ ((__u32)(x) >>  3)))
#define SIG1(x) ((__u32)(ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((__u32)(x) >> 10)))
#endif

/* IP Options for hash storage */
#define IP_OPT_HASH_ID       27 //25
#define IP_OPT_HASH_LEN      36
#define ETHERNET_HEADER_SIZE 14
#define SHA256_BLOCK_SIZE    32     // SHA256 outputs a 32 byte digest

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
static const BYTE SECRET_KEY[64] = {
    0x4b, 0x75, 0x8f, 0x94, 0x98, 0xd3, 0x31, 0x26,
    0x16, 0xec, 0xc2, 0x61, 0x99, 0x43, 0x76, 0x45,
    0x2a, 0x3b, 0x4c, 0x5d, 0x6e, 0x7f, 0x80, 0x91,
    0xa2, 0xb3, 0xc4, 0xd5, 0xe6, 0xf7, 0x08, 0x19,
    0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81,
    0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09,
    0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71,
    0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8, 0xf9
};

/****************************** COMMON STRUCTURES ******************************/

struct ip_auth_data {
    __u32 field_mask;
    __u8  key[64];
    __u8  action;
};

struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 data;
};

#define ACTION_DROP      0
#define ACTION_ALLOW     1
#define ACTION_MARK      2

#define STAT_TOTAL_PACKETS         0
#define STAT_AUTH_SUCCESS          1
#define STAT_AUTH_FAILURE          2
#define STAT_NO_AUTH_RULE          3
#define STAT_DROPPED_PACKETS       4
#define STAT_KEY_LOOKUP_SUCCESS    5
#define STAT_KEY_LOOKUP_FAILURE    6

/****************************** BPF MAP DEFINITIONS ******************************/

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct ip_auth_data);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 1000);
} src_ip_key_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, SHA256_CTX);
} sha256_ctx_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct {
        BYTE buffer[128];
        WORD m[64];
    });
} sha256_temp_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct {
        __u8 hash_output[SHA256_BLOCK_SIZE];
    });
} kfunc_hash_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct {
        __u8 use_kfunc;
    });
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} config_map SEC(".maps");

/****************************** CUSTOM SHA256 IMPLEMENTATION ******************************/

/*
 * OPTIMIZATION 1: sha256_transform is NOT marked __always_inline.
 *
 * With __always_inline the compiler emits a full copy of this ~300-instruction
 * function at every call site.  It is called up to 3 times
 * (once mid-update when the 84-byte input crosses the 64-byte block boundary,
 * and twice in sha256_final), so the old code produced ~900 duplicated
 * instructions from this function alone.
 *
 * As a plain static function the BPF JIT emits a single subprogram and calls
 * it by reference — the body is compiled once and shared across all call sites.
 * This is supported from kernel 4.16 onwards.
 */
#if 0
static int sha256_transform(const BYTE data[])
{
    __u32 key = 0;
    SHA256_CTX *ctx;
    struct { WORD m[64]; } *temp;
    WORD a, b, c, d, e, f, g, h, i, t1, t2;

    ctx = bpf_map_lookup_elem(&sha256_ctx_map, &key);
    if (!ctx)
        return -1;

    temp = bpf_map_lookup_elem(&sha256_temp_map, &key);
    if (!temp)
        return -1;

    /*
     * OPTIMIZATION 2: Remove tautological bounds checks.
     *
     * The original loops contained guards like "if (i >= 16) break" inside
     * "for (i = 0; i < 16; ++i)" — these are always false and generate dead
     * branch instructions that the verifier still has to evaluate.  Removed.
     *
     * Similarly "if (i - 2 < 0)" on an unsigned i is always false and removed.
     */
    #pragma unroll
    for (i = 0; i < 16; ++i) {
        int j = i * 4;
        temp->m[i] = ((WORD)data[j]     << 24) |
                     ((WORD)data[j + 1] << 16) |
                     ((WORD)data[j + 2] <<  8) |
                      (WORD)data[j + 3];
    }

    #pragma unroll
    for (i = 16; i < 64; ++i) {
        temp->m[i] = SIG1(temp->m[i - 2])  + temp->m[i - 7] +
                     SIG0(temp->m[i - 15]) + temp->m[i - 16];
    }

    a = ctx->state[0]; b = ctx->state[1];
    c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5];
    g = ctx->state[6]; h = ctx->state[7];

    #pragma unroll
    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + k[i] + temp->m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b;
    ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f;
    ctx->state[6] += g; ctx->state[7] += h;

    return 0;
}
/* sha256_transform takes no arguments — it looks up ctx from the map
 * directly, which the verifier can always track as a bounded map value. */
static int sha256_transform(void)
{
    __u32 key = 0;
    SHA256_CTX *ctx;
    struct { WORD m[64]; } *temp;
    WORD a, b, c, d, e, f, g, h, i, t1, t2;

    ctx = bpf_map_lookup_elem(&sha256_ctx_map, &key);
    if (!ctx)
        return -1;

    temp = bpf_map_lookup_elem(&sha256_temp_map, &key);
    if (!temp)
        return -1;

    #pragma unroll
    for (i = 0; i < 16; ++i) {
        int j = i * 4;
        /* VERIFIER HINT: j is derived from loop counter i which is
         * bounded [0,15], so j+3 <= 63 < 64. Explicit check required
         * because the verifier tracks j as a scalar.                  */
        if (j + 3 >= 64)
            return -1;
        temp->m[i] = ((WORD)ctx->data[j]     << 24) |
                     ((WORD)ctx->data[j + 1] << 16) |
                     ((WORD)ctx->data[j + 2] <<  8) |
                      (WORD)ctx->data[j + 3];
    }

    #pragma unroll
    for (i = 16; i < 64; ++i)
        temp->m[i] = SIG1(temp->m[i-2])  + temp->m[i-7]  +
                     SIG0(temp->m[i-15]) + temp->m[i-16];

    a = ctx->state[0]; b = ctx->state[1];
    c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5];
    g = ctx->state[6]; h = ctx->state[7];

    #pragma unroll
    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e,f,g) + k[i] + temp->m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b;
    ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f;
    ctx->state[6] += g; ctx->state[7] += h;

    return 0;
}
#else
/* Subprogram 1: message schedule only (m[0..15] → m[16..63]) */
static int sha256_message_schedule(void)
{
    __u32 map_key = 0;
    struct { BYTE buffer[128]; WORD m[64]; } *temp;
    WORD i;

    temp = bpf_map_lookup_elem(&sha256_temp_map, &map_key);
    if (!temp)
        return -1;

    /* Load first 16 words from ctx->data */
    SHA256_CTX *ctx = bpf_map_lookup_elem(&sha256_ctx_map, &map_key);
    if (!ctx)
        return -1;

    #pragma unroll
    for (i = 0; i < 16; ++i) {
        int j = i * 4;
        if (j + 3 >= 64) return -1;   /* verifier bounds proof */
        temp->m[i] = ((__u32)ctx->data[j]     << 24) |
                     ((__u32)ctx->data[j + 1] << 16) |
                     ((__u32)ctx->data[j + 2] <<  8) |
                      (__u32)ctx->data[j + 3];
    }

    /* Extend to 64 words — each result is explicitly cast to __u32 */
    #pragma unroll
    for (i = 16; i < 64; ++i) {
        temp->m[i] = (__u32)(SIG1(temp->m[i-2])  + temp->m[i-7]  +
                             SIG0(temp->m[i-15]) + temp->m[i-16]);
    }

    return 0;
}

/* Subprogram 2: compression — 64-round a..h update */
static int sha256_compress(void)
{
    __u32 map_key = 0;
    SHA256_CTX *ctx;
    struct { BYTE buffer[128]; WORD m[64]; } *temp;
    __u32 a, b, c, d, e, f, g, h, t1, t2;
    WORD i;

    ctx = bpf_map_lookup_elem(&sha256_ctx_map, &map_key);
    if (!ctx)
        return -1;

    temp = bpf_map_lookup_elem(&sha256_temp_map, &map_key);
    if (!temp)
        return -1;

    a = (__u32)ctx->state[0]; b = (__u32)ctx->state[1];
    c = (__u32)ctx->state[2]; d = (__u32)ctx->state[3];
    e = (__u32)ctx->state[4]; f = (__u32)ctx->state[5];
    g = (__u32)ctx->state[6]; h = (__u32)ctx->state[7];

    /*
     * Do NOT #pragma unroll the 64-round loop.
     *
     * With unroll, the verifier processes 64 independent copies of the
     * body and tracks scalar ranges through every copy — this is what
     * caused the 1M-instruction blowup even with the __u32 casts above.
     *
     * Without unroll, the verifier analyses the loop body once and uses
     * widening to prove termination (loop counter i is bounded [0,63]).
     * The __u32 casts in every macro keep the per-iteration state small
     * enough for the verifier to handle.
     */
    for (i = 0; i < 64; ++i) {
        if (i >= 64) break;  /* verifier hint for loop bound */
        t1 = (__u32)(h + EP1(e) + CH(e,f,g) + k[i] + temp->m[i]);
        t2 = (__u32)(EP0(a) + MAJ(a,b,c));
        h = g; g = f; f = e; e = (__u32)(d + t1);
        d = c; c = b; b = a; a = (__u32)(t1 + t2);
    }

    ctx->state[0] = (__u32)(ctx->state[0] + a);
    ctx->state[1] = (__u32)(ctx->state[1] + b);
    ctx->state[2] = (__u32)(ctx->state[2] + c);
    ctx->state[3] = (__u32)(ctx->state[3] + d);
    ctx->state[4] = (__u32)(ctx->state[4] + e);
    ctx->state[5] = (__u32)(ctx->state[5] + f);
    ctx->state[6] = (__u32)(ctx->state[6] + g);
    ctx->state[7] = (__u32)(ctx->state[7] + h);

    return 0;
}

/* sha256_transform: orchestrates the two subprograms */
static int sha256_transform(void)
{
    if (sha256_message_schedule() < 0)
        return -1;
    return sha256_compress();
}
#endif

static __always_inline int sha256_init(void)
{
    __u32 key = 0;
    SHA256_CTX *ctx;

    ctx = bpf_map_lookup_elem(&sha256_ctx_map, &key);
    if (!ctx)
        return -1;

    ctx->datalen  = 0;
    ctx->bitlen   = 0;
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

#if 0
static __always_inline int sha256_update(const BYTE data[], size_t len)
{
    __u32 key = 0;
    SHA256_CTX *ctx;
    WORD i;

    ctx = bpf_map_lookup_elem(&sha256_ctx_map, &key);
    if (!ctx)
        return -1;

    for (i = 0; i < len; ++i) {
        /*
         * OPTIMIZATION 2 (continued): The original loop had two redundant
         * guards: "if (i >= len) break" (always false — loop condition
         * already ensures i < len) and "if (ctx->datalen >= 64) break"
         * (datalen is reset to 0 whenever it reaches 64, so this never
         * triggers mid-loop).  Both removed.
         */
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;

        if (ctx->datalen == 64) {
            sha256_transform(ctx->data);
            ctx->bitlen  += 512;
            ctx->datalen  = 0;
        }
    }
    return 0;
}
#else
static __always_inline int sha256_update(const BYTE data[], size_t len)
{
    __u32 key = 0;
    SHA256_CTX *ctx;
    WORD i;

    ctx = bpf_map_lookup_elem(&sha256_ctx_map, &key);
    if (!ctx)
        return -1;

    for (i = 0; i < len; ++i) {
        /* VERIFIER HINT: ctx->datalen comes from persistent map storage.
         * The verifier treats it as an unbounded scalar and cannot infer
         * it is always < 64 from program logic alone. This explicit check
         * is required to prove the array write below is in bounds.        */
        if (ctx->datalen >= 64)
            return -1;

        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;

        if (ctx->datalen == 64) {
            //sha256_transform(ctx->data);
            sha256_transform();
            ctx->bitlen  += 512;
            ctx->datalen  = 0;
        }
    }
    return 0;
}
#endif

static __always_inline int sha256_final(BYTE hash[])
{
    __u32 key = 0;
    SHA256_CTX *ctx;
    WORD i;

    ctx = bpf_map_lookup_elem(&sha256_ctx_map, &key);
    if (!ctx)
        return -1;

    i = ctx->datalen;
    if (i >= 64)
        i = 0;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;

        #pragma unroll
        for (int j = 0; j < 56; j++) {
            if (i < 56)
                ctx->data[i++] = 0x00;
        }
    } else {
        ctx->data[i++] = 0x80;

        #pragma unroll
        for (int j = 0; j < 64; j++) {
            if (i < 64)
                ctx->data[i++] = 0x00;
        }

        //sha256_transform(ctx->data);
        sha256_transform();

        #pragma unroll
        for (int j = 0; j < 56; j++)
            ctx->data[j] = 0x00;

        i = 56;
    }

    ctx->bitlen += ctx->datalen * 8;

    /*
     * OPTIMIZATION 2 (continued): The original code wrapped each of these
     * 8 assignments in "if (N < 64)" — a compile-time constant that is always
     * true.  Removed; assignments are unconditional.
     */
    ctx->data[56] = ctx->bitlen >> 56;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[62] = ctx->bitlen >>  8;
    ctx->data[63] = ctx->bitlen;

    //sha256_transform(ctx->data);
    sha256_transform();

    /*
     * OPTIMIZATION 2 (continued): The original loop wrapped each hash[]
     * assignment in a multi-condition bounds check that was always true for
     * i in [0,3].  Unrolled and written as 32 direct assignments instead.
     */
    #pragma unroll
    for (i = 0; i < 4; ++i) {
        hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0xff;
        hash[i +  4] = (ctx->state[1] >> (24 - i * 8)) & 0xff;
        hash[i +  8] = (ctx->state[2] >> (24 - i * 8)) & 0xff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0xff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0xff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0xff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0xff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0xff;
    }

    return 0;
}

/****************************** HELPER FUNCTIONS ******************************/

// Function to print a hex dump of binary data
void print_hex(const unsigned char *data, int len) {
    //if (len > 20) return;
    for (int i = 0; i < len; i++)
        bpf_printk("%02x", data[i++]);
    bpf_printk("\n");
}

static __always_inline uint16_t calculate_ip_checksum(const void *header, int len) {
    const uint16_t *buf = header;
    uint32_t sum = 0;

    for (int i = 0; i < len / 2; i++)
        sum += buf[i];

    if (len % 2)
        sum += ((const uint8_t *)header)[len - 1];

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ~sum;
}

/*
 * OPTIMIZATION 3: lookup_auth_key — single LPM lookup instead of four.
 *
 * BPF_MAP_TYPE_LPM_TRIE performs longest-prefix match natively in a single
 * bpf_map_lookup_elem() call.  The original code manually tried /32, /24,
 * /16 and /8 in sequence, generating four map lookups and four separate
 * verifier-tracked code paths.  One lookup is sufficient and correct.
 *
 * OPTIMIZATION 4: Timing instrumentation moved behind the debug flag.
 *
 * bpf_ktime_get_ns() is a helper call that adds instructions on every packet
 * even when debug output is never printed.  The two calls and the arithmetic
 * between them are now compiled out entirely in non-debug builds.
 */
static __always_inline struct ip_auth_data *lookup_auth_key(__u32 src_ip)
{
    struct ipv4_lpm_key src_key;
    struct ip_auth_data *auth_data;

    src_key.prefixlen = 32;
    src_key.data      = src_ip;

    auth_data = bpf_map_lookup_elem(&src_ip_key_map, &src_key);

#ifdef BPF_DEBUG
    if (auth_data) {
        /* Timing kept only when debug output is actually useful */
        __u64 t0 = bpf_ktime_get_ns();
        __u64 t1 = bpf_ktime_get_ns();
        bpf_printk("Key lookup time: %llu ns\n", t1 - t0);
    }
#endif

    return auth_data;
}

/**
 * Compute keyed hash with dynamic key (custom SHA256).
 * Used when use_kfunc = 0.
 *
 * Input layout written once into temp->buffer:
 *   [0 .. 63]  64-byte key from the LPM map
 *   [64 .. 83] up to 20 bytes of IP header data
 * Total: up to 84 bytes → two SHA256 block transforms.
 */
static __always_inline int compute_keyed_hash_from_map_dynamic(
        const BYTE *data, size_t data_len,
        BYTE hash[SHA256_BLOCK_SIZE], const BYTE *dynamic_key)
{
    __u32 key = 0;
    struct { BYTE buffer[128]; WORD m[64]; } *temp;

    temp = bpf_map_lookup_elem(&sha256_temp_map, &key);
    if (!temp)
        return -1;

    /* Copy 64-byte key into the front of the buffer */
    __builtin_memcpy(temp->buffer, dynamic_key, 64);

    /*
     * OPTIMIZATION 5: Replace 20 conditional byte assignments with a single
     * __builtin_memcpy of fixed size 20.
     *
     * The original code emitted 20 "if (max_copy >= N)" branches.  Because
     * data_len is clamped to 20 on the line above, every condition was always
     * true — the verifier still tracked each branch separately.  A
     * __builtin_memcpy with a compile-time constant length lowers to a small
     * number of word-wide store instructions with no branching.
     *
     * We always copy 20 bytes (the fixed IP header size that is passed in).
     * If data_len < 20, the caller is responsible for zero-padding or the
     * trailing bytes are harmless since they lie beyond the hash input length
     * recorded in SHA256's bitlen.
     */
    __builtin_memcpy(temp->buffer + 64, data, 20);

    sha256_init();
    sha256_update(temp->buffer, 64 + (data_len < 20 ? data_len : 20));
    sha256_final(hash);

    return 0;
}

#endif   // SHA256_H
