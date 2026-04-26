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
#define ROTRIGHT(a,b) ((__u32)(((__u32)(a) >> (b)) | ((__u32)(a) << (32-(b)))))
#define ROTLEFT(a,b)  ((__u32)(((__u32)(a) << (b)) | ((__u32)(a) >> (32-(b)))))

#define CH(x,y,z)  ((__u32)(((__u32)(x) & (__u32)(y)) ^ (~(__u32)(x) & (__u32)(z))))
#define MAJ(x,y,z) ((__u32)(((__u32)(x) & (__u32)(y)) ^ ((__u32)(x) & (__u32)(z)) ^ ((__u32)(y) & (__u32)(z))))
#define EP0(x) ((__u32)(ROTRIGHT(x,2)  ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22)))
#define EP1(x) ((__u32)(ROTRIGHT(x,6)  ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25)))
#define SIG0(x) ((__u32)(ROTRIGHT(x,7)  ^ ROTRIGHT(x,18) ^ ((__u32)(x) >>  3)))
#define SIG1(x) ((__u32)(ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((__u32)(x) >> 10)))

/* IP Options for hash storage */
#define IP_OPT_HASH_ID       27
#define IP_OPT_HASH_LEN      36
#define ETHERNET_HEADER_SIZE 14
#define SHA256_BLOCK_SIZE    32     // SHA256 outputs a 32 byte digest

/*
 * OPTIMIZATION 6: Fixed-size checksum constant.
 *
 * calculate_ip_checksum previously took a runtime `len` argument derived
 * from new_ip->ihl * 4, which the verifier tracked as an unbounded scalar.
 * Since we always call it with sizeof(struct iphdr) + IP_OPT_HASH_LEN = 56
 * bytes, define it as a compile-time constant and use a fixed unrolled loop.
 */
#define IP_HDR_WITH_OPT_WORDS  ((sizeof(struct iphdr) + IP_OPT_HASH_LEN) / 2)  /* = 28 */

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
#if 0
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
#endif
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

#if 0
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
#endif

/****************************** CUSTOM SHA256 IMPLEMENTATION ******************************/

/*
 * OPTIMIZATION 1: sha256_transform split into two non-inlined subprograms.
 *
 * sha256_message_schedule: loads ctx->data into temp->m[0..63].
 * sha256_compress: runs the 64-round a..h update.
 * sha256_transform: calls both in sequence.
 *
 * None are marked __always_inline so the BPF JIT emits each body once and
 * calls it by reference — shared across all call sites.
 *
 * OPTIMIZATION 2: The 64-round compression loop is NOT unrolled.
 *
 * With #pragma unroll the verifier processes 64 independent copies of the
 * body and tracks __u32 scalar ranges through every copy — this caused the
 * original 1M-instruction blowup.  Without unroll, the verifier analyses
 * the loop body once and uses widening to prove termination.  The explicit
 * __u32 casts in every macro keep per-iteration state small enough to handle.
 */

/* Subprogram 1: message schedule only (ctx->data → temp->m[0..63]) */
static int sha256_message_schedule(void)
{
    __u32 map_key = 0;
    struct { BYTE buffer[128]; WORD m[64]; } *temp;
    WORD i;

    temp = bpf_map_lookup_elem(&sha256_temp_map, &map_key);
    if (!temp)
        return -1;

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

    #pragma unroll
    for (i = 16; i < 64; ++i) {
        temp->m[i] = (__u32)(SIG1(temp->m[i-2])  + temp->m[i-7]  +
                             SIG0(temp->m[i-15]) + temp->m[i-16]);
    }

    return 0;
}

/* Subprogram 2: compression — 64-round a..h update, NOT unrolled */
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

    for (i = 0; i < 64; ++i) {
        if (i >= 64) break;  /* verifier loop-bound hint */
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

static int sha256_init(void)
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

/*
 * OPTIMIZATION 3: sha256_final — eliminate variable-length memset.
 *
 * __builtin_memset with a runtime length (e.g. 55 - i) is rejected by the
 * BPF backend — it requires compile-time constant lengths.
 *
 * Solution: zero the entire 64-byte ctx->data with a single fixed-size
 * memset FIRST, then write the 0x80 marker at position i.  Since everything
 * after i is already zero, no second memset is needed.  The length 64 is a
 * compile-time constant so the BPF backend accepts it.
 */
static int sha256_final(BYTE hash[])
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
        /*
         * Zero the whole block first (constant length = fine for BPF),
         * then stamp 0x80 at position i.  Bytes [i+1..55] are already 0.
         */
        __builtin_memset(ctx->data, 0x00, 64);
        ctx->data[i] = 0x80;
    } else {
        /*
         * Same: zero entire block, stamp 0x80, transform, then zero again
         * for the second block (bytes [0..55] must be 0 before bit-length).
         */
        __builtin_memset(ctx->data, 0x00, 64);
        ctx->data[i] = 0x80;

        sha256_transform();

        __builtin_memset(ctx->data, 0x00, 64);
        i = 56;
    }

    ctx->bitlen += ctx->datalen * 8;

    ctx->data[56] = ctx->bitlen >> 56;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[62] = ctx->bitlen >>  8;
    ctx->data[63] = ctx->bitlen;

    sha256_transform();

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

/**
 * Compute keyed hash with dynamic key (custom SHA256).
 * Used when use_kfunc = 0.
 *
 * Input layout:
 *   temp->buffer[0  .. 63]  64-byte key from LPM map
 *   temp->buffer[64 .. 83]  20 bytes of IP header (fixed size)
 * Total: 84 bytes = one full 64-byte block + 20-byte remainder.
 *
 * OPTIMIZATION 7: Eliminate sha256_update entirely for this call path.
 *
 * sha256_update contained a loop "for (i = 0; i < len; ++i)" where `len`
 * was a runtime function argument.  The verifier saw `len` as an unbounded
 * scalar and could not prove loop termination, causing exponential state
 * blowup — this was the primary source of the 1M-instruction overflow.
 *
 * Since we always hash exactly 84 bytes (64-byte key + 20-byte IP header),
 * we know statically that:
 *   - The first 64 bytes fill exactly one SHA256 block → one transform.
 *   - The remaining 20 bytes are < 64 → they fit in ctx->data without
 *     triggering a mid-update transform.
 *
 * We can therefore inline the two-phase update directly:
 *   Phase 1: memcpy first 64 bytes into ctx->data, call transform.
 *   Phase 2: memcpy remaining 20 bytes into ctx->data, set datalen = 20.
 * Both memcpy lengths are compile-time constants → zero verifier overhead.
 */
//static int __attribute__((unused)) compute_keyed_hash_from_map_dynamic(
static int compute_keyed_hash_from_map_dynamic(
        const BYTE *data, size_t data_len,
        BYTE hash[SHA256_BLOCK_SIZE], const BYTE *dynamic_key)
{
    __u32 key = 0;
    struct { BYTE buffer[128]; WORD m[64]; } *temp;
    SHA256_CTX *ctx;
    size_t hdr_len;

    temp = bpf_map_lookup_elem(&sha256_temp_map, &key);
    if (!temp)
        return -1;

    ctx = bpf_map_lookup_elem(&sha256_ctx_map, &key);
    if (!ctx)
        return -1;

    /* Clamp header bytes to 20 (fixed IPv4 header, no options in input) */
    hdr_len = data_len < 20 ? data_len : 20;

    /* Build the 84-byte input in temp->buffer */
    __builtin_memcpy(temp->buffer,      dynamic_key, 64);  /* key */
    __builtin_memcpy(temp->buffer + 64, data,        20);  /* header (20 bytes always safe,
                                                              caller zero-pads if hdr_len < 20) */

    /* --- Inline sha256_update for exactly 84 bytes --- */

    /* Init SHA256 state */
    if (sha256_init() < 0)
        return -1;

    /* Re-fetch ctx after sha256_init (map pointer may have been re-derived) */
    ctx = bpf_map_lookup_elem(&sha256_ctx_map, &key);
    if (!ctx)
        return -1;

    /*
     * Phase 1: first 64 bytes → fills ctx->data exactly, triggers transform.
     * Use fixed-size memcpy so the compiler emits word stores, not a loop.
     */
    __builtin_memcpy(ctx->data, temp->buffer, 64);
    if (sha256_transform() < 0)
        return -1;
    ctx = bpf_map_lookup_elem(&sha256_ctx_map, &key);
    if (!ctx)
        return -1;
    ctx->bitlen  = 512;
    ctx->datalen = 0;

    /*
     * Phase 2: remaining bytes (hdr_len, max 20) → fit in ctx->data with
     * no mid-update transform.  Copy 20 bytes unconditionally (safe because
     * temp->buffer[64..83] was initialised above); record only hdr_len bytes
     * in datalen so sha256_final pads correctly.
     */
    __builtin_memcpy(ctx->data, temp->buffer + 64, 20);
    ctx->datalen = (__u32)hdr_len;

    /* --- End inline sha256_update --- */

    return sha256_final(hash);
}

#endif   // SHA256_H
