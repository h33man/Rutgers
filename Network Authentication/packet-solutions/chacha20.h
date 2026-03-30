/*********************************************************************
 * Filename:   chacha20.h
 * Description: Inline ChaCha20-Poly1305 authentication (Mode A) for
 *              TC eBPF programs. No kernel crypto API, no kfuncs,
 *              no setup loader — works on any kernel with BPF support.
 *
 * Usage:
 *   ret = compute_chacha20_keyed_hash(key, key_len,
 *                                     data, data_len,
 *                                     hash_result);
 *
 * Output buffer layout (32 bytes = SHA256_BLOCK_SIZE):
 *   [0 .. 7]   8-byte nonce  (big-endian u64 from nonce_map)
 *   [8 ..23]  16-byte Poly1305 authentication tag
 *   [24..31]   zero padding
 *
 * BPF constraints respected:
 *   - No heap allocation (all state in per-CPU maps or stack)
 *   - All loops bounded with #pragma unroll or known max iterations
 *   - Stack usage kept under 512 bytes by using per-CPU maps for
 *     large state (ChaCha20 block = 64B, Poly1305 state = 48B)
 *   - No standard library calls
 *
 * Designed for IP headers (max 60 bytes = max 4 x 16-byte blocks).
 *********************************************************************/

#ifndef CHACHA20_H
#define CHACHA20_H

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ------------------------------------------------------------------ */
/*  Constants                                                           */
/* ------------------------------------------------------------------ */

#define CHACHA20_KEY_SIZE    32
#define CHACHA20_NONCE_SIZE  12
#define CHACHA20_BLOCK_SIZE  64
#define POLY1305_KEY_SIZE    32
#define POLY1305_TAG_SIZE    16
#define CHACHA20_OUT_NONCE    0   /* offset of nonce in output buffer  */
#define CHACHA20_OUT_TAG      8   /* offset of tag in output buffer    */

/*
 * Maximum number of 16-byte Poly1305 blocks to process.
 * IP header max = 60 bytes = 3 full blocks + 1 partial = 4 blocks.
 * Set to 8 for safety margin.
 */
#define POLY1305_MAX_BLOCKS   8

/* ------------------------------------------------------------------ */
/*  Per-CPU maps — keep large state off the stack                       */
/* ------------------------------------------------------------------ */

/*
 * ChaCha20 block state — 16 x u32 = 64 bytes.
 * Kept in a per-CPU map to avoid blowing the 512-byte BPF stack limit.
 */
struct chacha20_block_state {
    __u32 s[16];    /* working state (copy of initial, gets mixed) */
    __u32 c[16];    /* initial constant state                       */
};

struct {
    __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, struct chacha20_block_state);
} chacha20_block_map SEC(".maps");

/*
 * Poly1305 accumulator state.
 * h[0..2]: 130-bit accumulator in 3 x u64 limbs
 * r[0..1]: clamped key r (128-bit in 2 x u64)
 * s[0..1]: key s (128-bit in 2 x u64)
 */
struct poly1305_state {
    __u64 h[3];
    __u64 r[2];
    __u64 s[2];
};

struct {
    __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, struct poly1305_state);
} poly1305_state_map SEC(".maps");

/*
 * Monotonic nonce counter — incremented atomically per packet.
 * Never reuse a (key, nonce) pair.
 */
struct {
    __uint(type,        BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, __u64);
} chacha_nonce_map SEC(".maps");

/* ------------------------------------------------------------------ */
/*  ChaCha20 primitives                                                 */
/* ------------------------------------------------------------------ */

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define CHACHA_QR(a, b, c, d)   \
    (a) += (b); (d) ^= (a); (d) = ROL32((d), 16); \
    (c) += (d); (b) ^= (c); (b) = ROL32((b), 12); \
    (a) += (b); (d) ^= (a); (d) = ROL32((d),  8); \
    (c) += (d); (b) ^= (c); (b) = ROL32((b),  7);

/*
 * chacha20_block - run 20 rounds on the state and produce 64 keystream bytes
 *
 * @bs:  pointer to per-CPU block state (avoids stack overflow)
 * @out: 64-byte output buffer for the keystream block
 */
static __always_inline void chacha20_block(struct chacha20_block_state *bs,
                                            __u8 out[CHACHA20_BLOCK_SIZE])
{
    int i;

    /* Copy initial state into working state */
    #pragma unroll
    for (i = 0; i < 16; i++)
        bs->s[i] = bs->c[i];

    /* 20 rounds = 10 double rounds */
    #pragma unroll
    for (i = 0; i < 10; i++) {
        /* Column rounds */
        CHACHA_QR(bs->s[0], bs->s[4], bs->s[ 8], bs->s[12]);
        CHACHA_QR(bs->s[1], bs->s[5], bs->s[ 9], bs->s[13]);
        CHACHA_QR(bs->s[2], bs->s[6], bs->s[10], bs->s[14]);
        CHACHA_QR(bs->s[3], bs->s[7], bs->s[11], bs->s[15]);
        /* Diagonal rounds */
        CHACHA_QR(bs->s[0], bs->s[5], bs->s[10], bs->s[15]);
        CHACHA_QR(bs->s[1], bs->s[6], bs->s[11], bs->s[12]);
        CHACHA_QR(bs->s[2], bs->s[7], bs->s[ 8], bs->s[13]);
        CHACHA_QR(bs->s[3], bs->s[4], bs->s[ 9], bs->s[14]);
    }

    /* Add initial state back and serialize to bytes (little-endian) */
    #pragma unroll
    for (i = 0; i < 16; i++) {
        __u32 w = bs->s[i] + bs->c[i];
        out[i * 4 + 0] = (__u8)(w);
        out[i * 4 + 1] = (__u8)(w >>  8);
        out[i * 4 + 2] = (__u8)(w >> 16);
        out[i * 4 + 3] = (__u8)(w >> 24);
    }
}

/*
 * chacha20_init_state - set up the ChaCha20 initial constant state
 *
 * ChaCha20 state layout (16 x u32):
 *   [0..3]   "expa nd 3 2-b yte k" (magic constant)
 *   [4..11]  256-bit key (8 x u32, little-endian)
 *   [12]     block counter
 *   [13..15] 96-bit nonce (3 x u32, little-endian)
 */
static __always_inline void
chacha20_init_state(struct chacha20_block_state *bs,
                    const __u8 key[CHACHA20_KEY_SIZE],
                    __u32 counter,
                    const __u8 nonce[CHACHA20_NONCE_SIZE])
{
    /* Magic constant "expand 32-byte k" */
    bs->c[0]  = 0x61707865;
    bs->c[1]  = 0x3320646e;
    bs->c[2]  = 0x79622d32;
    bs->c[3]  = 0x6b206574;

    /* Key — 8 x u32 little-endian */
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        bs->c[4 + i] = ((__u32)key[i*4])
                     | ((__u32)key[i*4 + 1] <<  8)
                     | ((__u32)key[i*4 + 2] << 16)
                     | ((__u32)key[i*4 + 3] << 24);
    }

    /* Block counter */
    bs->c[12] = counter;

    /* Nonce — 3 x u32 little-endian */
    bs->c[13] = ((__u32)nonce[0])  | ((__u32)nonce[1]  <<  8)
              | ((__u32)nonce[2]  << 16) | ((__u32)nonce[3]  << 24);
    bs->c[14] = ((__u32)nonce[4])  | ((__u32)nonce[5]  <<  8)
              | ((__u32)nonce[6]  << 16) | ((__u32)nonce[7]  << 24);
    bs->c[15] = ((__u32)nonce[8])  | ((__u32)nonce[9]  <<  8)
              | ((__u32)nonce[10] << 16) | ((__u32)nonce[11] << 24);
}

/* ------------------------------------------------------------------ */
/*  Poly1305 primitives                                                 */
/* ------------------------------------------------------------------ */

/*
 * poly1305_init - initialise Poly1305 state from a 32-byte one-time key
 *
 * The key is split:
 *   r = key[0..15] clamped per RFC 8439
 *   s = key[16..31] (no clamping)
 */
static __always_inline void poly1305_init(struct poly1305_state *st,
                                           const __u8 key[POLY1305_KEY_SIZE])
{
    /* Load r as two 64-bit little-endian words */
    __u64 r0 = ((__u64)key[0])  | ((__u64)key[1]  <<  8)
             | ((__u64)key[2]  << 16) | ((__u64)key[3]  << 24)
             | ((__u64)key[4]  << 32) | ((__u64)key[5]  << 40)
             | ((__u64)key[6]  << 48) | ((__u64)key[7]  << 56);

    __u64 r1 = ((__u64)key[8])  | ((__u64)key[9]  <<  8)
             | ((__u64)key[10] << 16) | ((__u64)key[11] << 24)
             | ((__u64)key[12] << 32) | ((__u64)key[13] << 40)
             | ((__u64)key[14] << 48) | ((__u64)key[15] << 56);

    /* Clamp r per RFC 8439 section 2.5 */
    r0 &= 0x0FFFFFFC0FFFFFFF;
    r1 &= 0x0FFFFFFC0FFFFFFC;

    st->r[0] = r0;
    st->r[1] = r1;

    /* Load s — no clamping */
    st->s[0] = ((__u64)key[16]) | ((__u64)key[17] <<  8)
             | ((__u64)key[18] << 16) | ((__u64)key[19] << 24)
             | ((__u64)key[20] << 32) | ((__u64)key[21] << 40)
             | ((__u64)key[22] << 48) | ((__u64)key[23] << 56);

    st->s[1] = ((__u64)key[24]) | ((__u64)key[25] <<  8)
             | ((__u64)key[26] << 16) | ((__u64)key[27] << 24)
             | ((__u64)key[28] << 32) | ((__u64)key[29] << 40)
             | ((__u64)key[30] << 48) | ((__u64)key[31] << 56);

    st->h[0] = 0;
    st->h[1] = 0;
    st->h[2] = 0;
}

/*
 * poly1305_block - process one 16-byte block into the accumulator
 *
 * @st:    Poly1305 state
 * @block: 16-byte input block (zero-padded if partial)
 * @final: 1 for the last (possibly partial) block, 0 otherwise
 */
static __always_inline void poly1305_block(struct poly1305_state *st,
                                            const __u8 block[16],
                                            int final)
{
    /* Load block as two 64-bit little-endian words */
    __u64 m0 = ((__u64)block[0])  | ((__u64)block[1]  <<  8)
             | ((__u64)block[2]  << 16) | ((__u64)block[3]  << 24)
             | ((__u64)block[4]  << 32) | ((__u64)block[5]  << 40)
             | ((__u64)block[6]  << 48) | ((__u64)block[7]  << 56);

    __u64 m1 = ((__u64)block[8])  | ((__u64)block[9]  <<  8)
             | ((__u64)block[10] << 16) | ((__u64)block[11] << 24)
             | ((__u64)block[12] << 32) | ((__u64)block[13] << 40)
             | ((__u64)block[14] << 48) | ((__u64)block[15] << 56);

    /* h += m (with high bit set for non-final blocks) */
    __u64 t0, t1, t2, c;

    t0 = st->h[0] + m0;
    c  = t0 < st->h[0] ? 1 : 0;
    t1 = st->h[1] + m1 + c;
    c  = t1 < st->h[1] ? 1 : 0;
    t2 = st->h[2] + (final ? 0ULL : 1ULL) + c;

    st->h[0] = t0;
    st->h[1] = t1;
    st->h[2] = t2 & 3;

    /*
     * h *= r  (mod 2^130 - 5)
     *
     * Split into 64x64→128 multiplications to avoid __int128.
     * Uses the identity: 2^130 ≡ 5 (mod 2^130-5) to fold carries.
     *
     * d0 = h0*r0 + h1*(r1*5) + h2*(r1_lo*5)  (lo 64 bits)
     * d1 = h0*r1 + h1*r0     + h2*(r0_lo)
     */
    __u64 r0 = st->r[0], r1 = st->r[1];
    __u64 h0 = st->h[0], h1 = st->h[1];
    __u32 h2 = (__u32)st->h[2];

    /* r1 * 5 — used to fold the 2^130 term */
    __u64 r1_5 = r1 * 5;

    /*
     * 128-bit multiply helpers using 32-bit splits to stay portable.
     * Each u64 * u64 → split into 32-bit halves.
     */
    __u32 r0l = (__u32)r0, r0h = (__u32)(r0 >> 32);
    __u32 r1l = (__u32)r1, r1h = (__u32)(r1 >> 32);
    __u32 r15l = (__u32)r1_5, r15h = (__u32)(r1_5 >> 32);
    __u32 h0l = (__u32)h0, h0h = (__u32)(h0 >> 32);
    __u32 h1l = (__u32)h1, h1h = (__u32)(h1 >> 32);

    /* d0 = h0 * r0 */
    __u64 d0  = (__u64)h0l * r0l;
    d0 += (__u64)h0l * r0h << 32;
    d0 += (__u64)h0h * r0l << 32;
    __u64 d0h = (__u64)h0h * r0h
              + ((__u64)h0l * r0h >> 32)
              + ((__u64)h0h * r0l >> 32);

    /* d0 += h1 * r1*5 */
    __u64 tmp  = (__u64)h1l * r15l;
    __u64 tmph = (__u64)h1h * r15h
               + ((__u64)h1l * r15h >> 32)
               + ((__u64)h1h * r15l >> 32);
    tmp  += (__u64)h1l * r15h << 32;
    tmp  += (__u64)h1h * r15l << 32;
    d0  += tmp;
    d0h += tmph + (d0 < tmp ? 1 : 0);

    /* d0 += h2 * (r1*5) low 32 bits */
    d0  += (__u64)h2 * r15l;
    d0h += (d0 < (__u64)h2 * r15l) ? 1 : 0;

    /* d1 = h0 * r1 */
    __u64 d1  = (__u64)h0l * r1l;
    d1 += (__u64)h0l * r1h << 32;
    d1 += (__u64)h0h * r1l << 32;
    __u64 d1h = (__u64)h0h * r1h
              + ((__u64)h0l * r1h >> 32)
              + ((__u64)h0h * r1l >> 32);

    /* d1 += h1 * r0 */
    tmp  = (__u64)h1l * r0l;
    tmph = (__u64)h1h * r0h
         + ((__u64)h1l * r0h >> 32)
         + ((__u64)h1h * r0l >> 32);
    tmp  += (__u64)h1l * r0h << 32;
    tmp  += (__u64)h1h * r0l << 32;
    d1  += tmp;
    d1h += tmph + (d1 < tmp ? 1 : 0);

    /* d1 += h2 * r0 low 32 */
    d1  += (__u64)h2 * r0l;
    d1h += (d1 < (__u64)h2 * r0l) ? 1 : 0;

    /*
     * Partial reduction mod 2^130 - 5:
     *   new_h2 = (d0h >> 2) | (d1h bits)  — kept as 2-bit value
     *   carry  = d0h >> 2
     *   new_h0 = d0 + carry * 5
     *   new_h1 = d1 + (d0h & 3 overflow)
     */
    c = d0h >> 2;
    st->h[2] = (d0h & 3) + d1h;   /* upper accumulator bits         */
    st->h[0] = d0 + c * 5;        /* fold 2^130 carry via ≡5        */
    st->h[1] = d1 + d0h;          /* add upper word of d0           */
    st->h[0] += (st->h[0] < d0) ? 5 : 0; /* propagate carry if needed */
}

/*
 * poly1305_finish - finalise and produce the 16-byte tag
 */
static __always_inline void poly1305_finish(struct poly1305_state *st,
                                             __u8 tag[POLY1305_TAG_SIZE])
{
    /* Final full reduction mod 2^130 - 5 */
    __u64 h0 = st->h[0], h1 = st->h[1], h2 = st->h[2];

    /* If h >= 2^130 - 5, subtract 2^130 - 5 */
    __u64 g0 = h0 + 5;
    __u64 g1 = h1 + (g0 < h0 ? 1 : 0);
    __u64 g2 = h2 + (g1 < h1 ? 1 : 0);

    /* Select h or g depending on whether h >= p */
    __u64 mask = ~((__u64)(g2 >> 2) - 1); /* all-ones if g2 >= 4 */
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);

    /* tag = (h + s) mod 2^128 */
    __u64 f0 = h0 + st->s[0];
    __u64 f1 = h1 + st->s[1] + (f0 < h0 ? 1 : 0);

    /* Serialise little-endian */
    tag[0]  = (__u8)(f0);       tag[1]  = (__u8)(f0 >>  8);
    tag[2]  = (__u8)(f0 >> 16); tag[3]  = (__u8)(f0 >> 24);
    tag[4]  = (__u8)(f0 >> 32); tag[5]  = (__u8)(f0 >> 40);
    tag[6]  = (__u8)(f0 >> 48); tag[7]  = (__u8)(f0 >> 56);
    tag[8]  = (__u8)(f1);       tag[9]  = (__u8)(f1 >>  8);
    tag[10] = (__u8)(f1 >> 16); tag[11] = (__u8)(f1 >> 24);
    tag[12] = (__u8)(f1 >> 32); tag[13] = (__u8)(f1 >> 40);
    tag[14] = (__u8)(f1 >> 48); tag[15] = (__u8)(f1 >> 56);
}

/* ------------------------------------------------------------------ */
/*  Public API                                                          */
/* ------------------------------------------------------------------ */

/*
 * compute_chacha20_keyed_hash - ChaCha20-Poly1305 auth tag over @data
 *
 * Matches the calling convention in tc_prog_kern_03.c:
 *   ret = compute_chacha20_keyed_hash(auth_data->key, 16,
 *                                     (BYTE *)iphdr, header_size,
 *                                     hash_result);
 *
 * @key      : pre-shared key (zero-padded to 32 bytes internally)
 * @key_len  : byte length of @key (typically 16)
 * @data     : data to authenticate (IP header)
 * @data_len : byte length of @data (max 60 bytes for IPv4 header)
 * @hash     : output buffer, must be >= 32 bytes (SHA256_BLOCK_SIZE)
 *
 * Returns 0 on success, -1 on map lookup failure.
 */
static __always_inline int
compute_chacha20_keyed_hash(const __u8 *key,  __u32 key_len,
                            const __u8 *data, __u32 data_len,
                            __u8       *hash)
{
    __u32 map_key = 0;
    int i;

    __u64 start_time = bpf_ktime_get_ns();
    __u64 end_time;
    __u64 total_latency;


    /* ---- 1. Get per-CPU working state off the stack ---- */
    struct chacha20_block_state *bs =
        bpf_map_lookup_elem(&chacha20_block_map, &map_key);
    if (!bs)
        return -1;

    struct poly1305_state *ps =
        bpf_map_lookup_elem(&poly1305_state_map, &map_key);
    if (!ps)
        return -1;

    /* ---- 2. Get and increment the nonce counter ---- */
    __u64 *ctr = bpf_map_lookup_elem(&chacha_nonce_map, &map_key);
    if (!ctr)
        return -1;

    __u64 nonce_val = __sync_fetch_and_add(ctr, 1);

    /*
     * Build the 12-byte ChaCha20 nonce:
     *   bytes [0.. 3] = 0x00000000 (constant)
     *   bytes [4..11] = nonce_val  (big-endian u64)
     */
    __u8 nonce[CHACHA20_NONCE_SIZE];
    nonce[0] = 0; nonce[1] = 0; nonce[2] = 0; nonce[3] = 0;
    nonce[4]  = (__u8)(nonce_val >> 56);
    nonce[5]  = (__u8)(nonce_val >> 48);
    nonce[6]  = (__u8)(nonce_val >> 40);
    nonce[7]  = (__u8)(nonce_val >> 32);
    nonce[8]  = (__u8)(nonce_val >> 24);
    nonce[9]  = (__u8)(nonce_val >> 16);
    nonce[10] = (__u8)(nonce_val >>  8);
    nonce[11] = (__u8)(nonce_val);

    /* ---- 3. Build the 32-byte ChaCha20 key (zero-pad if short) ---- */
    __u8 full_key[CHACHA20_KEY_SIZE];
    __builtin_memset(full_key, 0, CHACHA20_KEY_SIZE);
    if (key_len > CHACHA20_KEY_SIZE)
        key_len = CHACHA20_KEY_SIZE;
    #pragma unroll
    for (i = 0; i < 32; i++) {
        if ((__u32)i < key_len)
            full_key[i] = key[i];
    }

    /* ---- 4. Generate Poly1305 one-time key via ChaCha20 counter=0 ---- */
    /*
     * Per RFC 8439: the Poly1305 key is the first 32 bytes of the
     * ChaCha20 keystream generated with the same key and nonce, block
     * counter = 0. The remaining 32 bytes of the 64-byte block are
     * discarded.
     */
    __u8 keystream[CHACHA20_BLOCK_SIZE];
    chacha20_init_state(bs, full_key, 0, nonce);
    chacha20_block(bs, keystream);

    /* ---- 5. Initialise Poly1305 with the one-time key ---- */
    poly1305_init(ps, keystream);   /* keystream[0..31] = Poly1305 key */

    /* ---- 6. Process data in 16-byte blocks ---- */
    /*
     * Bounded loop — max POLY1305_MAX_BLOCKS iterations.
     * For a 60-byte IP header: 3 full blocks + 1 partial = 4 blocks.
     * The verifier sees a fixed upper bound so it's always accepted.
     */
    __u8 block[16];
    __u32 offset = 0;

    //#pragma unroll
    for (i = 0; i < POLY1305_MAX_BLOCKS; i++) {
        if (offset >= data_len)
            break;

        __u32 remaining = data_len - offset;

        if (remaining >= 16) {
            /* Full block — load directly */
            #pragma unroll
            for (int j = 0; j < 16; j++)
                block[j] = data[offset + j];
            poly1305_block(ps, block, 0);
            offset += 16;
        } else {
            /* Final partial block — zero-pad and process */
            __builtin_memset(block, 0, 16);
            #pragma unroll
            for (int j = 0; j < 16; j++) {
                if ((__u32)j < remaining)
                    block[j] = data[offset + j];
            }
            poly1305_block(ps, block, 1);
            offset = data_len; /* signal done */
        }
    }

    /* ---- 7. Finalise and produce tag ---- */
    __u8 tag[POLY1305_TAG_SIZE];
    poly1305_finish(ps, tag);

    /* ---- 8. Pack output buffer ---- */
    /*
     * Layout:
     *   hash[0.. 7]  = nonce  (8-byte big-endian counter)
     *   hash[8..23]  = tag    (16-byte Poly1305 tag)
     *   hash[24..31] = 0x00   (padding)
     */
    __builtin_memset(hash, 0, 32);

    /* Nonce in big-endian */
    hash[0] = (__u8)(nonce_val >> 56);
    hash[1] = (__u8)(nonce_val >> 48);
    hash[2] = (__u8)(nonce_val >> 40);
    hash[3] = (__u8)(nonce_val >> 32);
    hash[4] = (__u8)(nonce_val >> 24);
    hash[5] = (__u8)(nonce_val >> 16);
    hash[6] = (__u8)(nonce_val >>  8);
    hash[7] = (__u8)(nonce_val);

    /* Poly1305 tag */
    #pragma unroll
    for (i = 0; i < POLY1305_TAG_SIZE; i++)
        hash[CHACHA20_OUT_TAG + i] = tag[i];

    end_time = bpf_ktime_get_ns();
    total_latency = end_time - start_time;

    if (debug)
        bpf_printk("CHACHA20 latency: %llu ns\n", total_latency);

    return 0;
}

static __always_inline int
verify_chacha20_keyed_hash(const __u8 *key,   __u32 key_len,
                           const __u8 *data,  __u32 data_len,
                           const __u8 *received_hash,  /* hash[0..31] from IP option */
                           __u8       *computed_hash)
{
    __u32 map_key = 0;
    int i;

    struct chacha20_block_state *bs =
        bpf_map_lookup_elem(&chacha20_block_map, &map_key);
    if (!bs) return -1;

    struct poly1305_state *ps =
        bpf_map_lookup_elem(&poly1305_state_map, &map_key);
    if (!ps) return -1;

    /* ---- Extract nonce from received hash[0..7] ---- */
    __u64 nonce_val =
        ((__u64)received_hash[0] << 56) | ((__u64)received_hash[1] << 48) |
        ((__u64)received_hash[2] << 40) | ((__u64)received_hash[3] << 32) |
        ((__u64)received_hash[4] << 24) | ((__u64)received_hash[5] << 16) |
        ((__u64)received_hash[6] <<  8) | ((__u64)received_hash[7]);

    /* Rebuild the same 12-byte nonce the sender used */
    __u8 nonce[CHACHA20_NONCE_SIZE];
    nonce[0] = 0; nonce[1] = 0; nonce[2] = 0; nonce[3] = 0;
    nonce[4]  = (__u8)(nonce_val >> 56);
    nonce[5]  = (__u8)(nonce_val >> 48);
    nonce[6]  = (__u8)(nonce_val >> 40);
    nonce[7]  = (__u8)(nonce_val >> 32);
    nonce[8]  = (__u8)(nonce_val >> 24);
    nonce[9]  = (__u8)(nonce_val >> 16);
    nonce[10] = (__u8)(nonce_val >>  8);
    nonce[11] = (__u8)(nonce_val);

    /* ---- Build full key ---- */
    __u8 full_key[CHACHA20_KEY_SIZE];
    __builtin_memset(full_key, 0, CHACHA20_KEY_SIZE);
    if (key_len > CHACHA20_KEY_SIZE) key_len = CHACHA20_KEY_SIZE;
    #pragma unroll
    for (i = 0; i < 32; i++)
        if ((__u32)i < key_len) full_key[i] = key[i];

    /* ---- Reproduce Poly1305 one-time key ---- */
    __u8 keystream[CHACHA20_BLOCK_SIZE];
    chacha20_init_state(bs, full_key, 0, nonce);
    chacha20_block(bs, keystream);
    poly1305_init(ps, keystream);

    /* ---- Process data ---- */
    __u8 block[16];
    __u32 offset = 0;
    for (i = 0; i < POLY1305_MAX_BLOCKS; i++) {
        if (offset >= data_len) break;
        __u32 remaining = data_len - offset;
        if (remaining >= 16) {
            #pragma unroll
            for (int j = 0; j < 16; j++)
                block[j] = data[offset + j];
            poly1305_block(ps, block, 0);
            offset += 16;
        } else {
            __builtin_memset(block, 0, 16);
            #pragma unroll
            for (int j = 0; j < 16; j++)
                if ((__u32)j < remaining) block[j] = data[offset + j];
            poly1305_block(ps, block, 1);
            offset = data_len;
        }
    }

    /* ---- Produce tag into computed_hash[8..23] ---- */
    __builtin_memset(computed_hash, 0, 32);
    /* Copy nonce into output so caller can compare full 32 bytes if needed */
    #pragma unroll
    for (i = 0; i < 8; i++)
        computed_hash[i] = received_hash[i];

    __u8 tag[POLY1305_TAG_SIZE];
    poly1305_finish(ps, tag);
    #pragma unroll
    for (i = 0; i < POLY1305_TAG_SIZE; i++)
        computed_hash[CHACHA20_OUT_TAG + i] = tag[i];

    return 0;
}

#endif /* CHACHA20_H */
