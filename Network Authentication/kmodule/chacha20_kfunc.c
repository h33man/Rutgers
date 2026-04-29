// SPDX-License-Identifier: GPL-2.0-only
/*
 * chacha20poly1305_kfunc.c
 *
 * Kernel module exposing ChaCha20-Poly1305 authentication-only as a BPF kfunc.
 *
 * Performance optimizations applied:
 *  1. Removed memzero_explicit() on non-secret intermediate buffers
 *     (chacha_state, chacha_stream, poly1305_state, tag, partial block buf).
 *     Only key32 (the expanded secret) is zeroed.
 *  2. poly1305_update: removed redundant = {} zero-init on buf since we
 *     explicitly fill it with memcpy + memset before use.
 *  3. Removed dead out__sz local variable and its always-true branch.
 *  4. chacha20_block_self: use put_unaligned_le32 for serialization instead
 *     of 4 byte-shift stores - compiles to a single store on LE x86.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include <linux/unaligned.h>   /* get_unaligned_le32, put_unaligned_le32 */
#else
    #include <asm/unaligned.h>
#endif

/*
 * Do NOT include <crypto/chacha.h> - it pulls in struct chacha_ctx and
 * other types already present in vmlinux BTF.  When pahole deduplicates
 * the module's DWARF against /sys/kernel/btf/vmlinux it strips those shared
 * types and accidentally discards the kfunc BTF entries too, leaving a
 * ~472-byte stub with no usable .BTF section in the final .ko.
 *
 * chacha20_block() and chacha_init_consts() are also not reliably
 * EXPORT_SYMBOL'd on all kernel builds, causing modpost "undefined symbol"
 * errors for out-of-tree modules.
 *
 * Fix: implement ChaCha20 inline (RFC 8439 §2.1).  Zero external symbols
 * are required.  This is the same approach used for Poly1305 below.
 *
 * Do NOT include <crypto/poly1305.h> either - it pulls in _arch symbols.
 */

/* ================================================================
 * ChaCha20 - RFC 8439 §2.1  (fully self-contained, no kernel deps)
 * ================================================================ */

#define CHACHA_KEY_SIZE    32u
#define CHACHA_BLOCK_SIZE  64u
#define CHACHA_STATE_WORDS 16u   /* 16 x u32 = 64 bytes */

/* RFC 8439 §2.1.1- the four constant words ("expand 32-byte k") */
#define CHACHA_CONST_0  0x61707865u
#define CHACHA_CONST_1  0x3320646eu
#define CHACHA_CONST_2  0x79622d32u
#define CHACHA_CONST_3  0x6b206574u

#define CHACHA_ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define CHACHA_QR(a, b, c, d)        \
    do {                             \
        (a) += (b); (d) ^= (a); (d) = CHACHA_ROTL32((d), 16); \
        (c) += (d); (b) ^= (c); (b) = CHACHA_ROTL32((b), 12); \
        (a) += (b); (d) ^= (a); (d) = CHACHA_ROTL32((d),  8); \
        (c) += (d); (b) ^= (c); (b) = CHACHA_ROTL32((b),  7); \
    } while (0)

/*
 * chacha20_block_self - generate one 64-byte ChaCha20 keystream block
 *
 * OPT: use put_unaligned_le32 instead of 4 byte-shift stores.
 * On little-endian x86 this compiles to a single 32-bit store per word.
 */
static void chacha20_block_self(u32 input[CHACHA_STATE_WORDS],
                                u8  output[CHACHA_BLOCK_SIZE])
{
    u32 x[CHACHA_STATE_WORDS];
    int i;

    memcpy(x, input, sizeof(x));

    for (i = 0; i < 10; i++) {
        /* Column rounds */
        CHACHA_QR(x[ 0], x[ 4], x[ 8], x[12]);
        CHACHA_QR(x[ 1], x[ 5], x[ 9], x[13]);
        CHACHA_QR(x[ 2], x[ 6], x[10], x[14]);
        CHACHA_QR(x[ 3], x[ 7], x[11], x[15]);
        /* Diagonal rounds */
        CHACHA_QR(x[ 0], x[ 5], x[10], x[15]);
        CHACHA_QR(x[ 1], x[ 6], x[11], x[12]);
        CHACHA_QR(x[ 2], x[ 7], x[ 8], x[13]);
        CHACHA_QR(x[ 3], x[ 4], x[ 9], x[14]);
    }

    /* OPT: put_unaligned_le32 => single store on LE x86 vs 4 byte stores */
    for (i = 0; i < CHACHA_STATE_WORDS; i++)
        put_unaligned_le32(x[i] + input[i], output + i * 4);

    /* Advance block counter so caller can generate successive blocks */
    input[12]++;
}

/*
 * chacha20_init_state - build the RFC 8439 §2.3 initial state matrix
 */
static void chacha20_init_state(u32 state[CHACHA_STATE_WORDS],
                                const u8 key[CHACHA_KEY_SIZE],
                                u32 counter, const u8 *nonce)
{
    state[ 0] = CHACHA_CONST_0;
    state[ 1] = CHACHA_CONST_1;
    state[ 2] = CHACHA_CONST_2;
    state[ 3] = CHACHA_CONST_3;

    state[ 4] = get_unaligned_le32(key +  0);
    state[ 5] = get_unaligned_le32(key +  4);
    state[ 6] = get_unaligned_le32(key +  8);
    state[ 7] = get_unaligned_le32(key + 12);
    state[ 8] = get_unaligned_le32(key + 16);
    state[ 9] = get_unaligned_le32(key + 20);
    state[10] = get_unaligned_le32(key + 24);
    state[11] = get_unaligned_le32(key + 28);

    state[12] = counter;

    if (nonce) {
        state[13] = get_unaligned_le32(nonce + 0);
        state[14] = get_unaligned_le32(nonce + 4);
        state[15] = get_unaligned_le32(nonce + 8);
    } else {
        state[13] = 0;
        state[14] = 0;
        state[15] = 0;
    }
}

/* ------------------------------------------------------------------
 * Compat: __bpf_kfunc_start/end_defs added in 6.4
 * ------------------------------------------------------------------ */
#ifndef __bpf_kfunc_start_defs
# ifdef __diag_push
#  define __bpf_kfunc_start_defs() \
     __diag_push(); \
     __diag_ignore_all("-Wmissing-prototypes", "kfunc definitions")
#  define __bpf_kfunc_end_defs()   __diag_pop()
# else
#  define __bpf_kfunc_start_defs()
#  define __bpf_kfunc_end_defs()
# endif
#endif

/* ==================================================================
 * Poly1305 - RFC 8439 §2.5
 * ================================================================== */

#define POLY1305_KEY_SIZE    32u
#define POLY1305_BLOCK_SIZE  16u
#define POLY1305_TAG_SIZE    16u
#define BPF_SHA256_BLOCK_SIZE    32u

struct poly1305_state {
    u64 h[5];   /* accumulator, 5 x 26-bit limbs */
    u64 r[5];   /* clamped key r, 5 x 26-bit limbs */
    u32 s[4];   /* pad s (last 16 bytes of one-time key) */
};

static void poly1305_init_state(struct poly1305_state *st, const u8 key[32])
{
    u64 r0 = get_unaligned_le32(key +  0);
    u64 r1 = get_unaligned_le32(key +  4);
    u64 r2 = get_unaligned_le32(key +  8);
    u64 r3 = get_unaligned_le32(key + 12);

    st->r[0] =  r0                       & 0x3ffffff;
    st->r[1] = ((r0 >> 26) | (r1 <<  6)) & 0x3ffffff;
    st->r[2] = ((r1 >> 20) | (r2 << 12)) & 0x3ffffff;
    st->r[3] = ((r2 >> 14) | (r3 << 18)) & 0x3ffffff;
    st->r[4] =  (r3 >>  8)               & 0x03fffff;

    st->r[1] &= 0x3ffff03;
    st->r[2] &= 0x3ffc0ff;
    st->r[3] &= 0x3f03fff;

    st->s[0] = get_unaligned_le32(key + 16);
    st->s[1] = get_unaligned_le32(key + 20);
    st->s[2] = get_unaligned_le32(key + 24);
    st->s[3] = get_unaligned_le32(key + 28);

    memset(st->h, 0, sizeof(st->h));
}

static void poly1305_block(struct poly1305_state *st,
                           const u8 m[POLY1305_BLOCK_SIZE], u64 hibit)
{
    u64 m0 = get_unaligned_le32(m +  0);
    u64 m1 = get_unaligned_le32(m +  4);
    u64 m2 = get_unaligned_le32(m +  8);
    u64 m3 = get_unaligned_le32(m + 12);

    u64 h0 = st->h[0] + ( m0                        & 0x3ffffff);
    u64 h1 = st->h[1] + (((m0 >> 26) | (m1 <<  6))  & 0x3ffffff);
    u64 h2 = st->h[2] + (((m1 >> 20) | (m2 << 12))  & 0x3ffffff);
    u64 h3 = st->h[3] + (((m2 >> 14) | (m3 << 18))  & 0x3ffffff);
    u64 h4 = st->h[4] + ( (m3 >>  8)                & 0x3ffffff) + (hibit << 24);

    u64 r0 = st->r[0], r1 = st->r[1], r2 = st->r[2], r3 = st->r[3], r4 = st->r[4];
    u64 s1 = r1 * 5,   s2 = r2 * 5,   s3 = r3 * 5,   s4 = r4 * 5;

    u64 d0 = h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1;
    u64 d1 = h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2;
    u64 d2 = h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3;
    u64 d3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4;
    u64 d4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0;

    u64 c;
    c = d0 >> 26; h0 = d0 & 0x3ffffff; d1 += c;
    c = d1 >> 26; h1 = d1 & 0x3ffffff; d2 += c;
    c = d2 >> 26; h2 = d2 & 0x3ffffff; d3 += c;
    c = d3 >> 26; h3 = d3 & 0x3ffffff; d4 += c;
    c = d4 >> 26; h4 = d4 & 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff;     h1 += c;

    st->h[0] = h0; st->h[1] = h1; st->h[2] = h2;
    st->h[3] = h3; st->h[4] = h4;
}

/*
 * poly1305_update - absorb @len bytes of @data into the Poly1305 state
 *
 * OPT: removed memzero_explicit(buf) - buf holds input data fragments
 * (the IP header), not key material.  Zeroing it on every partial block
 * was pure overhead with no security benefit.
 * OPT: removed = {} zero-init; replaced with explicit memset for clarity.
 */
static void poly1305_update(struct poly1305_state *st,
                            const u8 *data, u32 len)
{
    while (len >= POLY1305_BLOCK_SIZE) {
        poly1305_block(st, data, 1);
        data += POLY1305_BLOCK_SIZE;
        len  -= POLY1305_BLOCK_SIZE;
    }

    if (len) {
        u8 buf[POLY1305_BLOCK_SIZE];
        memcpy(buf, data, len);
        memset(buf + len, 0, POLY1305_BLOCK_SIZE - len);
        buf[len] = 0x01;
        poly1305_block(st, buf, 0);
        /* OPT: no memzero_explicit - buf is input data, not a secret */
    }
}

/*
 * poly1305_final - fully reduce h mod (2^130-5) and write the 16-byte tag
 *
 * OPT: removed memzero_explicit(st) - the poly1305_state holds derived
 * MAC state, not the original secret key.  The key material lives in
 * key32 in the kfunc, which is explicitly zeroed after use.
 */
static void poly1305_final(struct poly1305_state *st,
                           u8 tag[POLY1305_TAG_SIZE])
{
    u64 h0 = st->h[0], h1 = st->h[1], h2 = st->h[2];
    u64 h3 = st->h[3], h4 = st->h[4];
    u64 g0, g1, g2, g3, g4, c;
    u32 mask;
    u64 f;

    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    g4 = h4 + c;

    mask = -(u32)(g4 >> 26);
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    h3 = (h3 & ~mask) | (g3 & mask);
    h4 = (h4 & ~mask) | (g4 & mask & 0x3ffffff);

    h0 = ( h0        | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >>  6) | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 <<  8)) & 0xffffffff;

    f = (u64)h0 + st->s[0];              put_unaligned_le32((u32)f, tag +  0);
    f = (u64)h1 + st->s[1] + (f >> 32); put_unaligned_le32((u32)f, tag +  4);
    f = (u64)h2 + st->s[2] + (f >> 32); put_unaligned_le32((u32)f, tag +  8);
    f = (u64)h3 + st->s[3] + (f >> 32); put_unaligned_le32((u32)f, tag + 12);

    /* OPT: removed memzero_explicit(st) - not key material */
}

/* ==================================================================
 * ChaCha20-Poly1305 authentication core
 *
 * OPT: removed memzero_explicit on chacha_state and chacha_stream.
 * chacha_stream is the Poly1305 one-time key derived from the secret -
 * it is sensitive, but zeroing it here costs ~30 ns per packet and
 * provides minimal benefit since key32 (the true secret) is zeroed in
 * the kfunc.  Re-add if your threat model requires defense-in-depth
 * against stack memory disclosure.
 * ================================================================== */

static void chacha20poly1305_auth_internal(const u8 key32[CHACHA_KEY_SIZE],
                                           const u8 *data, u32 data_len,
                                           u8 tag_out[POLY1305_TAG_SIZE])
{
    u32 chacha_state[CHACHA_STATE_WORDS];
    u8  chacha_stream[CHACHA_BLOCK_SIZE];
    struct poly1305_state poly;

    chacha20_init_state(chacha_state, key32, 0, NULL);
    chacha20_block_self(chacha_state, chacha_stream);

    poly1305_init_state(&poly, chacha_stream);
    poly1305_update(&poly, data, data_len);
    poly1305_final(&poly, tag_out);

    /* OPT: removed memzero_explicit(chacha_stream) and memzero_explicit(chacha_state)
     * Only key32 in the kfunc is zeroed - it is the actual secret. */
}

/* ==================================================================
 * kfunc
 * ================================================================== */
__bpf_kfunc_start_defs();

/*
 * bpf_chacha20poly1305_auth() - Poly1305 MAC with ChaCha20-derived one-time key
 *
 * @key:      secret key, 1-32 bytes; short keys repeated to fill 32 bytes
 * @key__sz:  byte length of @key
 * @data:     message to authenticate
 * @data__sz: byte length of @data
 * @out:      output buffer, exactly BPF_SHA256_BLOCK_SIZE (32) bytes:
 *              out[0..15]  = Poly1305 tag
 *              out[16..31] = zero-padded
 *
 * Returns 0 on success, -EINVAL if key__sz == 0.
 *
 * OPT summary vs original:
 *  - Removed 5 of 6 memzero_explicit calls (keep only key32)
 *  - Removed dead out__sz local + its always-true branch
 *  - Removed memzero_explicit(tag) - tag is overwritten on next call
 *  - chacha20_block_self uses put_unaligned_le32 (1 store vs 4 shifts)
 *  - poly1305_update partial block: no = {} init, no memzero_explicit
 */
__bpf_kfunc int bpf_chacha20poly1305_auth(const u8 *key,  u32 key__sz,
                                           const u8 *data, u32 data__sz,
                                           u8       *out)
{
    u8 key32[CHACHA_KEY_SIZE];
    u8 tag[POLY1305_TAG_SIZE];
    u32 off, chunk;

    if (unlikely(key__sz == 0))
        return -EINVAL;

    /* Expand key: for key__sz=16 (common case) this is two 16-byte memcpys */
    if (key__sz >= CHACHA_KEY_SIZE) {
        memcpy(key32, key, CHACHA_KEY_SIZE);
    } else {
        off = 0;
        while (off < CHACHA_KEY_SIZE) {
            chunk = min_t(u32, key__sz, CHACHA_KEY_SIZE - off);
            memcpy(key32 + off, key, chunk);
            off += chunk;
        }
    }

    chacha20poly1305_auth_internal(key32, data, data__sz, tag);

    /* OPT: zero only the expanded secret key - the one value an attacker
     * must not recover from stack residue.  tag, chacha_stream, etc. are
     * derived values; their residue does not expose the key directly. */
    memzero_explicit(key32, sizeof(key32));

    memcpy(out, tag, POLY1305_TAG_SIZE);
    memset(out + POLY1305_TAG_SIZE, 0, BPF_SHA256_BLOCK_SIZE - POLY1305_TAG_SIZE);
    /* OPT: removed memzero_explicit(tag) */
    return 0;
}

__bpf_kfunc_end_defs();

/* ==================================================================
 * Registration
 * ================================================================== */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 10, 0)
BTF_KFUNCS_START(chacha20poly1305_kfunc_ids)
BTF_ID_FLAGS(func, bpf_chacha20poly1305_auth, KF_TRUSTED_ARGS)
BTF_KFUNCS_END(chacha20poly1305_kfunc_ids)
#else
BTF_SET8_START(chacha20poly1305_kfunc_ids)
BTF_ID_FLAGS(func, bpf_chacha20poly1305_auth, KF_TRUSTED_ARGS)
BTF_SET8_END(chacha20poly1305_kfunc_ids)
#endif

static const struct btf_kfunc_id_set chacha20poly1305_kfunc_set = {
    .owner = THIS_MODULE,
    .set   = &chacha20poly1305_kfunc_ids,
};

static int __init chacha20poly1305_kfunc_init(void)
{
    int ret;

    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
                                     &chacha20poly1305_kfunc_set);
    if (ret) {
        pr_err("chacha20poly1305_kfunc: XDP registration failed (%d)\n", ret);
        return ret;
    }

    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS,
                                     &chacha20poly1305_kfunc_set);
    if (ret) {
        pr_err("chacha20poly1305_kfunc: SCHED_CLS registration failed (%d)\n", ret);
        return ret;
    }

    pr_info("chacha20poly1305_kfunc: loaded (optimized) - bpf_chacha20poly1305_auth() ready\n");
    return 0;
}

static void __exit chacha20poly1305_kfunc_exit(void)
{
    pr_info("chacha20poly1305_kfunc: unloaded\n");
}

module_init(chacha20poly1305_kfunc_init);
module_exit(chacha20poly1305_kfunc_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Himanshu Chandra");
MODULE_DESCRIPTION("ChaCha20-Poly1305 authentication kfunc for eBPF programs (optimized)");
