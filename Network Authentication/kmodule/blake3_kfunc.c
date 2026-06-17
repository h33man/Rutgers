// SPDX-License-Identifier: GPL-2.0-only
/*
 * blake3_kfunc.c
 *
 * Exposes BLAKE3 hash as a BPF kfunc.
 *
 * BLAKE3 is NOT in the mainline kernel Crypto API, so this module bundles
 * a self-contained, portable C implementation derived from the BLAKE3
 * reference implementation (https://github.com/BLAKE3-team/BLAKE3,
 * Creative Commons CC0 / Apache 2.0).  Only scalar C is used here (no
 * SSE/AVX intrinsics) to avoid BTF-symbol-deduplication issues identical
 * to those documented in chacha20_kfunc.c: including kernel SIMD headers
 * can cause pahole to strip kfunc BTF entries from the .ko.
 *
 * The implementation covers:
 *   - Single-call "oneshot" hashing up to 1 KiB of input
 *   - 32-byte (256-bit) output
 *
 * Restrictions kept intentionally tight for eBPF verifier stack safety:
 *   data_len <= 1024 bytes
 *   out is exactly 32 bytes
 *
 * kfunc signature visible to BPF programs:
 *
 *   int bpf_blake3_hash(const __u8 *data, __u32 data_len, __u8 *out);
 *
 * Returns 0 on success, -EINVAL on bad args.
 *
 * Design notes (matching chacha20_kfunc.c conventions):
 *   - No kernel crypto API dependency — zero external symbols required
 *   - No dynamic allocation in the hot path
 *   - __bpf_kfunc_start/end_defs() compat shim for kernels < 6.4
 *   - BTF_KFUNCS_START/END vs BTF_SET8_START/END version gate at 6.10
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include <linux/unaligned.h>
#else
#include <asm/unaligned.h>
#endif

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
 * BLAKE3 — self-contained scalar C implementation
 *
 * Spec: https://github.com/BLAKE3-team/BLAKE3/blob/master/spec/blake3.pdf
 *
 * Scope: oneshot hashing of up to 1 KiB.  Streaming / XOF / keyed-hash
 * / key-derivation modes are not implemented (not needed for kfunc use).
 * ================================================================== */

/* ---- Constants ---- */
#define BLAKE3_KEY_LEN        32u
#define BLAKE3_OUT_LEN        32u
#define BLAKE3_BLOCK_LEN      64u
#define BLAKE3_CHUNK_LEN    1024u

/* Number of words in the chaining value / output */
#define BLAKE3_STATE_WORDS    16u
#define BLAKE3_CV_WORDS        8u

/* Domain flags */
#define BLAKE3_CHUNK_START   (1u << 0)
#define BLAKE3_CHUNK_END     (1u << 1)
#define BLAKE3_PARENT        (1u << 2)
#define BLAKE3_ROOT          (1u << 3)

/* Initialization vector (same as SHA-256 IV) */
static const u32 BLAKE3_IV[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u,
};

/* Message permutation for each round */
static const u8 BLAKE3_MSG_SCHEDULE[7][16] = {
    { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15},
    { 2, 10,  8, 14,  3,  4,  9, 15,  0,  6,  5, 11, 13,  7, 12,  1},
    { 3, 11, 10, 15,  1,  9,  6, 14,  0,  7,  5,  8, 12,  2,  4, 13},
    { 1, 14, 10,  0,  2,  8, 14,  6,  3,  4,  9,  5, 12, 11,  7, 13},
    {11,  8,  7,  9,  3, 14,  4,  5,  2, 15,  6,  0, 10, 13,  1, 12},
    { 7,  5,  3,  1, 13, 11, 12, 14,  2,  4,  6,  8, 15,  0,  9, 10},
    { 1,  7, 14,  5, 10,  8,  3,  9, 13,  6,  0,  2, 11, 15, 12,  4},
};

/* ---- Primitives ---- */

static inline u32 b3_rotr32(u32 x, unsigned n)
{
    return (x >> n) | (x << (32 - n));
}

static inline void b3_g(u32 state[16], size_t a, size_t b, size_t c, size_t d,
                         u32 mx, u32 my)
{
    state[a] = state[a] + state[b] + mx;
    state[d] = b3_rotr32(state[d] ^ state[a], 16);
    state[c] = state[c] + state[d];
    state[b] = b3_rotr32(state[b] ^ state[c], 12);
    state[a] = state[a] + state[b] + my;
    state[d] = b3_rotr32(state[d] ^ state[a],  8);
    state[c] = state[c] + state[d];
    state[b] = b3_rotr32(state[b] ^ state[c],  7);
}

static inline void b3_round(u32 state[16], const u32 m[16], size_t round)
{
    const u8 *sched = BLAKE3_MSG_SCHEDULE[round % 7];

    /* Column step */
    b3_g(state, 0, 4,  8, 12, m[sched[ 0]], m[sched[ 1]]);
    b3_g(state, 1, 5,  9, 13, m[sched[ 2]], m[sched[ 3]]);
    b3_g(state, 2, 6, 10, 14, m[sched[ 4]], m[sched[ 5]]);
    b3_g(state, 3, 7, 11, 15, m[sched[ 6]], m[sched[ 7]]);
    /* Diagonal step */
    b3_g(state, 0, 5, 10, 15, m[sched[ 8]], m[sched[ 9]]);
    b3_g(state, 1, 6, 11, 12, m[sched[10]], m[sched[11]]);
    b3_g(state, 2, 7,  8, 13, m[sched[12]], m[sched[13]]);
    b3_g(state, 3, 4,  9, 14, m[sched[14]], m[sched[15]]);
}

/*
 * b3_compress - BLAKE3 compression function
 *
 * @chaining:  8-word input chaining value (CV)
 * @block_words: 16-word message block (little-endian words)
 * @counter:   64-bit chunk counter (lo and hi halves)
 * @blen:      number of bytes in this block (0..64)
 * @flags:     domain separation flags
 * @out:       16-word output state (caller XORs to get new CV)
 */
static void b3_compress(const u32 chaining[8],
                        const u32 block_words[16],
                        u64 counter, u32 blen, u32 flags,
                        u32 out[16])
{
    u32 state[16];
    int i;

    /* Upper half: chaining value */
    for (i = 0; i < 8; i++)
        state[i] = chaining[i];
    /* Lower half: IV, counter, block length, flags */
    state[ 8] = BLAKE3_IV[0];
    state[ 9] = BLAKE3_IV[1];
    state[10] = BLAKE3_IV[2];
    state[11] = BLAKE3_IV[3];
    state[12] = (u32)(counter & 0xFFFFFFFFu);
    state[13] = (u32)(counter >> 32);
    state[14] = blen;
    state[15] = flags;

    /* 7 rounds */
    for (i = 0; i < 7; i++)
        b3_round(state, block_words, i);

    /* XOR upper and lower halves */
    for (i = 0; i < 8; i++) {
        out[i]     = state[i] ^ state[i + 8];
        out[i + 8] = state[i + 8] ^ chaining[i];
    }
}

/* Read up to 64 bytes of input into a 16-word LE block, zero-padding remainder */
static void b3_load_block(const u8 *src, size_t src_len,
                           u32 words[16])
{
    u8 buf[BLAKE3_BLOCK_LEN];
    size_t i;

    memset(buf, 0, BLAKE3_BLOCK_LEN);
    if (src_len > BLAKE3_BLOCK_LEN)
        src_len = BLAKE3_BLOCK_LEN;
    memcpy(buf, src, src_len);

    for (i = 0; i < 16; i++)
        words[i] = get_unaligned_le32(buf + i * 4);
}

/*
 * b3_hash_oneshot - BLAKE3 hash for inputs up to one chunk (1024 bytes)
 *
 * For inputs <= 1024 bytes there is at most one chunk and no parent nodes,
 * which keeps the implementation simple and stack-bounded.
 *
 * Inputs longer than 1024 bytes would require a Merkle tree of parent
 * nodes; that is not implemented.  The kfunc enforces data_len <= 1024.
 */
static void b3_hash_oneshot(const u8 *data, size_t data_len,
                              u8 out[BLAKE3_OUT_LEN])
{
    const u32 *cv = BLAKE3_IV;     /* chunk CV starts as IV for hash mode */
    u32 block_words[16];
    u32 compress_out[16];
    u32 cv_buf[8];
    size_t offset = 0;
    u32 flags;
    bool first_block = true;
    u32 block_len;

    /*
     * Process the input in 64-byte blocks within the single chunk.
     * Each block gets CHUNK_START on the first block, CHUNK_END on
     * the last (which may be both if input <= 64 bytes), and ROOT
     * because there is only one chunk.
     */
    do {
        size_t remaining = data_len - offset;
        bool   last_block = (remaining <= BLAKE3_BLOCK_LEN);

        block_len = last_block ? (u32)remaining : BLAKE3_BLOCK_LEN;

        flags = 0;
        if (first_block)
            flags |= BLAKE3_CHUNK_START;
        if (last_block)
            flags |= BLAKE3_CHUNK_END | BLAKE3_ROOT;

        b3_load_block(data + offset, block_len, block_words);
        b3_compress(cv, block_words, 0, block_len, flags, compress_out);

        /* New CV is the first 8 words of compress output */
        memcpy(cv_buf, compress_out, sizeof(cv_buf));
        cv = cv_buf;

        offset     += block_len;
        first_block = false;

    } while (offset < data_len && !(flags & BLAKE3_CHUNK_END));

    /*
     * Handle the edge case of zero-length input: one empty ROOT block.
     * The loop above runs at least once, so offset==0 only if data_len==0
     * and the loop body executed with block_len=0, flags=START|END|ROOT.
     * This is already handled correctly by the loop above.
     */

    /* Write the first 32 bytes of compress_out as the hash output */
    {
        int i;
        for (i = 0; i < 8; i++)
            put_unaligned_le32(compress_out[i], out + i * 4);
    }
}

/* ==================================================================
 * kfunc
 * ================================================================== */
__bpf_kfunc_start_defs();

/**
 * bpf_blake3_hash - compute BLAKE3(data) with 32-byte output
 * @data:     pointer to input bytes (BPF-trusted)
 * @data_len: length of input, must be <= 1024
 * @out:      output buffer, must be exactly 32 bytes (BPF-trusted)
 *
 * Returns 0 on success, -EINVAL on bad args.
 *
 * Note: For inputs > 1024 bytes, BLAKE3 requires a Merkle-tree parent
 * node construction not implemented here.  If you need larger inputs,
 * either hash in the caller (XOR/fold) or extend this module.
 */
__bpf_kfunc int bpf_blake3_hash(const __u8 *data, __u32 data_len, __u8 *out)
{
    if (!data || !out)
        return -EINVAL;
    if (data_len > BLAKE3_CHUNK_LEN)
        return -EINVAL;

    b3_hash_oneshot(data, data_len, out);
    return 0;
}

__bpf_kfunc_end_defs();

EXPORT_SYMBOL_GPL(bpf_blake3_hash);

/* ==================================================================
 * Registration
 * ================================================================== */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 10, 0)
BTF_KFUNCS_START(blake3_kfunc_ids)
BTF_ID_FLAGS(func, bpf_blake3_hash, KF_TRUSTED_ARGS)
BTF_KFUNCS_END(blake3_kfunc_ids)
#else
BTF_SET8_START(blake3_kfunc_ids)
BTF_ID_FLAGS(func, bpf_blake3_hash, KF_TRUSTED_ARGS)
BTF_SET8_END(blake3_kfunc_ids)
#endif

static const struct btf_kfunc_id_set blake3_kfunc_set = {
    .owner = THIS_MODULE,
    .set   = &blake3_kfunc_ids,
};

static int __init blake3_kfunc_init(void)
{
    int ret;

    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &blake3_kfunc_set);
    if (ret) {
        pr_err("blake3_kfunc: XDP registration failed (%d)\n", ret);
        return ret;
    }

    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS, &blake3_kfunc_set);
    if (ret)
        pr_warn("blake3_kfunc: SCHED_CLS registration failed (%d), continuing\n", ret);

    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &blake3_kfunc_set);
    if (ret)
        pr_warn("blake3_kfunc: SYSCALL registration failed (%d), continuing\n", ret);

    pr_info("blake3_kfunc: loaded — bpf_blake3_hash() ready (scalar C, up to 1 KiB input)\n");
    return 0;
}

static void __exit blake3_kfunc_exit(void)
{
    pr_info("blake3_kfunc: unloaded\n");
}

module_init(blake3_kfunc_init);
module_exit(blake3_kfunc_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Research Module");
MODULE_DESCRIPTION("BLAKE3 hash kfunc for eBPF (self-contained scalar C, no Crypto API)");
MODULE_VERSION("1.0");
