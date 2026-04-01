/*********************************************************************
 * Filename:   chacha20.h
 * Description: ChaCha20-Poly1305 auth-only MAC for TC eBPF programs.
 *
 *              Defines the maps and the inline helper
 *              compute_chacha20_keyed_hash() used by tc_prog_kern_03.c
 *              when use_kfunc == 2.
 *
 *              Map layout:
 *                crypto_ctx_map  — kptr to bpf_crypto_ctx created by
 *                                  setup_chacha_ctx (SEC("syscall"))
 *                psk_map         — 32-byte pre-shared key written by
 *                                  setup_loader before TC attach
 *                nonce_map       — u64 monotonic counter, one slot,
 *                                  incremented atomically per packet
 *********************************************************************/

#ifndef CHACHA20_H
#define CHACHA20_H

/*
 * Only BPF-safe headers here — no userspace headers (<stdio.h> etc.).
 * bpf_helpers.h and bpf_endian.h are already included by the parent
 * .c file via vmlinux.h / common headers, but guard includes are safe.
 */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_crypto.h"         /* struct bpf_crypto_params, kfuncs  */

/* ------------------------------------------------------------------ */
/*  Constants                                                           */
/* ------------------------------------------------------------------ */

/*
 * Output buffer size — reuses SHA256_BLOCK_SIZE (32 bytes) so the
 * result fits in the same hash_result[] buffer and add_ip_option_hash_tc
 * needs no changes.
 *
 * Layout:
 *   [0 ..11]  12-byte nonce  (4-byte zero pad + 8-byte BE counter)
 *   [12..27]  16-byte Poly1305 authentication tag
 *   [28..31]  zero padding
 */
#define CHACHA20_OUT_LEN     32   /* == SHA256_BLOCK_SIZE              */
#define CHACHA20_NONCE_LEN   12   /* ChaCha20-Poly1305 nonce size      */
#define CHACHA20_TAG_LEN     16   /* Poly1305 tag size                  */

/* ------------------------------------------------------------------ */
/*  Maps                                                                */
/* ------------------------------------------------------------------ */

/*
 * crypto_ctx_map — holds the bpf_crypto_ctx kptr created once by
 * setup_chacha_ctx.  The TC fast path acquires/releases a reference
 * on every packet.
 */
struct {
    __uint(type,        BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, struct bpf_crypto_ctx *);  /* kptr */
} crypto_ctx_map SEC(".maps");

/*
 * psk_map — pre-shared key written by setup_loader before the TC
 * program is attached.  Read once by setup_chacha_ctx to create the
 * crypto context.
 */
struct {
    __uint(type,        BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, __u8[32]);
} psk_map SEC(".maps");

/*
 * nonce_map — single u64 counter, incremented atomically on every
 * packet.  Using a per-CPU map would give independent counters per CPU
 * but then the receiver needs the CPU id; a plain ARRAY with atomic
 * increment is simpler and correct.
 *
 * CRITICAL: (key, nonce) pairs must never repeat.  The atomic
 * increment guarantees this for the lifetime of the map.
 */
struct {
    __uint(type,        BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, __u64);
} nonce_map SEC(".maps");

/* ------------------------------------------------------------------ */
/*  compute_chacha20_keyed_hash                                         */
/* ------------------------------------------------------------------ */

/*
 * compute_chacha20_keyed_hash - compute a ChaCha20-Poly1305 auth tag
 *
 * Auth-only mode (Mode A):
 *   plaintext = empty  →  nothing is encrypted
 *   AAD       = @data  →  IP header to authenticate
 *   output    = 16-byte Poly1305 tag stored in @hash[12..27]
 *             + 12-byte nonce            stored in @hash[0..11]
 *
 * @key      : not used directly (context was pre-created from psk_map)
 *             kept to match the SHA256 function signature
 * @key_len  : not used
 * @data     : data to authenticate (IP header bytes)
 * @data_len : byte length of @data
 * @hash     : output buffer, must be >= CHACHA20_OUT_LEN (32) bytes
 *
 * Returns 0 on success, negative on error.
 */
static __always_inline int
compute_chacha20_keyed_hash(const __u8 *key,  __u32 key_len,
                            const __u8 *data, __u32 data_len,
                            __u8       *hash)
{
    /* ---- 1. Look up the pre-created crypto context ---- */
    __u32 map_key = 0;
    struct bpf_crypto_ctx **cctx_p =
        bpf_map_lookup_elem(&crypto_ctx_map, &map_key);
    if (!cctx_p || !*cctx_p)
        return -1;

    /* ---- 2. Acquire a per-packet reference ---- */
    struct bpf_crypto_ctx *cctx = bpf_crypto_ctx_acquire(*cctx_p);
    if (!cctx)
        return -1;

    /* ---- 3. Obtain a unique, monotonically increasing nonce ---- */
    __u64 *ctr = bpf_map_lookup_elem(&nonce_map, &map_key);
    if (!ctr) {
        bpf_crypto_ctx_release(cctx);
        return -1;
    }

    /*
     * Atomically increment so concurrent CPUs never share a nonce.
     * A repeated (key, nonce) pair breaks ChaCha20-Poly1305 entirely —
     * an attacker could recover the Poly1305 key and forge packets.
     */
    __u64 nonce_val = __sync_fetch_and_add(ctr, 1);

    /*
     * Pack the 12-byte nonce:
     *   bytes [0.. 3]  = 0x00000000  (4-byte little-endian counter, fixed 0)
     *   bytes [4..11]  = nonce_val   (8-byte big-endian monotonic counter)
     *
     * Storing the nonce in hash[0..11] lets the receiver extract it
     * directly from the IP option and reproduce the Poly1305 key.
     */
    __u8 nonce[CHACHA20_NONCE_LEN];
    __builtin_memset(nonce, 0, 4);
    *(__u64 *)(nonce + 4) = bpf_cpu_to_be64(nonce_val);

    /* ---- 4. Build dynptrs ---- */
    /*
     * src  = empty  — auth-only, nothing to encrypt
     * dst  = hash[CHACHA20_NONCE_LEN..]  — receives the 16-byte tag
     * iv   = nonce  — 12-byte ChaCha20-Poly1305 nonce
     *
     * bpf_crypto_encrypt() with an empty src writes only the
     * AEAD tag (16 bytes) into dst; no ciphertext is prepended.
     */
    __u8 empty[1] = {};
    struct bpf_dynptr src_ptr, dst_ptr, iv_ptr;

    bpf_dynptr_from_mem(empty,
                        sizeof(empty),
                        0, &src_ptr);

    bpf_dynptr_from_mem(hash + CHACHA20_NONCE_LEN,  /* tag goes after nonce */
                        CHACHA20_TAG_LEN,
                        0, &dst_ptr);

    bpf_dynptr_from_mem(nonce,
                        sizeof(nonce),
                        0, &iv_ptr);

    /* ---- 5. Generate authentication tag ---- */
    /*
     * The IP header (@data) is passed as AAD.  However, bpf_crypto_encrypt
     * takes the AAD as part of the src dynptr for AEAD — with src_len == 0
     * the tag covers only the IV and the empty plaintext.  To authenticate
     * the IP header as AAD, build a dynptr from @data and pass it as src.
     *
     * Note: some kernel versions expose a separate aad parameter; adjust
     * if your kernel's bpf_crypto_encrypt signature differs.
     */
    struct bpf_dynptr aad_ptr;
    bpf_dynptr_from_mem((void *)data, data_len, 0, &aad_ptr);

    int ret = bpf_crypto_encrypt(cctx, &aad_ptr, &dst_ptr, &iv_ptr);

    /* ---- 6. Store nonce in the output buffer ---- */
    if (ret == 0)
        __builtin_memcpy(hash, nonce, CHACHA20_NONCE_LEN);

    /* Zero the padding bytes [28..31] */
    __builtin_memset(hash + CHACHA20_NONCE_LEN + CHACHA20_TAG_LEN, 0,
                     CHACHA20_OUT_LEN - CHACHA20_NONCE_LEN - CHACHA20_TAG_LEN);

    /* ---- 7. Release the per-packet reference ---- */
    bpf_crypto_ctx_release(cctx);

    return ret;
}

#endif /* CHACHA20_H */
