/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * chacha20_kfunc.h
 *
 * Include this header in eBPF programs that want to call
 * bpf_chacha20poly1305_hash().
 *
 * The kfunc is implemented in chacha20poly1305_kfunc.c and registered for
 * BPF_PROG_TYPE_XDP and BPF_PROG_TYPE_SCHED_CLS.
 *
 * Output layout
 * -------------
 * The Poly1305 tag is 16 bytes.  The kfunc zero-pads the output buffer up to
 * out__sz bytes, so passing SHA256_BLOCK_SIZE (32) works as a drop-in
 * replacement of the existing SHA-256 / custom ChaCha20 hash_result[] arrays.
 * Note: only the first 16 bytes carry authentication data; the trailing 16
 * bytes are always zero.  Comparison logic in the eBPF verifier program must
 * therefore compare only the first POLY1305_DIGEST_SIZE (16) bytes, or compare
 * the full buffer (the zeros will naturally match on both sides).
 */

#ifndef __CHACHA20POLY1305_KFUNC_H
#define __CHACHA20POLY1305_KFUNC_H

#define POLY1305_DIGEST_SIZE  16   /* Poly1305 tag length in bytes  */
#define CHACHA_KEY_SIZE       32   /* ChaCha20 key size in bytes    */

/*
 * kfunc declaration for the BPF-program side.
 *
 * Key rules for kfunc externs in eBPF C (clang + libbpf):
 *
 *  1. Use __ksym (expands to __attribute__((section(".ksyms"))) in
 *     bpf_helpers.h) so libbpf resolves the BTF ID at load time.
 *
 *  2. Drop const qualifiers on pointer parameters.  Some clang versions
 *     (< 16) mishandle const-qualified pointers in kfunc call lowering
 *     and produce the "too many args" LLVM error you may have seen.
 *
 *  3. Use void * instead of typed pointers (u8 *, etc.) for the same
 *     reason — the BPF backend occasionally rejects typed ptr kfunc
 *     args when it cannot match them against the BTF.  The kernel-side
 *     kfunc still receives the correct pointer; only the eBPF-side type
 *     annotation is relaxed here.
 *
 *  4. The __sz suffix on size parameters is the BTF convention that
 *     tells the verifier which size arg bounds which pointer arg.
 *     The names must match: key / key__sz, data / data__sz, out / out__sz.
 *
 *  5. Six-argument kfuncs require clang >= 14 and libbpf >= 1.0.
 *     Verify with:  clang --version
 *
 * Example (TC / XDP, use_kfunc == 2):
 *
 *   __u8 hash_result[SHA256_BLOCK_SIZE] = {};   // 32-byte buffer
 *   int ret = bpf_chacha20poly1305_hash(auth_data->key, 16,
 *                                       hdr_copy, header_size,
 *                                       hash_result, sizeof(hash_result));
 *   if (ret != 0) { ... error ... }
 *   // hash_result[0..15] holds the Poly1305 tag
 *   // hash_result[16..31] are zero (zero-padded by kfunc)
 */
extern int bpf_chacha20poly1305_hash(const __u8 *key,  __u32 key__sz,
                                     const __u8 *data, __u32 data__sz,
                                     __u8 *out) __ksym;

#endif /* __CHACHA20POLY1305_KFUNC_H */
