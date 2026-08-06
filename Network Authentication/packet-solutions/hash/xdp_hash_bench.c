// SPDX-License-Identifier: GPL-2.0-only
/*
 * xdp_hash_bench.c
 *
 * XDP instrumentation program for hash algorithm characterization.
 * Attaches to a physical NIC ingress hook.
 *
 * Build with exactly one ALGO_ flag:
 *
 *   -DALGO_BLANK          XDP_PASS immediately, zero instrumentation
 *   -DALGO_PARSE_ONLY     Ethernet + IP parse, time full program
 *   -DALGO_SHA256         bpf_sha256_keyed_hash(), time hash call only
 *   -DALGO_SHA512         bpf_sha512_keyed_hash(), time hash call only
 *   -DALGO_HMAC_SHA256    bpf_hmac_sha256(), time hash call only
 *   -DALGO_HMAC_SHA512    bpf_hmac_sha512(), time hash call only
 *   -DALGO_BLAKE3         bpf_blake3_keyed_hash(), time hash call only
 *   -DALGO_CHACHA20       bpf_chacha20poly1305_hash(), time hash call only
 *   -DALGO_KFUNC_SHA256   bpf_sha256_hash(), time hash only
 *   -DALGO_PURE_EBPF      compute_keyed_hash_from_map_dynamic(), time hash only
 *   -DALGO_PACKET_RESIZE  AH header insertion, time resize operation only
 *
 * Latency histogram:
 *   Each variant times exactly the operation being characterised using
 *   bpf_ktime_get_ns().  Results are accumulated in a per-CPU log2
 *   histogram map (lat_hist) with 64 buckets covering 1ns to ~9 seconds.
 *   bench_tool.py reads and aggregates per-CPU buckets after each run.
 *
 * Instruction count:
 *   Load without attaching and inspect with bpftool:
 *     bpftool -d prog load xdp_sha256.o /sys/fs/bpf/test 2>&1 | grep processed
 *     bpftool prog dump xlated pinned /sys/fs/bpf/test | grep -c "^[[:space:]]*[0-9]\+:"
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* sha256.h pulls in xdp_stats_kern.h and pinned maps — only needed for
 * the pure eBPF variant.  Including it elsewhere causes map-pin conflicts
 * at load time and inflates instruction counts. */
#if defined(ALGO_PURE_EBPF)
#include "sha256.h"
#endif

/* ------------------------------------------------------------------
 * Sanity check
 * ------------------------------------------------------------------ */
#if !defined(ALGO_BLANK)         && \
    !defined(ALGO_PARSE_ONLY)    && \
    !defined(ALGO_SHA256)        && \
    !defined(ALGO_SHA512)        && \
    !defined(ALGO_HMAC_SHA256)   && \
    !defined(ALGO_HMAC_SHA512)   && \
    !defined(ALGO_BLAKE3)        && \
    !defined(ALGO_CHACHA20)      && \
    !defined(ALGO_KFUNC_SHA256)  && \
    !defined(ALGO_PURE_EBPF)     && \
    !defined(ALGO_PACKET_RESIZE)
# error "Define exactly one ALGO_ flag"
#endif

/* ------------------------------------------------------------------
 * kfunc declarations
 * ------------------------------------------------------------------ */
#if defined(ALGO_SHA256)
extern int bpf_sha256_keyed_hash(const __u8 *key,  __u32 key_len,
                                  const __u8 *data, __u32 data_len,
                                  __u8 *hash) __ksym;
#elif defined(ALGO_SHA512)
extern int bpf_sha512_keyed_hash(const __u8 *key,  __u32 key_len,
                                  const __u8 *data, __u32 data_len,
                                  __u8 *hash) __ksym;
#elif defined(ALGO_HMAC_SHA256)
extern int bpf_hmac_sha256(const __u8 *key,  __u32 key_len,
                            const __u8 *data, __u32 data_len,
                            __u8 *out) __ksym;
#elif defined(ALGO_HMAC_SHA512)
extern int bpf_hmac_sha512(const __u8 *key,  __u32 key_len,
                            const __u8 *data, __u32 data_len,
                            __u8 *out) __ksym;
#elif defined(ALGO_BLAKE3)
extern int bpf_blake3_keyed_hash(const __u8 *key,  __u32 key_len,
                                const __u8 *data, __u32 data_len,
                            __u8 *out) __ksym;
#elif defined(ALGO_CHACHA20)
extern int bpf_chacha20poly1305_hash(const __u8 *key,  __u32 key__sz,
                                     const __u8 *data, __u32 data__sz,
                                     __u8 *out) __ksym;
#elif defined(ALGO_KFUNC_SHA256)
extern int bpf_sha256_hash(const __u8 *key, __u32 key_len,
                                const __u8 *data, __u32 data_len,
                                __u8 *hash) __ksym;
#endif

/* ------------------------------------------------------------------
 * Constants
 * ------------------------------------------------------------------ */
#define IP_HDR_LEN       20u
#define KEY_LEN          64u
#define HASH_OUT_LEN     64u

/* AH header for ALGO_PACKET_RESIZE:
 *   8 bytes fixed AH header + 32 bytes ICV (zeroed) = 40 bytes total.
 *   Protocol field 51 (IPPROTO_AH). */
#define AH_HDR_LEN       40u

/* Log2 histogram: 64 buckets, bucket i covers [2^(i-1), 2^i) nanoseconds.
 * Bucket 0 = 0ns, bucket 63 = overflow (>= 2^62 ns, ~146 years). */
#define LAT_HIST_BUCKETS 64u

/* ------------------------------------------------------------------
 * Latency histogram map — per-CPU to avoid atomic contention.
 * bench_tool.py sums across CPUs after the run.
 * Not defined for ALGO_BLANK which has no instrumentation.
 * ------------------------------------------------------------------ */
#if !defined(ALGO_BLANK)
struct {
    __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, LAT_HIST_BUCKETS);
    __type(key,         __u32);
    __type(value,       __u64);
} lat_hist SEC(".maps");

/* log2_bucket - return the log2 histogram bucket index for a latency
 * value in nanoseconds.  Uses __builtin_clzll for a branchless O(1)
 * implementation safe for the BPF verifier. */
#if 0
static __always_inline __u32 log2_bucket(__u64 ns)
{
    if (ns == 0)
        return 0;
    __u32 bit = 63 - ((__u32)__builtin_clzll(ns));
    return bit < LAT_HIST_BUCKETS ? bit : LAT_HIST_BUCKETS - 1;
}
#else
static __always_inline __u32 log2_bucket(__u64 ns)
{
    __u32 r = 0;
    if (ns >= (1ULL << 32)) { ns >>= 32; r += 32; }
    if (ns >= (1ULL << 16)) { ns >>= 16; r += 16; }
    if (ns >= (1ULL <<  8)) { ns >>=  8; r +=  8; }
    if (ns >= (1ULL <<  4)) { ns >>=  4; r +=  4; }
    if (ns >= (1ULL <<  2)) { ns >>=  2; r +=  2; }
    if (ns >= (1ULL <<  1)) {            r +=  1; }
    return r < LAT_HIST_BUCKETS ? r : LAT_HIST_BUCKETS - 1;
}
#endif

static __always_inline void record_latency(__u64 t_start, __u64 t_end)
{
    __u64 delta = t_end - t_start;
    __u32 bucket = log2_bucket(delta);
    __u64 *cnt = bpf_map_lookup_elem(&lat_hist, &bucket);
    if (cnt)
        (*cnt)++;
}
#endif /* !ALGO_BLANK */

/* ------------------------------------------------------------------
 * Fixed key — stack-copied before kfunc call to satisfy KF_TRUSTED_ARGS.
 * Not needed for BLANK or PARSE_ONLY.
 * ------------------------------------------------------------------ */
#if !defined(ALGO_BLANK) && !defined(ALGO_PARSE_ONLY) && !defined(ALGO_PACKET_RESIZE)
static const __u8 fixed_key[KEY_LEN] = {
    0x4b, 0x75, 0x8f, 0x94, 0x98, 0xd3, 0x31, 0x26,
    0x16, 0xec, 0xc2, 0x61, 0x99, 0x43, 0x76, 0x45,
    0x2a, 0x3b, 0x4c, 0x5d, 0x6e, 0x7f, 0x80, 0x91,
    0xa2, 0xb3, 0xc4, 0xd5, 0xe6, 0xf7, 0x08, 0x19,
    0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81,
    0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09,
    0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71,
    0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8, 0xf9
};
#endif

/* ==================================================================
 * XDP program
 * ================================================================== */
//SEC("xdp")
SEC("xdp.frags")
int xdp_hash_bench(struct xdp_md *ctx)
{

   bpf_printk("Processing packets...\n");

/* ------------------------------------------------------------------
 * ALGO_BLANK — absolute minimum, no parsing, no timing.
 * Baseline for XDP hook overhead alone.
 * ------------------------------------------------------------------ */
#if defined(ALGO_BLANK)
    return XDP_PASS;

/* ------------------------------------------------------------------
 * All other variants share the same parse preamble.
 * ------------------------------------------------------------------ */
#else
    __u64 t_start, t_end;
    t_start = bpf_ktime_get_ns();
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Layer 2 */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* Layer 3 */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

/* ------------------------------------------------------------------
 * ALGO_PARSE_ONLY — time the full program including parse above.
 * t_start is taken before parsing so the full program cost is captured.
 * ------------------------------------------------------------------ */
#if defined(ALGO_PARSE_ONLY)
    t_end = bpf_ktime_get_ns();
    record_latency(t_start, t_end);
    return XDP_PASS;

/* ------------------------------------------------------------------
 * ALGO_PACKET_RESIZE — AH header insertion, time resize only.
 * Inserts a 40-byte AH header between Ethernet and IP.
 * ICV field is zeroed — this is instrumentation, not real auth.
 * ------------------------------------------------------------------ */
#elif defined(ALGO_PACKET_RESIZE)
    __u8 orig_protocol = ip->protocol;
    //t_start = bpf_ktime_get_ns();

    /* Push ethernet header back by AH_HDR_LEN bytes to make room */
    if (bpf_xdp_adjust_head(ctx, -(int)AH_HDR_LEN))
        return XDP_PASS;

    t_end = bpf_ktime_get_ns();
    record_latency(t_start, t_end);
#if 1
    /* Re-establish pointers after head adjustment */
    data     = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    /* Rewrite Ethernet header at new position */
    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_PASS;

    /* Copy old eth header (now AH_HDR_LEN bytes forward) to new position */
    struct ethhdr *old_eth = (void *)(data + AH_HDR_LEN);
    if ((void *)(old_eth + 1) > data_end)
        return XDP_PASS;

    __builtin_memcpy(new_eth->h_dest,   old_eth->h_dest,   ETH_ALEN);
    __builtin_memcpy(new_eth->h_source, old_eth->h_source, ETH_ALEN);
    new_eth->h_proto = old_eth->h_proto;

    /* Write zeroed AH header in the gap between eth and IP.
     * AH format (RFC 4302):
     *   u8  next_header  (= original IP protocol)
     *   u8  payload_len  (= (AH_HDR_LEN/4) - 2 = 8)
     *   u16 reserved     (= 0)
     *   u32 spi          (= 0, placeholder)
     *   u32 seq          (= 0, placeholder)
     *   u8  icv[32]      (= 0, zeroed)
     */
    __u8 *ah = (void *)(new_eth + 1);
    if ((void *)(ah + AH_HDR_LEN) > data_end)
        return XDP_PASS;

    __builtin_memset(ah, 0, AH_HDR_LEN);
    ah[0] = orig_protocol; //ip->protocol;   /* next header = original IP protocol */
    ah[1] = 8;              /* payload len = (40/4) - 2 */

    /* Update IP header: new protocol = IPPROTO_AH (51) */
    struct iphdr *new_ip = (void *)(ah + AH_HDR_LEN);
    if ((void *)(new_ip + 1) > data_end)
        return XDP_PASS;
    new_ip->protocol = 51;  /* IPPROTO_AH */
#endif

    return XDP_PASS;

/* ------------------------------------------------------------------
 * Hash variants — extract IP header, call hash, time hash call only.
 * ------------------------------------------------------------------ */
#else
    __u8 ip_data[IP_HDR_LEN];
    if (bpf_xdp_load_bytes(ctx, sizeof(struct ethhdr),
                           ip_data, IP_HDR_LEN) < 0)
        return XDP_PASS;

    __u8 hash_out[HASH_OUT_LEN] = {};
    __u8 key[KEY_LEN];
    __builtin_memcpy(key, fixed_key, KEY_LEN);

    t_start = bpf_ktime_get_ns();

#if defined(ALGO_SHA256)
    bpf_sha256_keyed_hash(key, KEY_LEN, ip_data, IP_HDR_LEN, hash_out);

#elif defined(ALGO_SHA512)
    bpf_sha512_keyed_hash(key, KEY_LEN, ip_data, IP_HDR_LEN, hash_out);

#elif defined(ALGO_HMAC_SHA256)
    bpf_hmac_sha256(key, KEY_LEN, ip_data, IP_HDR_LEN, hash_out);

#elif defined(ALGO_HMAC_SHA512)
    bpf_hmac_sha512(key, KEY_LEN, ip_data, IP_HDR_LEN, hash_out);

#elif defined(ALGO_BLAKE3)
    //__u8 blake3_input[KEY_LEN + IP_HDR_LEN];
    //__builtin_memcpy(blake3_input,           key,     KEY_LEN);
    //__builtin_memcpy(blake3_input + KEY_LEN, ip_data, IP_HDR_LEN);
    //bpf_blake3_hash(key, blake3_input, KEY_LEN + IP_HDR_LEN, hash_out);
    bpf_blake3_keyed_hash(key, KEY_LEN, ip_data, IP_HDR_LEN, hash_out);

#elif defined(ALGO_CHACHA20)
    bpf_chacha20poly1305_hash(key, KEY_LEN, ip_data, IP_HDR_LEN, hash_out);

#elif defined(ALGO_KFUNC_SHA256)
    bpf_sha256_hash(key, KEY_LEN, ip_data, IP_HDR_LEN, hash_out);

#elif defined(ALGO_PURE_EBPF)
    compute_keyed_hash_from_map_dynamic(ip_data, IP_HDR_LEN,
                                        hash_out, key);
#endif

    t_end = bpf_ktime_get_ns();
    record_latency(t_start, t_end);

    /* Prevent dead-code elimination of hash computation */
    __asm__ __volatile__("" : : "r"(hash_out) : "memory");

    return XDP_PASS;

#endif /* hash variant inner #if */
#endif /* !ALGO_BLANK outer #if */
}

char _license[] SEC("license") = "GPL";
