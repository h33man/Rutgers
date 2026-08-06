#ifndef SHA256_KFUNC_H
#define SHA256_KFUNC_H

#include <linux/types.h>

#define SHA256_BLOCK_SIZE 32

struct bpf_sha256_ctx {
    __u8 data[64];
    __u32 datalen;
    __u64 bitlen;
    __u32 state[8];
};

/* kfunc declarations for eBPF programs */
extern struct bpf_sha256_ctx *bpf_sha256_ctx_create(void) __ksym;
extern void bpf_sha256_ctx_release(struct bpf_sha256_ctx *ctx) __ksym;
extern int bpf_sha256_update(struct bpf_sha256_ctx *ctx, const __u8 *data, __u32 len) __ksym;
extern int bpf_sha256_final(struct bpf_sha256_ctx *ctx, __u8 *hash) __ksym;
extern int bpf_sha256_oneshot(const __u8 *data, __u32 len, __u8 *hash) __ksym;
extern int bpf_sha256_hash(const __u8 *key, __u32 key_len,
                                const __u8 *data, __u32 data_len, 
                                __u8 *hash) __ksym;

#endif /* SHA256_KFUNC_H */
