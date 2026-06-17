// SPDX-License-Identifier: GPL-2.0-only
/*
 * sha512_crypto.c
 *
 * Exposes SHA-512 keyed hash as a BPF kfunc via the Kernel Crypto API.
 *
 * The Crypto API selects the highest-priority registered backend at
 * crypto_alloc_shash() time.  On x86-64 this will be sha512-avx2 or
 * sha512-avx (SIMD-accelerated), on aarch64 sha512-ce (ARMv8.2 CE), etc.
 * No explicit SIMD management is required here.
 *
 * Per-CPU shash_desc descriptors are pre-allocated in module init so the
 * hot path performs zero dynamic allocation.
 *
 * kfunc signature visible to BPF programs:
 *
 *   int bpf_sha512_keyed_hash(const __u8 *key,  __u32 key_len,
 *                             const __u8 *data, __u32 data_len,
 *                             __u8 *hash);
 *
 *   Concatenates key||data, computes SHA-512, writes 64 bytes to hash[].
 *   key_len  <= 128, data_len <= 128 (generous but still stack-safe).
 *   Returns 0 on success, -EINVAL on bad args, negative errno from crypto.
 *
 * NOTE: SHA-512 produces a 64-byte digest.  Ensure your BPF map value
 * or output buffer is at least 64 bytes, not 32.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <crypto/hash.h>

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

/* SHA-512 produces 64-byte digests */
#define SHA512_DIGEST_SIZE  64u
#define SHA512_MAX_KEY     128u
#define SHA512_MAX_DATA    128u
#define SHA512_MAX_COMBINED (SHA512_MAX_KEY + SHA512_MAX_DATA)  /* 256 */

/*************************** MODULE STATE ***************************/
static struct crypto_shash *sha512_tfm;
static DEFINE_PER_CPU(struct shash_desc *, sha512_desc);

/*************************** KFUNC ***************************/
__bpf_kfunc_start_defs();

/**
 * bpf_sha512_keyed_hash - compute SHA-512(key || data)
 * @key:      pointer to key bytes (BPF-trusted)
 * @key_len:  length of key, must be <= 128
 * @data:     pointer to data bytes (BPF-trusted)
 * @data_len: length of data, must be <= 128
 * @hash:     output buffer, must be exactly 64 bytes (BPF-trusted)
 *
 * This is a keyed hash by concatenation, NOT HMAC.  Use the HMAC module
 * (hmac_kfunc.ko) for a proper PRF.
 */
__bpf_kfunc int bpf_sha512_keyed_hash(const __u8 *key,  __u32 key_len,
                                       const __u8 *data, __u32 data_len,
                                       __u8 *hash)
{
    struct shash_desc *desc;
    u8 combined[SHA512_MAX_COMBINED];
    int ret;

    if (!key || !data || !hash)
        return -EINVAL;
    if (key_len > SHA512_MAX_KEY || data_len > SHA512_MAX_DATA)
        return -EINVAL;

    memcpy(combined, key, key_len);
    memcpy(combined + key_len, data, data_len);

    desc = get_cpu_var(sha512_desc);
    ret = crypto_shash_digest(desc, combined, key_len + data_len, hash);
    put_cpu_var(sha512_desc);

    return ret;
}

__bpf_kfunc_end_defs();

EXPORT_SYMBOL_GPL(bpf_sha512_keyed_hash);

/*************************** BTF REGISTRATION ***************************/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 10, 0)
BTF_KFUNCS_START(sha512_crypto_ids)
BTF_ID_FLAGS(func, bpf_sha512_keyed_hash, KF_TRUSTED_ARGS)
BTF_KFUNCS_END(sha512_crypto_ids)
#else
BTF_SET8_START(sha512_crypto_ids)
BTF_ID_FLAGS(func, bpf_sha512_keyed_hash, KF_TRUSTED_ARGS)
BTF_SET8_END(sha512_crypto_ids)
#endif

static const struct btf_kfunc_id_set sha512_crypto_set = {
    .owner = THIS_MODULE,
    .set   = &sha512_crypto_ids,
};

/*************************** MODULE INIT / EXIT ***************************/
static int __init sha512_crypto_init(void)
{
    int cpu, ret;

    sha512_tfm = crypto_alloc_shash("sha512", 0, 0);
    if (IS_ERR(sha512_tfm)) {
        pr_err("sha512_crypto: failed to allocate shash transform: %ld\n",
               PTR_ERR(sha512_tfm));
        return PTR_ERR(sha512_tfm);
    }

    for_each_possible_cpu(cpu) {
        struct shash_desc *desc = kmalloc_node(
            sizeof(*desc) + crypto_shash_descsize(sha512_tfm),
            GFP_KERNEL, cpu_to_node(cpu));
        if (!desc) {
            pr_err("sha512_crypto: failed to allocate shash_desc for CPU %d\n", cpu);
            for_each_possible_cpu(cpu) {
                kfree(per_cpu(sha512_desc, cpu));
                per_cpu(sha512_desc, cpu) = NULL;
            }
            crypto_free_shash(sha512_tfm);
            return -ENOMEM;
        }
        desc->tfm = sha512_tfm;
        per_cpu(sha512_desc, cpu) = desc;
    }

    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &sha512_crypto_set);
    if (ret) {
        pr_err("sha512_crypto: XDP registration failed (%d)\n", ret);
        goto err_free;
    }

    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS, &sha512_crypto_set);
    if (ret)
        pr_warn("sha512_crypto: SCHED_CLS registration failed (%d), continuing\n", ret);

    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &sha512_crypto_set);
    if (ret)
        pr_warn("sha512_crypto: SYSCALL registration failed (%d), continuing\n", ret);

    pr_info("sha512_crypto: loaded — bpf_sha512_keyed_hash() ready (driver: %s)\n",
            crypto_shash_driver_name(sha512_tfm));
    return 0;

err_free:
    for_each_possible_cpu(cpu) {
        kfree(per_cpu(sha512_desc, cpu));
        per_cpu(sha512_desc, cpu) = NULL;
    }
    crypto_free_shash(sha512_tfm);
    return ret;
}

static void __exit sha512_crypto_exit(void)
{
    int cpu;

    for_each_possible_cpu(cpu) {
        kfree(per_cpu(sha512_desc, cpu));
        per_cpu(sha512_desc, cpu) = NULL;
    }
    crypto_free_shash(sha512_tfm);
    pr_info("sha512_crypto: unloaded\n");
}

module_init(sha512_crypto_init);
module_exit(sha512_crypto_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Research Module");
MODULE_DESCRIPTION("SHA-512 keyed hash kfunc for eBPF (Crypto API, SIMD-accelerated)");
MODULE_VERSION("1.0");
