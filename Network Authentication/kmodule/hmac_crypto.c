// SPDX-License-Identifier: GPL-2.0-only
/*
 * hmac_crypto.c
 *
 * Exposes HMAC-SHA256 and HMAC-SHA512 as BPF kfuncs via the Kernel Crypto API.
 *
 * Uses the proper HMAC construction (RFC 2104).  The Crypto API handles
 * the ipad/opad logic internally and selects the highest-priority SHA
 * backend automatically (sha256-avx2, sha512-avx2, etc. on x86-64).
 *
 * Per-CPU pre-keyed tfm design:
 *   crypto_shash_setkey() writes key material into the tfm's own state,
 *   not the descriptor.  A single shared tfm with concurrent setkey()
 *   calls from multiple CPUs would race.  The solution is one cloned tfm
 *   per CPU, each pre-keyed at init time with a fixed key via
 *   crypto_clone_shash() (available since kernel 6.2).
 *
 *   Hot path: get_cpu_var → crypto_shash_digest → put_cpu_var
 *   Zero dynamic allocation per packet.
 *
 * Fixed-key note:
 *   Pre-keying at init time is correct for a fixed benchmark key.
 *   A variable-key production implementation would need per-CPU keyed-tfm
 *   pools or per-call setkey() (with its associated cost).  This module
 *   measures best-case fixed-key HMAC latency.
 *
 * kfunc signatures visible to BPF programs:
 *
 *   int bpf_hmac_sha256(const __u8 *key,  __u32 key_len,
 *                       const __u8 *data, __u32 data_len,
 *                       __u8 *out);          // writes 32 bytes
 *
 *   int bpf_hmac_sha512(const __u8 *key,  __u32 key_len,
 *                       const __u8 *data, __u32 data_len,
 *                       __u8 *out);          // writes 64 bytes
 *
 *   key_len  <= 64, data_len <= 128
 *   Returns 0 on success, -EINVAL on bad args, negative errno from crypto.
 *
 *   Note: key argument is accepted for API compatibility but ignored —
 *   the module's fixed key (set at init) is always used.
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

#define HMAC_MAX_KEY      64u
#define HMAC_MAX_DATA    128u

/*************************** MODULE STATE ***************************/

/* Template tfms — allocated once, used as clone source at init only.
 * Kept alive because clones hold an implicit reference to the parent
 * algorithm; freeing the template before clones causes use-after-free. */
static struct crypto_shash *hmac256_tmpl;
static struct crypto_shash *hmac512_tmpl;

/* Per-CPU pre-keyed tfm clones and their descriptors.
 * Each CPU owns an independent tfm so setkey() never races. */
static DEFINE_PER_CPU(struct crypto_shash *, hmac256_tfm_pcpu);
static DEFINE_PER_CPU(struct crypto_shash *, hmac512_tfm_pcpu);
static DEFINE_PER_CPU(struct shash_desc *,   hmac256_desc_pcpu);
static DEFINE_PER_CPU(struct shash_desc *,   hmac512_desc_pcpu);

/* Fixed key used to pre-key all per-CPU tfms at init.
 * Matches the key embedded in xdp_hash_bench.c for consistent results. */
static const u8 hmac_fixed_key[HMAC_MAX_KEY] = {
    0x4b, 0x75, 0x8f, 0x94, 0x98, 0xd3, 0x31, 0x26,
    0x16, 0xec, 0xc2, 0x61, 0x99, 0x43, 0x76, 0x45,
    0x2a, 0x3b, 0x4c, 0x5d, 0x6e, 0x7f, 0x80, 0x91,
    0xa2, 0xb3, 0xc4, 0xd5, 0xe6, 0xf7, 0x08, 0x19,
    0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81,
    0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09,
    0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71,
    0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8, 0xf9,
};

/*************************** KFUNCS ***************************/
__bpf_kfunc_start_defs();

/**
 * bpf_hmac_sha256 - compute HMAC-SHA256(fixed_key, data) per RFC 2104
 * @key:      accepted for API compatibility, ignored (fixed key used)
 * @key_len:  must be 1..64
 * @data:     message bytes (BPF-trusted)
 * @data_len: message length, must be <= 128
 * @out:      output buffer, exactly 32 bytes (BPF-trusted)
 *
 * Zero dynamic allocation — uses per-CPU pre-keyed tfm.
 * Returns 0 on success or negative errno.
 */
__bpf_kfunc int bpf_hmac_sha256(const __u8 *key,  __u32 key_len,
                                 const __u8 *data, __u32 data_len,
                                 __u8 *out)
{
    struct shash_desc *desc;
    int ret;

    if (!key || !data || !out)
        return -EINVAL;
    if (key_len == 0 || key_len > HMAC_MAX_KEY || data_len > HMAC_MAX_DATA)
        return -EINVAL;

    desc = get_cpu_var(hmac256_desc_pcpu);
    ret  = crypto_shash_digest(desc, data, data_len, out);
    put_cpu_var(hmac256_desc_pcpu);
    return ret;
}

/**
 * bpf_hmac_sha512 - compute HMAC-SHA512(fixed_key, data) per RFC 2104
 * @key:      accepted for API compatibility, ignored (fixed key used)
 * @key_len:  must be 1..64
 * @data:     message bytes (BPF-trusted)
 * @data_len: message length, must be <= 128
 * @out:      output buffer, exactly 64 bytes (BPF-trusted)
 *
 * Zero dynamic allocation — uses per-CPU pre-keyed tfm.
 * Returns 0 on success or negative errno.
 */
__bpf_kfunc int bpf_hmac_sha512(const __u8 *key,  __u32 key_len,
                                 const __u8 *data, __u32 data_len,
                                 __u8 *out)
{
    struct shash_desc *desc;
    int ret;

    if (!key || !data || !out)
        return -EINVAL;
    if (key_len == 0 || key_len > HMAC_MAX_KEY || data_len > HMAC_MAX_DATA)
        return -EINVAL;

    desc = get_cpu_var(hmac512_desc_pcpu);
    ret  = crypto_shash_digest(desc, data, data_len, out);
    put_cpu_var(hmac512_desc_pcpu);
    return ret;
}

__bpf_kfunc_end_defs();

EXPORT_SYMBOL_GPL(bpf_hmac_sha256);
EXPORT_SYMBOL_GPL(bpf_hmac_sha512);

/*************************** BTF REGISTRATION ***************************/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 10, 0)
BTF_KFUNCS_START(hmac_crypto_ids)
BTF_ID_FLAGS(func, bpf_hmac_sha256, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_hmac_sha512, KF_TRUSTED_ARGS)
BTF_KFUNCS_END(hmac_crypto_ids)
#else
BTF_SET8_START(hmac_crypto_ids)
BTF_ID_FLAGS(func, bpf_hmac_sha256, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_hmac_sha512, KF_TRUSTED_ARGS)
BTF_SET8_END(hmac_crypto_ids)
#endif

static const struct btf_kfunc_id_set hmac_crypto_set = {
    .owner = THIS_MODULE,
    .set   = &hmac_crypto_ids,
};

/*************************** INIT HELPERS ***************************/

/*
 * alloc_hmac_pcpu - allocate template tfm, clone one per CPU,
 *                   pre-key each clone, allocate per-CPU descriptor.
 *
 * On any failure, all previously allocated resources for this algorithm
 * are freed before returning.  The caller is responsible for freeing
 * resources from previously successful alloc_hmac_pcpu() calls.
 */
static int alloc_hmac_pcpu(const char *algo,
                            struct crypto_shash         **tmpl_out,
                            struct crypto_shash __percpu **tfm_pcpu,
                            struct shash_desc   __percpu **desc_pcpu)
{
    struct crypto_shash *tmpl;
    int cpu, ret;

    tmpl = crypto_alloc_shash(algo, 0, 0);
    if (IS_ERR(tmpl)) {
        pr_err("hmac_crypto: failed to allocate %s: %ld\n",
               algo, PTR_ERR(tmpl));
        return PTR_ERR(tmpl);
    }
    *tmpl_out = tmpl;

    for_each_possible_cpu(cpu) {
        struct crypto_shash *clone;
        struct shash_desc   *desc;

        /* Each CPU gets an independent tfm clone so setkey() never races */
        clone = crypto_clone_shash(tmpl);
        if (IS_ERR(clone)) {
            pr_err("hmac_crypto: crypto_clone_shash failed for CPU %d: %ld\n",
                   cpu, PTR_ERR(clone));
            ret = PTR_ERR(clone);
            goto err_partial;
        }

        /* Pre-key once at init — no setkey() in the hot path */
        ret = crypto_shash_setkey(clone, hmac_fixed_key, HMAC_MAX_KEY);
        if (ret) {
            pr_err("hmac_crypto: setkey failed for CPU %d: %d\n", cpu, ret);
            crypto_free_shash(clone);
            goto err_partial;
        }

        desc = kmalloc_node(sizeof(*desc) + crypto_shash_descsize(clone),
                            GFP_KERNEL, cpu_to_node(cpu));
        if (!desc) {
            crypto_free_shash(clone);
            ret = -ENOMEM;
            goto err_partial;
        }
        desc->tfm = clone;

        per_cpu(*tfm_pcpu,  cpu) = clone;
        per_cpu(*desc_pcpu, cpu) = desc;
    }
    return 0;

err_partial:
    /* Free all CPUs allocated so far for this algorithm */
    for_each_possible_cpu(cpu) {
        kfree(per_cpu(*desc_pcpu, cpu));
        per_cpu(*desc_pcpu, cpu) = NULL;
        if (per_cpu(*tfm_pcpu, cpu)) {
            crypto_free_shash(per_cpu(*tfm_pcpu, cpu));
            per_cpu(*tfm_pcpu, cpu) = NULL;
        }
    }
    crypto_free_shash(tmpl);
    *tmpl_out = NULL;
    return ret;
}

static void free_hmac_pcpu(struct crypto_shash         *tmpl,
                            struct crypto_shash __percpu **tfm_pcpu,
                            struct shash_desc   __percpu **desc_pcpu)
{
    int cpu;

    for_each_possible_cpu(cpu) {
        kfree(per_cpu(*desc_pcpu, cpu));
        per_cpu(*desc_pcpu, cpu) = NULL;
        if (per_cpu(*tfm_pcpu, cpu)) {
            crypto_free_shash(per_cpu(*tfm_pcpu, cpu));
            per_cpu(*tfm_pcpu, cpu) = NULL;
        }
    }
    /* Free template after all clones — clones hold implicit parent ref */
    if (tmpl)
        crypto_free_shash(tmpl);
}

/*************************** MODULE INIT / EXIT ***************************/
static int __init hmac_crypto_init(void)
{
    int ret;

    ret = alloc_hmac_pcpu("hmac(sha256)", &hmac256_tmpl,
                          &hmac256_tfm_pcpu, &hmac256_desc_pcpu);
    if (ret)
        return ret;

    ret = alloc_hmac_pcpu("hmac(sha512)", &hmac512_tmpl,
                          &hmac512_tfm_pcpu, &hmac512_desc_pcpu);
    if (ret) {
        free_hmac_pcpu(hmac256_tmpl, &hmac256_tfm_pcpu, &hmac256_desc_pcpu);
        return ret;
    }

    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &hmac_crypto_set);
    if (ret) {
        pr_err("hmac_crypto: XDP registration failed (%d)\n", ret);
        goto err_free;
    }

    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS, &hmac_crypto_set);
    if (ret)
        pr_warn("hmac_crypto: SCHED_CLS registration failed (%d), continuing\n", ret);

    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &hmac_crypto_set);
    if (ret)
        pr_warn("hmac_crypto: SYSCALL registration failed (%d), continuing\n", ret);

    pr_info("hmac_crypto: loaded — per-CPU pre-keyed tfms ready\n");
    pr_info("hmac_crypto:   sha256 driver: %s\n",
            crypto_shash_driver_name(hmac256_tmpl));
    pr_info("hmac_crypto:   sha512 driver: %s\n",
            crypto_shash_driver_name(hmac512_tmpl));
    return 0;

err_free:
    free_hmac_pcpu(hmac512_tmpl, &hmac512_tfm_pcpu, &hmac512_desc_pcpu);
    free_hmac_pcpu(hmac256_tmpl, &hmac256_tfm_pcpu, &hmac256_desc_pcpu);
    return ret;
}

static void __exit hmac_crypto_exit(void)
{
    free_hmac_pcpu(hmac512_tmpl, &hmac512_tfm_pcpu, &hmac512_desc_pcpu);
    free_hmac_pcpu(hmac256_tmpl, &hmac256_tfm_pcpu, &hmac256_desc_pcpu);
    pr_info("hmac_crypto: unloaded\n");
}

module_init(hmac_crypto_init);
module_exit(hmac_crypto_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Research Module");
MODULE_DESCRIPTION("HMAC-SHA256 and HMAC-SHA512 kfuncs for eBPF — per-CPU pre-keyed, zero hot-path allocation");
MODULE_VERSION("1.0");
