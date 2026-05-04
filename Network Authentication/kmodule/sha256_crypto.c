/*
 * SHA256 crypto Kernel Module
 * Exposes SHA256 hash functions as eBPF kfuncs
 * Uses Kernel Crypto API
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>
#include <crypto/hash.h>

/* Only include BTF headers if kernel supports them properly */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0)
    #ifdef CONFIG_DEBUG_INFO_BTF
        #include <linux/btf.h>
        #include <linux/bpf.h>
        #if IS_ENABLED(CONFIG_DEBUG_INFO_BTF)
            #include <linux/btf_ids.h>
            #define KFUNC_SUPPORTED 1
        #endif
    #endif
#endif

#ifndef KFUNC_SUPPORTED
#warning "kfunc support not available, compiling as regular module"
#define KFUNC_SUPPORTED 0
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Research Module");
MODULE_DESCRIPTION("Crypto SHA256 kfunc for eBPF programs");
MODULE_VERSION("1.0");

/*************************** STATE ***************************/
static struct crypto_shash *sha256_tfm;
static DEFINE_PER_CPU(struct shash_desc *, sha256_desc);

/*************************** KFUNC PROTOTYPES ***************************/
#if KFUNC_SUPPORTED
__bpf_kfunc int bpf_sha256_keyed_hash(const __u8 *key, __u32 key_len,
                                      const __u8 *data, __u32 data_len,
                                      __u8 *hash);
#endif

/************************ KFUNC IMPLEMENTATION ************************/
#if KFUNC_SUPPORTED
__bpf_kfunc int bpf_sha256_keyed_hash(const __u8 *key, __u32 key_len,
                                      const __u8 *data, __u32 data_len,
                                      __u8 *hash)
{
    struct shash_desc *desc;
    int ret;
    u8 combined[84];  // 64 key + 20 data - fixed size, stack allocated

    if (!key || !data || !hash)
        return -EINVAL;
    if (key_len > 64 || data_len > 20)
        return -EINVAL;

    memcpy(combined, key, key_len);
    memcpy(combined + key_len, data, data_len);

    desc = get_cpu_var(sha256_desc);
    ret = crypto_shash_digest(desc, combined, key_len + data_len, hash);
    put_cpu_var(sha256_desc);
    return ret;
}

/* BTF registration */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 10, 0)
BTF_KFUNCS_START(sha256_kfunc_ids)
#else
BTF_SET8_START(sha256_kfunc_ids)
#endif

BTF_ID_FLAGS(func, bpf_sha256_keyed_hash, KF_TRUSTED_ARGS)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 10, 0)
BTF_KFUNCS_END(sha256_kfunc_ids)
#else
BTF_SET8_END(sha256_kfunc_ids)
#endif

static const struct btf_kfunc_id_set sha256_kfunc_set = {
    .owner = THIS_MODULE,
    .set   = &sha256_kfunc_ids,
};
#endif /* KFUNC_SUPPORTED */

/************************ MODULE INIT/EXIT ************************/
static int __init sha256_kfunc_init(void)
{
    int cpu, ret;

    printk(KERN_INFO "SHA256 module loading (kfunc support: %s)\n",
           KFUNC_SUPPORTED ? "yes" : "no");

    sha256_tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(sha256_tfm)) {
        pr_err("Failed to allocate sha256 shash: %ld\n", PTR_ERR(sha256_tfm));
        return PTR_ERR(sha256_tfm);
    }

    for_each_possible_cpu(cpu) {
        struct shash_desc *desc = kmalloc_node(
            sizeof(*desc) + crypto_shash_descsize(sha256_tfm),
            GFP_KERNEL, cpu_to_node(cpu));
        if (!desc) {
            pr_err("Failed to allocate shash_desc for CPU %d\n", cpu);
            for_each_possible_cpu(cpu) {
                kfree(per_cpu(sha256_desc, cpu));
                per_cpu(sha256_desc, cpu) = NULL;
            }
            crypto_free_shash(sha256_tfm);
            return -ENOMEM;
        }
        desc->tfm = sha256_tfm;
        per_cpu(sha256_desc, cpu) = desc;
    }

#if KFUNC_SUPPORTED
    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &sha256_kfunc_set);
    if (ret) {
        pr_err("Failed to register SHA256 kfuncs for XDP: %d\n", ret);
        return ret;
    }
    printk(KERN_INFO "XDP kfunc registration result: %d\n", ret);

    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &sha256_kfunc_set);
    if (ret)
        pr_err("Failed to register SHA256 kfuncs for SYSCALL: %d\n", ret);
    printk(KERN_INFO "SYSCALL kfunc registration result: %d\n", ret);

    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS, &sha256_kfunc_set);
    if (ret)
        pr_err("Failed to register SHA256 kfuncs for TC: %d\n", ret);
    printk(KERN_INFO "TC kfunc registration result: %d\n", ret);

    printk(KERN_INFO "SHA256 kfuncs registered successfully\n");
#else
    printk(KERN_INFO "SHA256 module loaded (kfunc registration skipped - no BTF support)\n");
#endif

    return 0;
}

static void __exit sha256_kfunc_exit(void)
{
    int cpu;
    for_each_possible_cpu(cpu) {
        kfree(per_cpu(sha256_desc, cpu));
        per_cpu(sha256_desc, cpu) = NULL;
    }
    crypto_free_shash(sha256_tfm);
    pr_info("SHA256 kfunc module unloading\n");
}

module_init(sha256_kfunc_init);
module_exit(sha256_kfunc_exit);
