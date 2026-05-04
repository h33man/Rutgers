/*
 * SHA256 kfunc Kernel Module
 * Exposes SHA256 hash functions as eBPF kfuncs
 * Based on Brad Conte's SHA256 implementation
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>

/* Only include BTF headers if kernel supports them properly */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0)
    /* Try to include BTF support with fallback */
    #ifdef CONFIG_DEBUG_INFO_BTF
        #include <linux/btf.h>
        #include <linux/bpf.h>
        
        /* Check if btf_ids.h is available */
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
MODULE_DESCRIPTION("Custom SHA256 kfunc for eBPF programs");
MODULE_VERSION("1.0");

/*************************** TYPES ***************************/
typedef unsigned char u8;

#define BPF_SHA256_BLOCK_SIZE 32

struct bpf_sha256_ctx {
    u8 data[64];
    u32 datalen;
    unsigned long long bitlen;
    u32 state[8];
};

/****************************** MACROS ******************************/
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

/**************************** VARIABLES *****************************/
static const u32 k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/*********************** FUNCTION PROTOTYPES ***********************/
// Internal SHA256 functions
static void sha256_transform(struct bpf_sha256_ctx *ctx, const u8 data[]);
static void bpf_sha256_init(struct bpf_sha256_ctx *ctx);
static int bpf_sha256_update(struct bpf_sha256_ctx *ctx, const u8 data[], size_t len);
static int bpf_sha256_final(struct bpf_sha256_ctx *ctx, u8 hash[]);

#if KFUNC_SUPPORTED
// kfunc prototypes (to suppress -Wmissing-prototypes warnings)
__bpf_kfunc struct bpf_sha256_ctx *bpf_sha256_ctx_create(void);
__bpf_kfunc void bpf_sha256_ctx_release(struct bpf_sha256_ctx *ctx);
__bpf_kfunc int bpf_bpf_sha256_update(struct bpf_sha256_ctx *ctx, const __u8 *data, __u32 len);
__bpf_kfunc int bpf_bpf_sha256_final(struct bpf_sha256_ctx *ctx, __u8 *hash);
__bpf_kfunc int bpf_sha256_oneshot(const __u8 *data, __u32 len, __u8 *hash);
__bpf_kfunc int bpf_sha256_keyed_hash(const __u8 *key, __u32 key_len,
                                      const __u8 *data, __u32 data_len, 
                                      __u8 *hash);
#endif

/*********************** CORE SHA256 IMPLEMENTATION ***********************/
static void sha256_transform(struct bpf_sha256_ctx *ctx, const u8 data[])
{
    u32 a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    for ( ; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void bpf_sha256_init(struct bpf_sha256_ctx *ctx)
{
    ctx->datalen = 0; ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

static int bpf_sha256_update(struct bpf_sha256_ctx *ctx, const u8 data[], size_t len)
{
    u32 i;
    for (i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        if (++ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
    return 0;
}

static int bpf_sha256_final(struct bpf_sha256_ctx *ctx, u8 hash[])
{
    u32 i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;      ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16; ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32; ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48; ctx->data[56] = ctx->bitlen >> 56;
    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i) {
        hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
    }
    return 0;
}

/************************ KFUNC IMPLEMENTATIONS (if supported) ************************/

#if KFUNC_SUPPORTED

__bpf_kfunc struct bpf_sha256_ctx *bpf_sha256_ctx_create(void)
{
    struct bpf_sha256_ctx *ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
    if (ctx) bpf_sha256_init(ctx);
    return ctx;
}

__bpf_kfunc void bpf_sha256_ctx_release(struct bpf_sha256_ctx *ctx)
{
    if (ctx) kfree(ctx);
}

__bpf_kfunc int bpf_bpf_sha256_update(struct bpf_sha256_ctx *ctx, const __u8 *data, __u32 len)
{
    return (!ctx || !data) ? -EINVAL : bpf_sha256_update(ctx, data, len);
}

__bpf_kfunc int bpf_bpf_sha256_final(struct bpf_sha256_ctx *ctx, __u8 *hash)
{
    return (!ctx || !hash) ? -EINVAL : bpf_sha256_final(ctx, hash);
}

__bpf_kfunc int bpf_sha256_oneshot(const __u8 *data, __u32 len, __u8 *hash)
{
    struct bpf_sha256_ctx ctx;
    if (!data || !hash) return -EINVAL;
    bpf_sha256_init(&ctx);
    bpf_sha256_update(&ctx, data, len);
    return bpf_sha256_final(&ctx, hash);
}

__bpf_kfunc int bpf_sha256_keyed_hash(const __u8 *key, __u32 key_len,
                                      const __u8 *data, __u32 data_len, __u8 *hash)
{
    struct bpf_sha256_ctx ctx;
    int ret;
    
    if (!key || !data || !hash)
        return -EINVAL;
    
    bpf_sha256_init(&ctx);
    
    // Hash key first, then data (simple keyed hash, not full HMAC)
    ret = bpf_sha256_update(&ctx, key, key_len);
    if (ret)
        return ret;
        
    ret = bpf_sha256_update(&ctx, data, data_len);
    if (ret)
        return ret;
        
    return bpf_sha256_final(&ctx, hash);
}

/* BTF registration */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 10, 0)
BTF_KFUNCS_START(sha256_kfunc_ids)
#else
BTF_SET8_START(sha256_kfunc_ids)
#endif
BTF_ID_FLAGS(func, bpf_sha256_ctx_create, KF_ACQUIRE | KF_RET_NULL | KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_sha256_ctx_release, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_bpf_sha256_update, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_bpf_sha256_final, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_sha256_oneshot, KF_TRUSTED_ARGS)
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
    int ret;
    
    printk(KERN_INFO "SHA256 module loading (kfunc support: %s)\n", 
           KFUNC_SUPPORTED ? "yes" : "no");

#if KFUNC_SUPPORTED
    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &sha256_kfunc_set);
    if (ret) {
        printk(KERN_ERR "Failed to register SHA256 kfuncs for XDP: %d\n", ret);
        return ret;
    }
    printk(KERN_INFO "XDP kfunc registration result: %d\n", ret);
    
    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &sha256_kfunc_set);
    if (ret) {
        printk(KERN_ERR "Failed to register SHA256 kfuncs for SYSCALL: %d\n", ret);
        // Don't fail module load if only one registration fails
    }
    printk(KERN_INFO "SYSCALL kfunc registration result: %d\n", ret);
    
    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS, &sha256_kfunc_set);
    if (ret) {
        printk(KERN_ERR "Failed to register SHA256 kfuncs for TC: %d\n", ret);
        // Don't fail module load if only one registration fails
    }
    printk(KERN_INFO "TC kfunc registration result: %d\n", ret);
    
    printk(KERN_INFO "SHA256 kfuncs registered successfully\n");
#else
    printk(KERN_INFO "SHA256 module loaded (kfunc registration skipped - no BTF support)\n");
#endif

    return 0;
}

static void __exit sha256_kfunc_exit(void)
{
    printk(KERN_INFO "SHA256 kfunc module unloading\n");
}

module_init(sha256_kfunc_init);
module_exit(sha256_kfunc_exit);
