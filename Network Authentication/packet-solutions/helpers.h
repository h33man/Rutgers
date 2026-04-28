#ifndef __HELPERS_H
#define __HELPERS_H
/*************************** HEADER FILES ***************************/
/****************************** COMMON STRUCTURES ******************************/

struct ip_auth_data {
    __u32 field_mask;
    __u8  key[64];
    __u8  action;
};

struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 data;
};

#define ACTION_DROP      0
#define ACTION_ALLOW     1
#define ACTION_MARK      2

#define STAT_TOTAL_PACKETS         0
#define STAT_AUTH_SUCCESS          1
#define STAT_AUTH_FAILURE          2
#define STAT_NO_AUTH_RULE          3
#define STAT_DROPPED_PACKETS       4
#define STAT_KEY_LOOKUP_SUCCESS    5
#define STAT_KEY_LOOKUP_FAILURE    6

/****************************** BPF MAP DEFINITIONS ******************************/

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct ip_auth_data);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 1000);
} src_ip_key_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct {
        __u8 hash_output[SHA256_BLOCK_SIZE];
    });
} kfunc_hash_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct {
        __u8 use_kfunc;
    });
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} config_map SEC(".maps");

/****************************** HELPER FUNCTIONS ******************************/
#if 0
// Method 1: Memory-intensive operations with map lookups
static __always_inline void artificial_latency_map_ops(struct __sk_buff *ctx)
{
    __u32 key = 0;
    struct {BYTE buffer[128];} *temp;

    // Multiple map lookups and memory operations
    #pragma unroll
    for (int i = 0; i < 50; i++) {
        temp = bpf_map_lookup_elem(&sha256_temp_map, &key);
        if (temp) {
            // Memory operations that can't be optimized away
            temp->buffer[0] = (temp->buffer[0] + i) & 0xFF;
            temp->buffer[1] = temp->buffer[0] ^ i;
            temp->buffer[2] = temp->buffer[1] + temp->buffer[0];

            // Dependency chain to prevent optimization
            temp->buffer[3] = temp->buffer[2] * 3;
            temp->buffer[4] = temp->buffer[3] >> 2;
            temp->buffer[5] = temp->buffer[4] | temp->buffer[0];
        }
    }
}

#else
// Method 2: Computational intensive operations
static __always_inline void artificial_latency_compute_ops(__u8 loop_count) //void)
{

    //__u64 start_time = bpf_ktime_get_ns();

    volatile __u64 result = 1;
    volatile __u64 multiplier = 1234567;

    //if (loop_count > 255) {
    //	bpf_printk("Artificial latency: Wrong loop count %d\n", loop_count);
    //	return;
    //`}

    //bpf_printk("Artificial latency: loop count %d\n", loop_count);
    //#pragma unroll
    //for (int i = 0; i < 1000; i++) {
    for (int i = 0; i < 10 * loop_count; i++) {
        // Operations that create dependencies and can't be easily optimized
        result = (result * multiplier) & 0xFFFFFFFF;
        result = result ^ (result >> 16);
        result = result + (result << 8);
        multiplier = (multiplier + result) & 0xFFFFFFFF;
    }

    //__u64 end_time = bpf_ktime_get_ns();
    //__u64 total_latency = end_time - start_time;

    //bpf_printk("Artificial latency: %llu ns\n", total_latency);
}
#endif

// Function to print a hex dump of binary data
void print_hex(const unsigned char *data, int len) {
    for (int i = 0; i < len; i++)
        bpf_printk("%02x", data[i++]);
    bpf_printk("\n");
}

static __always_inline uint16_t calculate_ip_checksum(const void *header, int len)
{
    const uint16_t *buf = header;
    uint32_t sum = 0;

    /* len is always sizeof(struct iphdr)=20 or sizeof(struct iphdr)+IP_OPT_HASH_LEN=56.
     * Both are compile-time constants at every call site since __always_inline
     * lets the compiler see the constant value and unroll accordingly. */
    for (int i = 0; i < len / 2; i++) {
        if (i >= 28) break;   /* verifier bound: max possible = 56/2 = 28 words */
        sum += buf[i];
    }

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (~sum) & 0xFFFF;
}
#if 1

/**
 * Lookup authentication key for source IP using LPM trie
 */
static __always_inline struct ip_auth_data* lookup_auth_key(__u32 src_ip) {
    struct ipv4_lpm_key src_key;
    struct ip_auth_data *auth_data;

#ifdef BPF_DEBUG
    __u64 start_time = bpf_ktime_get_ns();
#endif

    // Try exact match first (32-bit prefix)
    src_key.prefixlen = 32;
    src_key.data = src_ip;
    auth_data = bpf_map_lookup_elem(&src_ip_key_map, &src_key);

    if (auth_data) {
        goto out;
    }

    // Try /24 subnet match
    src_key.prefixlen = 24;
    src_key.data = src_ip & bpf_htonl(0xFFFFFF00);
    auth_data = bpf_map_lookup_elem(&src_ip_key_map, &src_key);

    if (auth_data) {
        goto out;
    }

    // Try /16 subnet match
    src_key.prefixlen = 16;
    src_key.data = src_ip & bpf_htonl(0xFFFF0000);
    auth_data = bpf_map_lookup_elem(&src_ip_key_map, &src_key);

    if (auth_data) {
        goto out;
    }

    // Try /8 subnet match
    src_key.prefixlen = 8;
    src_key.data = src_ip & bpf_htonl(0xFF000000);
    auth_data = bpf_map_lookup_elem(&src_ip_key_map, &src_key);

out:
#ifdef BPF_DEBUG
    if (auth_data)
        bpf_printk("Key lookup time: %llu ns\n", bpf_ktime_get_ns() - start_time);
#endif
    
    return auth_data;
}
#else

/*
 * OPTIMIZATION 4: lookup_auth_key - single LPM lookup.
 * OPTIMIZATION 5: Timing instrumentation behind debug flag only.
 */
static struct ip_auth_data *lookup_auth_key(__u32 src_ip)
{
    struct ipv4_lpm_key src_key;
    struct ip_auth_data *auth_data;

    src_key.prefixlen = 32;
    src_key.data      = src_ip;

    auth_data = bpf_map_lookup_elem(&src_ip_key_map, &src_key);

#ifdef BPF_DEBUG
    if (auth_data) {
        __u64 t0 = bpf_ktime_get_ns();
        __u64 t1 = bpf_ktime_get_ns();
        bpf_printk("Key lookup time: %llu ns\n", t1 - t0);
    }
#endif

    return auth_data;
}
#endif

#endif /*__HELPERS_H */
