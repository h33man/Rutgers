#ifndef __HELPERS_H
#define __HELPERS_H
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
    __u64 start_time = bpf_ktime_get_ns();

    volatile __u64 result = 1;
    volatile __u64 multiplier = 1234567;

    //if (loop_count > 255) {
    //	bpf_printk("Artificial latency: Wrong loop count %d\n", loop_count);
    //	return;
    //`}

    //bpf_printk("Artificial latency: loop count %d\n", loop_count);
    //#pragma unroll
    for (int i = 0; i < 10 * loop_count; i++) {
        // Operations that create dependencies and can't be easily optimized
        result = (result * multiplier) & 0xFFFFFFFF;
        result = result ^ (result >> 16);
        result = result + (result << 8);
        multiplier = (multiplier + result) & 0xFFFFFFFF;
    }

    __u64 end_time = bpf_ktime_get_ns();
    __u64 total_latency = end_time - start_time;

    bpf_printk("Artificial latency: %llu ns\n", total_latency);
}
#endif
#endif /*__HELPERS_H */
