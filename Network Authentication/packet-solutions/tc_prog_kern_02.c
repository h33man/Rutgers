/*********************************************************************
* Filename:   tc_prog_kern_02.c
* Author:     Converted from XDP to TC with kfunc support
* Description: TC version of IP hash program with SHA-256 functionality
*              Supports runtime selection between custom and kfunc SHA256
*********************************************************************/

/*************************** HEADER FILES ***************************/
#include "sha256.h"
#include "sha256_kfunc.h"
<<<<<<< HEAD
#include "chacha20.h"
=======
#include "chacha20_kfunc.h"
>>>>>>> 03ddeb4 (Adde Chacha20 kernel module)

extern __u8 debug;

/* Defines tc_stats_map instead of xdp_stats_map */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, struct datarec);
} tc_stats_map SEC(".maps");

/****************************** BPF MAPS ******************************/


/****************************** HELPER FUNCTIONS ******************************/

// TC stats recording function
static __always_inline __u32 tc_stats_record_action(struct __sk_buff *ctx, __u32 action)
{
    if (action >= 5)
        return action;

    __u32 key = action;
    struct datarec *rec = bpf_map_lookup_elem(&tc_stats_map, &key);
    if (!rec)
        return action;

    rec->rx_packets++;
    rec->rx_bytes += (ctx->data_end - ctx->data);

    return action;
}

/****************************** IP OPTION MANIPULATION ******************************/

static __always_inline int add_ip_option_hash_tc(struct __sk_buff *skb,
        struct iphdr *ip_orig, BYTE hash[SHA256_BLOCK_SIZE])
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    uint8_t option_len = IP_OPT_HASH_LEN;
    int i;

    // Save original headers before bpf_skb_change_head invalidates pointers
    struct ethhdr *orig_eth = (struct ethhdr *)data;
    if ((void *)(orig_eth + 1) > data_end)
        return -1;

    struct iphdr *orig_ip = (struct iphdr *)(data + ETHERNET_HEADER_SIZE);
    if ((void *)(orig_ip + 1) > data_end)
        return -1;

    struct ethhdr saved_eth = *orig_eth;
    struct iphdr saved_ip = *orig_ip;

    // Use bpf_skb_change_head to add space
    if (bpf_skb_change_head(skb, IP_OPT_HASH_LEN, 0))
        return -1;

    // After change_head, all previous pointers are invalidated
    data_end = (void *)(long)skb->data_end;
    data = (void *)(long)skb->data;

    // Restore Ethernet header
    struct ethhdr *new_eth = (struct ethhdr *)data;
    if ((void *)(new_eth + 1) > data_end)
        return -1;
    *new_eth = saved_eth;

    // Restore and update IP header
    struct iphdr *new_ip = (struct iphdr *)(data + ETHERNET_HEADER_SIZE);
    if ((void *)(new_ip + 1) > data_end)
        return -1;
    *new_ip = saved_ip;

    new_ip->ihl = (sizeof(struct iphdr) + IP_OPT_HASH_LEN) / 4;
    new_ip->tot_len = bpf_htons(bpf_ntohs(new_ip->tot_len) + IP_OPT_HASH_LEN);
    new_ip->check = 0;

    // Add option after IP header
    uint8_t *options = (uint8_t *)(new_ip + 1);
    if ((void *)(options + option_len) > data_end)
        return -1;

    options[0] = IP_OPT_HASH_ID;
    options[1] = option_len;
    options[2] = 0x12;
    options[3] = 0x34;

    // Copy hash value
    #pragma unroll
    for (i = 0; i < 32; i += 4) {
        if (i + 3 < 32 && 4 + i + 3 < option_len) {
            options[4 + i] = hash[i];
            options[4 + i + 1] = hash[i + 1];
            options[4 + i + 2] = hash[i + 2];
            options[4 + i + 3] = hash[i + 3];
        }
    }

    // Calculate checksum
    int header_len = new_ip->ihl * 4;
    new_ip->check = calculate_ip_checksum((const void *)new_ip, header_len);

    if(debug)
        bpf_printk("TC: Hash added, checksum: 0x%04x\n", new_ip->check);

    return 0;
}

/****************************** TC PROGRAMS ******************************/
/**
 * TC program for adding hash to packets with runtime selection
 */
SEC("tc_ip_hash")
int tc_ip_hash_func(struct __sk_buff *ctx)
{
    int action = TC_ACT_OK;
    int eth_type, ip_type;
    struct ethhdr *eth;
    struct iphdr *iphdr;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct hdr_cursor nh = { .pos = data };
    BYTE hash_result[SHA256_BLOCK_SIZE];
    __u64 start_time;

    // TIMING: Calculate total latency for eBPF program
    if (debug)
        start_time = bpf_ktime_get_ns();

    __u32 key = 0;
    struct {
        __u8 use_kfunc;  // Runtime flag: 0 = custom SHA256, 1 = kfunc SHA256
    } *config_ctx;

    config_ctx = bpf_map_lookup_elem(&config_map, &key);
    if (!config_ctx)
        return -1;

    __builtin_memset(hash_result, 0, SHA256_BLOCK_SIZE);

    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type < 0) {
        action = TC_ACT_SHOT;
        goto out;
    }

    if (eth_type == bpf_htons(ETH_P_IP)) {
        ip_type = parse_iphdr(&nh, data_end, &iphdr);
        if (ip_type < 0) {
            action = TC_ACT_SHOT;
            goto out;
        }

        // Only processing UDP
        if (iphdr->protocol != IPPROTO_UDP) {
            bpf_printk("Not a UDP packet, passing through\n");
            action = TC_ACT_OK;
            goto out;
        }

        if ((void *)(iphdr + 1) > data_end) {
            action = TC_ACT_SHOT;
            goto out;
        }

        int header_size = iphdr->ihl * 4;
        if ((void *)iphdr + header_size > data_end) {
            action = TC_ACT_SHOT;
            goto out;
        }

        struct ip_auth_data *auth_data = lookup_auth_key(iphdr->saddr);
        if (!auth_data) {
            bpf_printk("No authentication key found for source IP, passing without hash\n");
            action = TC_ACT_OK;
            goto out;
        }

        if (debug)
            bpf_printk("Found authentication key for source IP\n");

        iphdr->check = 0;

        if (debug)
            bpf_printk("=== Processing packet for hash addition with dynamic key ===\n");

        // Runtime selection: use kfunc or custom SHA256 based on use_kfunc flag
        int ret = 0;
        if (config_ctx->use_kfunc == 0) {
            // Use custom SHA256 implementation
            if (debug)
                bpf_printk("Using custom SHA256 for hash\n");
            ret = compute_keyed_hash_from_map_dynamic((BYTE *)iphdr, header_size,
                                                           hash_result, auth_data->key);
        }
        else if (config_ctx->use_kfunc == 1) {
            // Use kernel SHA256 kfunc
            if (debug)
                bpf_printk("Using kfunc SHA256 for hash\n");
            
            ret = bpf_sha256_keyed_hash(auth_data->key, 16,
                           (BYTE *)iphdr, header_size,
                           hash_result);
        }
        else if (config_ctx->use_kfunc == 2) {
            // Use custom CHACHA20-POLY1305 implementation
            if (debug)
                bpf_printk("Using custom CHACHA20-POLY1305 for hash\n");
<<<<<<< HEAD
            #if 0
            ret = compute_chacha20_keyed_hash(auth_data->key, 16, 
                                   (BYTE *)iphdr, header_size,
                                        hash_result);
            #endif
=======
>>>>>>> 03ddeb4 (Adde Chacha20 kernel module)

            /* copy header to stack buffer first */
            __u8 hdr_copy[60] = {};   /* max IPv4 header size */

            if (header_size > 60)
                header_size = 60;

            /* bpf_skb_load_bytes is the safe way to read packet data */
            if (bpf_skb_load_bytes(ctx, sizeof(struct ethhdr), hdr_copy, header_size) < 0) {
                action = TC_ACT_SHOT;
                goto out;
            }

<<<<<<< HEAD
            ret = compute_chacha20_keyed_hash(auth_data->key, 16,
                                              hdr_copy, header_size,
                                              hash_result);
=======
            #if 0
            ret = compute_chacha20_keyed_hash(auth_data->key, 16,
                                              hdr_copy, header_size,
                                              hash_result);
            #endif

            ret = bpf_chacha20poly1305_auth(auth_data->key, 16, 
                                            hdr_copy, header_size, 
                                            hash_result);
            /* hash_result[0..15]  = Poly1305 tag
             * hash_result[16..31] = 0 (zero-padded by kfunc) */
>>>>>>> 03ddeb4 (Adde Chacha20 kernel module)

        } else {
            // Use custom SHA256 implementation
            bpf_printk("Invalid option for hash\n");
        }

        if (ret == 0) {
            if (add_ip_option_hash_tc(ctx, iphdr, hash_result) < 0) {
                action = TC_ACT_OK;
            } else {
                if (debug)
                    bpf_printk("Hash option added successfully with dynamic key\n");
            }
        } else {
            bpf_printk("Failed to compute hash\n");
            action = TC_ACT_OK;
        }
    } else if (eth_type == bpf_htons(ETH_P_IPV6)) {
        action = TC_ACT_OK;
    }

    if (debug) {
        __u64 end_time = bpf_ktime_get_ns();
    	__u64 total_latency = end_time - start_time;

    	bpf_printk("Latency of eBPF program: %d ns\n", total_latency);
    }
out:
    return tc_stats_record_action(ctx, action);
}


SEC("tc_pass")
int tc_pass_func(struct __sk_buff *ctx)
{
    // Get config to check use_kfunc flag
    __u32 key = 0;
    struct {
        __u8 use_kfunc;
    } *config_ctx;

    config_ctx = bpf_map_lookup_elem(&config_map, &key);
    if (!config_ctx)
        return -1;

    // TIMING: Calculate total latency for baseline measurement
    //__u64 start_time = bpf_ktime_get_ns();
    artificial_latency_compute_ops(config_ctx->use_kfunc);

    //__u64 end_time = bpf_ktime_get_ns();
    //__u64 total_latency = end_time - start_time;

    //bpf_printk("Latency in TC: %d ns\n", total_latency);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
