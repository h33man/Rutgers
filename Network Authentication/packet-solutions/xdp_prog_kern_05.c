/*********************************************************************
* XDP Program for Hash key - Source IP lookup and HMAC computation
* 
* Author: Himanshu Chandra 
* Email:  himanshu.chandra@rutgers.edu
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details: Implementation of IP packet authentication using SHA-256 hashing.
*          Includes LPM trie-based key lookup for per-source-IP authentication.
*          Custom SHA-256 implementation in eBPF and kernel, runtime selection via use_kfunc flag.
*********************************************************************/
/*************************** HEADER FILES ***************************/
#include "sha256.h"
#include "chacha20_kfunc.h"
#include <bpf/bpf_helpers.h>

//extern __u8 debug;

// Map for verification to avoid stack overflow
// Extended with use_kfunc flag for runtime selection
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct {
        BYTE extracted_hash[SHA256_BLOCK_SIZE];
        BYTE computed_hash[SHA256_BLOCK_SIZE];
        struct iphdr original_header;
        uint8_t headers_buffer[ETHERNET_HEADER_SIZE + 60];
    });
} verify_map SEC(".maps");

/****************************** HASH VERIFICATION AND COMPUTATION ******************************/

/**
 * Verify IP hash with runtime selection (custom or kfunc)
 * Reads use_kfunc flag from verify_map to decide which implementation to use
 */
static __always_inline int verify_ip_hash_with_key(struct xdp_md *ctx, 
                                                    const BYTE *dynamic_key)
{
    __u32 key = 0;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct {
        __u8 use_kfunc;  // Runtime flag: 0 = custom SHA256, 1 = kfunc SHA256
    } *config_ctx;

   #ifdef BPF_DEBUG
    __u64 t0, t1, t2, t3, t4, t5, t6, t7;
    t0 = bpf_ktime_get_ns();
    #endif

    config_ctx = bpf_map_lookup_elem(&config_map, &key);
    if (!config_ctx)
        return -1;

   #ifdef BPF_DEBUG
    t1 = bpf_ktime_get_ns();
    #endif

    struct {
        BYTE extracted_hash[SHA256_BLOCK_SIZE];
        BYTE computed_hash[SHA256_BLOCK_SIZE];
        struct iphdr original_header;
        uint8_t headers_buffer[ETHERNET_HEADER_SIZE + 60];
    } *verify_ctx;

    verify_ctx = bpf_map_lookup_elem(&verify_map, &key);
    if (!verify_ctx)
        return -1;

   #ifdef BPF_DEBUG
    t2 = bpf_ktime_get_ns();
    #endif

#if 0
    /* Prefetch SHA256 map entries into cache before any other map accesses.
     * This keeps sha256_ctx_map and sha256_temp_map warm when SHA runs later,
     * avoiding cache eviction caused by the intervening header copy loop. */
    {
        __u32 sha_key = 0;
        SHA256_CTX *_sha_ctx __attribute__((unused)) =
            bpf_map_lookup_elem(&sha256_ctx_map, &sha_key);
        struct { BYTE buffer[128]; WORD m[64]; } *_sha_tmp __attribute__((unused)) =
            bpf_map_lookup_elem(&sha256_temp_map, &sha_key);
    }
#endif

    #ifdef BPF_DEBUG
    // map lookups
    t3 = bpf_ktime_get_ns();
    #endif


    struct iphdr *ip_header = (struct iphdr *)(data + ETHERNET_HEADER_SIZE);
    if ((void *)(ip_header + 1) > data_end)
        return -1;

    int header_size = ip_header->ihl * 4;
    int options_len = header_size - sizeof(struct iphdr);

    if (header_size < 20 || header_size > 60 || options_len <= 0) {
        return -1;
    }

    if ((void *)ip_header + header_size > data_end) {
        return -1;
    }

    uint8_t *safe_ip_header = verify_ctx->headers_buffer + ETHERNET_HEADER_SIZE;

    #pragma unroll
    for (int i = 0; i < 60; i++) {
        if (i < header_size && (void *)ip_header + i < data_end) {
            safe_ip_header[i] = *((uint8_t *)ip_header + i);
        } else if (i < 60) {
            safe_ip_header[i] = 0;
        }
    }

    #ifdef BPF_DEBUG
    t4 = bpf_ktime_get_ns();
    #endif

    struct iphdr *safe_ip = (struct iphdr *)safe_ip_header;
    uint8_t *options = safe_ip_header + sizeof(struct iphdr);

    #pragma unroll
    for (int x = 0; x < 32; x++) {
        verify_ctx->extracted_hash[x] = 0;
        verify_ctx->computed_hash[x] = 0;
    }

    int found_hash = 0;

    #pragma unroll
    for (int start_pos = 0; start_pos <= 4 && !found_hash; start_pos++) {
        if (start_pos >= options_len) continue;
        if (start_pos + IP_OPT_HASH_LEN > options_len) continue;

        uint8_t opt_type = options[start_pos];
        if (opt_type == 0) break;
        if (opt_type == 1) continue;

        if (start_pos + 1 < options_len) {
            uint8_t opt_len = options[start_pos + 1];

            if (opt_type == IP_OPT_HASH_ID && opt_len == IP_OPT_HASH_LEN) {
                if (start_pos + 3 < options_len &&
                    options[start_pos + 2] == 0x12 &&
                    options[start_pos + 3] == 0x34) {

                    #ifdef BPF_DEBUG 
                    bpf_printk("Found hash option for verification at pos %d\n", start_pos);
                    #endif

                    #pragma unroll
                    for (int j = 0; j < 32; j++) {
                        if (start_pos + 4 + j < options_len && j < SHA256_BLOCK_SIZE) {
                            verify_ctx->extracted_hash[j] = options[start_pos + 4 + j];
                        }
                    }

                    found_hash = 1;
                }
            }
        }
    }

    #ifdef BPF_DEBUG
    t5 = bpf_ktime_get_ns();
    #endif

    if (!found_hash) {
        bpf_printk("Hash option not found\n");
        return -1;
    }

    verify_ctx->original_header = *safe_ip;
    verify_ctx->original_header.ihl = 5;
    verify_ctx->original_header.tot_len = bpf_htons(bpf_ntohs(verify_ctx->original_header.tot_len) - options_len);
    verify_ctx->original_header.check = 0;

    #ifdef BPF_DEBUG
    t6 = bpf_ktime_get_ns();
    #endif

    int ret = 0;
    if (config_ctx->use_kfunc == 0) {
        // Use custom SHA256 implementation
        #ifdef BPF_DEBUG 
        bpf_printk("Using custom SHA256 for verification\n");
        #endif

        ret = compute_keyed_hash_from_map_dynamic((BYTE *)&verify_ctx->original_header,
                                            sizeof(struct iphdr), verify_ctx->computed_hash, dynamic_key);
    }
    else if (config_ctx->use_kfunc == 1) {
        // Use kernel SHA256 kfunc
        #ifdef BPF_DEBUG 
        bpf_printk("Using kfunc SHA256 for verification\n");
        #endif

        __u8 hdr_stack[sizeof(struct iphdr)];
        __builtin_memcpy(hdr_stack, &verify_ctx->original_header, sizeof(struct iphdr));
        ret = bpf_sha256_hash(dynamic_key, 64,
                                   hdr_stack,
                                   sizeof(struct iphdr),
                                   verify_ctx->computed_hash);

    }
    else if (config_ctx->use_kfunc == 2) {
        // Use crypto SHA256 kfunc
        #ifdef BPF_DEBUG 
        bpf_printk("Using crypto SHA256 for verification\n");
        #endif

        __u8 hdr_stack[sizeof(struct iphdr)];
        __builtin_memcpy(hdr_stack, &verify_ctx->original_header, sizeof(struct iphdr));
        ret = bpf_sha256_keyed_hash(dynamic_key, 64,
                                   hdr_stack,
                                   sizeof(struct iphdr),
                                   verify_ctx->computed_hash);

    }
    else if (config_ctx->use_kfunc == 3) {
        // Use custom CHACHA20-POLY1305 implementation
        #ifdef BPF_DEBUG 
        bpf_printk("Using custom CHACHA20-POLY1305 for hash\n");
        #endif

        /* Copy to stack buffer - verifier can track bounds on stack */
        __u8 hdr_copy[60] = {};
        if (header_size > 60)
            header_size = 60;

        /* XDP uses __builtin_memcpy not bpf_skb_load_bytes */
        __builtin_memcpy(hdr_copy, (const __u8 *)&verify_ctx->original_header,
                                   sizeof(struct iphdr)); 

        ret = bpf_chacha20poly1305_hash(dynamic_key, 32, hdr_copy, sizeof(struct iphdr),
                                        verify_ctx->computed_hash);

    }
    else {
        bpf_printk("Invalid option for hash\n");
    }

    #ifdef BPF_DEBUG
    // sha256
    t7 = bpf_ktime_get_ns();
    #endif

    if (ret != 0) {
        bpf_printk("Failed to compute hash for verification\n");
        return -1;
    }

    int hash_match = 1;
    #pragma unroll
    for (int k = 0; k < 32; k++) {
        if (k < SHA256_BLOCK_SIZE &&
            verify_ctx->extracted_hash[k] != verify_ctx->computed_hash[k]) {
            hash_match = 0;
            break;
        }
    }

    #ifdef BPF_DEBUG 
    bpf_printk("Hash recieved: ");
    print_hex(verify_ctx->extracted_hash, 32);
    bpf_printk("Hash computed: ");
    print_hex(verify_ctx->computed_hash, 32);
    #endif

    #ifdef BPF_DEBUG 
    bpf_printk("config map lookup=%llu verify map lookup=%llu sha map lookup=%llu \
                header copy loop=%llu hash extraction loop=%llu original_header reconstruction=%llu \
                SHA256=%llu",
                t1-t0, t2-t1, t3-t2, t4-t3, t5-t4, t6-t5, t7-t6);
    #endif


    if (hash_match) {
        #ifdef BPF_DEBUG 
        bpf_printk("Hash verification PASSED with dynamic key\n");
        #endif
        return 0;
    } else {
        bpf_printk("Hash verification FAILED with dynamic key\n");
        return -2;
    }
    
    return 0;
}

/****************************** IP OPTION MANIPULATION ******************************/

/**
 * Remove IP option hash from packet
 */
static __always_inline int remove_ip_option_hash(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    uint8_t headers_copy[ETHERNET_HEADER_SIZE + sizeof(struct iphdr)];

    if ((void *)data + IP_OPT_HASH_LEN + sizeof(headers_copy) > data_end)
        return -1;

    __builtin_memcpy(headers_copy, data, sizeof(headers_copy));

    if (bpf_xdp_adjust_head(ctx, (int)IP_OPT_HASH_LEN))
        return -1;

    data_end = (void *)(long)ctx->data_end;
    data = (void *)(long)ctx->data;

    if ((void *)data + sizeof(headers_copy) > data_end)
        return -1;

    __builtin_memcpy(data, headers_copy, sizeof(headers_copy));

    struct iphdr *new_ip = (struct iphdr *)(data + ETHERNET_HEADER_SIZE);
    if ((void *)(new_ip + 1) > data_end)
        return -1;

    new_ip->ihl = (sizeof(struct iphdr)) / 4;
    new_ip->tot_len = bpf_htons(bpf_ntohs(new_ip->tot_len) - IP_OPT_HASH_LEN);
    new_ip->check = 0;

    new_ip->check = calculate_ip_checksum((const void *)new_ip, sizeof(struct iphdr));

    #ifdef BPF_DEBUG 
    bpf_printk("Hash option removed, new checksum: 0x%04x\n", new_ip->check);
    #endif

    return 0;
}

/**
 * Add IP option with hash with runtime selection (custom or kfunc)
 */
static __always_inline int add_ip_option_hash(struct xdp_md *ctx,
                                              struct iphdr *ip_orig,
                                              const BYTE *hash,
                                              const __u8 *dynamic_key)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    uint8_t headers_copy[ETHERNET_HEADER_SIZE + sizeof(struct iphdr)];
    uint8_t option_len = IP_OPT_HASH_LEN;
    int ret = -1;

    if ((void *)data + sizeof(headers_copy) > data_end)
        return -1;

    __builtin_memcpy(headers_copy, data, sizeof(headers_copy));

    // Check if we should use kfunc or custom implementation
    __u32 key = 0;
    struct {
        __u8 hash_output[SHA256_BLOCK_SIZE];
    } *hash_ctx;

    hash_ctx = bpf_map_lookup_elem(&kfunc_hash_map, &key);
    if (!hash_ctx) {
        #ifdef BPF_DEBUG 
        //bpf_printk("Attempting to compute hash using custom sha\n");
        bpf_printk("Using custom SHA256 for hash addition\n");
        #endif

        struct iphdr *header_copy = (struct iphdr *)(headers_copy + ETHERNET_HEADER_SIZE);
        header_copy->check = 0;

        ret = compute_keyed_hash_from_map_dynamic((const __u8 *)header_copy, sizeof(*header_copy),
                                    hash_ctx->hash_output, dynamic_key);
        if (ret == 0) {
            #ifdef BPF_DEBUG 
            bpf_printk("Using kfunc SHA256 for hash addition\n");
            #endif

            // Use hash computed by kfunc
            if (bpf_xdp_adjust_head(ctx, 0 - (int)IP_OPT_HASH_LEN))
                return -1;

            data_end = (void *)(long)ctx->data_end;
            data = (void *)(long)ctx->data;

            if ((void *)data + sizeof(headers_copy) > data_end)
                return -1;

            __builtin_memcpy(data, headers_copy, sizeof(headers_copy));

            struct iphdr *new_ip = (struct iphdr *)(data + ETHERNET_HEADER_SIZE);
            if ((void *)(new_ip + 1) > data_end)
                return -1;

            new_ip->ihl = (sizeof(struct iphdr) + IP_OPT_HASH_LEN) / 4;
            new_ip->tot_len = bpf_htons(bpf_ntohs(new_ip->tot_len) + IP_OPT_HASH_LEN);
            new_ip->check = 0;

            uint8_t *options = (uint8_t *)(new_ip + 1);
            if ((void *)(options + option_len) > data_end)
                return -1;

            options[0] = IP_OPT_HASH_ID;
            options[1] = option_len;
            options[2] = 0x12;
            options[3] = 0x34;

            #pragma unroll
            for (int i = 0; i < 32; i += 4) {
                if (i + 3 < 32 && 4 + i + 3 < option_len) {
                    options[4 + i] = hash_ctx->hash_output[i];
                    options[4 + i + 1] = hash_ctx->hash_output[i + 1];
                    options[4 + i + 2] = hash_ctx->hash_output[i + 2];
                    options[4 + i + 3] = hash_ctx->hash_output[i + 3];
                }
            }

            int header_len = new_ip->ihl * 4;
            new_ip->check = calculate_ip_checksum((const void *)new_ip, header_len);
            
            #ifdef BPF_DEBUG 
            bpf_printk("Hash added successfully (kfunc), new checksum: 0x%04x\n", new_ip->check);
            #endif
            return 0;
        }
    }

    // If kfunc failed or not available, use custom SHA256
    #ifdef BPF_DEBUG 
    bpf_printk("Using custom SHA256 for hash addition\n");
    #endif
    
    if (bpf_xdp_adjust_head(ctx, 0 - (int)IP_OPT_HASH_LEN))
        return -1;

    data_end = (void *)(long)ctx->data_end;
    data = (void *)(long)ctx->data;

    if ((void *)data + sizeof(headers_copy) > data_end)
        return -1;

    __builtin_memcpy(data, headers_copy, sizeof(headers_copy));

    struct iphdr *new_ip = (struct iphdr *)(data + ETHERNET_HEADER_SIZE);
    if ((void *)(new_ip + 1) > data_end)
        return -1;

    new_ip->ihl = (sizeof(struct iphdr) + IP_OPT_HASH_LEN) / 4;
    new_ip->tot_len = bpf_htons(bpf_ntohs(new_ip->tot_len) + IP_OPT_HASH_LEN);
    new_ip->check = 0;

    uint8_t *options = (uint8_t *)(new_ip + 1);
    if ((void *)(options + option_len) > data_end)
        return -1;

    options[0] = IP_OPT_HASH_ID;
    options[1] = option_len;
    options[2] = 0x12;
    options[3] = 0x34;

    #pragma unroll
    for (int i = 0; i < 32; i += 4) {
        if (i + 3 < 32 && 4 + i + 3 < option_len) {
            options[4 + i] = hash[i];
            options[4 + i + 1] = hash[i + 1];
            options[4 + i + 2] = hash[i + 2];
            options[4 + i + 3] = hash[i + 3];
        }
    }

    int header_len = new_ip->ihl * 4;
    new_ip->check = calculate_ip_checksum((const void *)new_ip, header_len);
    
    #ifdef BPF_DEBUG 
    bpf_printk("Hash added successfully (custom), new checksum: 0x%04x\n", new_ip->check);
    #endif

    return 0;
}

/****************************** XDP PROGRAMS ******************************/

/**
 * XDP program for hash verification and removal with runtime selection
 */
SEC("xdp_ip_hash_verify")
int xdp_ip_hash_verify_func(struct xdp_md *ctx)
{
    int action = XDP_PASS;
    int eth_type, ip_type;
    struct ethhdr *eth;
    struct iphdr *iphdr;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct hdr_cursor nh = { .pos = data };

    #ifdef BPF_DEBUG
    __u64 t0, t1, t2, t3;
    t0 = bpf_ktime_get_ns();
    t1 = t2 = t3 = t0;
    #endif

    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type < 0) {
        action = XDP_ABORTED;
        goto out;
    }

    if (eth_type == bpf_htons(ETH_P_IP)) {
        ip_type = parse_iphdr(&nh, data_end, &iphdr);
        if (ip_type < 0) {
            action = XDP_ABORTED;
            goto out;
        }

        // Only processing UDP
        if (iphdr->protocol != IPPROTO_UDP) {
            
            #ifdef BPF_DEBUG 
            bpf_printk("Not a UDP packet, passing through\n");
            #endif

            action = XDP_PASS;
            goto out;
        }

        int header_size = iphdr->ihl * 4;
        if ((void *)iphdr + header_size > data_end) {
            action = XDP_ABORTED;
            goto out;
        }

        struct ip_auth_data *auth_data = lookup_auth_key(iphdr->saddr);
        if (!auth_data) {
            #ifdef BPF_DEBUG 
            bpf_printk("No authentication key found for source IP %s\n", iphdr->saddr);
            #endif

            action = XDP_PASS;
            goto out;
        }

        #ifdef BPF_DEBUG
	    // key lookup
        t1 = bpf_ktime_get_ns();
        #endif

        #ifdef BPF_DEBUG 
        bpf_printk("Found authentication key for source IP\n");
        #endif

        if (iphdr->ihl > 5) {
            #ifdef BPF_DEBUG 
            bpf_printk("IP options present, attempting hash verification with dynamic key\n");
            #endif

            int verify_result = verify_ip_hash_with_key(ctx, auth_data->key);

            #ifdef BPF_DEBUG
	        t2 = bpf_ktime_get_ns();
            #endif

            if (verify_result == 0) {
                #ifdef BPF_DEBUG 
                bpf_printk("Hash verification passed with dynamic key\n");
                #endif

                switch (auth_data->action) {
                    case ACTION_ALLOW:
                        #ifdef BPF_DEBUG 
                        bpf_printk("Action: ALLOW - removing hash option\n");
                        #endif
                        if (remove_ip_option_hash(ctx) == 0) {
                            #ifdef BPF_DEBUG 
                            bpf_printk("Hash option removed successfully\n");
                            #endif
                        } else {
                            bpf_printk("Failed to remove hash option\n");
                        }
                        action = XDP_PASS;
                        break;
                    case ACTION_MARK:
                        #ifdef BPF_DEBUG 
                        bpf_printk("Action: MARK - passing with mark\n");
                        #endif
                        action = XDP_PASS;
                        break;
                    case ACTION_DROP:
                        #ifdef BPF_DEBUG 
                        bpf_printk("Action: DROP - dropping authenticated packet\n");
                        #endif
                        action = XDP_DROP;
                        break;
                    default:
                        action = XDP_PASS;
                        break;
                }
            } else if (verify_result == -2) {
                bpf_printk("SECURITY: Hash verification failed - dropping packet\n");
                action = XDP_DROP;
            } else {
                bpf_printk("Hash option not found or verification error, passing packet\n");
                action = XDP_PASS;
            }
        } else {
            bpf_printk("No IP options found, passing packet through\n");
            action = XDP_PASS;
        }
    } else if (eth_type == bpf_htons(ETH_P_IPV6)) {
        action = XDP_PASS;
    }

    #ifdef BPF_DEBUG
    //adjust
    t3 = bpf_ktime_get_ns();
    bpf_printk("key lookup=%llu adjust=%llu\n", t1-t0, t3-t2);
    #endif

out:
    return xdp_stats_record_action(ctx, action);
}

/**
 * XDP program for adding hash to packets with runtime selection
 */
SEC("xdp_ip_hash")
int xdp_ip_hash_func(struct xdp_md *ctx)
{
    int action = XDP_PASS;
    int eth_type, ip_type;
    struct ethhdr *eth;
    struct iphdr *iphdr;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct hdr_cursor nh = { .pos = data };
    BYTE hash_result[SHA256_BLOCK_SIZE];

    __u32 key = 0;
    struct {
        __u8 use_kfunc;  // Runtime flag: 0 = custom SHA256, 1 = kfunc SHA256
    } *config_ctx;

    config_ctx = bpf_map_lookup_elem(&config_map, &key);
    if (!config_ctx)
        return -1;

    struct {
        BYTE extracted_hash[SHA256_BLOCK_SIZE];
        BYTE computed_hash[SHA256_BLOCK_SIZE];
        struct iphdr original_header;
        uint8_t headers_buffer[ETHERNET_HEADER_SIZE + 60];
    } *verify_ctx;

    verify_ctx = bpf_map_lookup_elem(&verify_map, &key);
    if (!verify_ctx)
        return -1;

    __builtin_memset(hash_result, 0, SHA256_BLOCK_SIZE);

    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type < 0) {
        action = XDP_ABORTED;
        goto out;
    }

    if (eth_type == bpf_htons(ETH_P_IP)) {
        ip_type = parse_iphdr(&nh, data_end, &iphdr);
        if (ip_type < 0) {
            action = XDP_ABORTED;
            goto out;
        }

        // Only processing UDP
        if (iphdr->protocol != IPPROTO_UDP) {
            bpf_printk("Not a UDP packet, passing through\n");
            action = XDP_PASS;
            goto out;
        }

        if ((void *)(iphdr + 1) > data_end) {
            action = XDP_ABORTED;
            goto out;
        }

        int header_size = iphdr->ihl * 4;
        if ((void *)iphdr + header_size > data_end) {
            action = XDP_ABORTED;
            goto out;
        }

        struct ip_auth_data *auth_data = lookup_auth_key(iphdr->saddr);
        if (!auth_data) {
            bpf_printk("No authentication key found for source IP, passing without hash\n");
            action = XDP_PASS;
            goto out;
        }

        #ifdef BPF_DEBUG 
        bpf_printk("Found authentication key for source IP\n");
        #endif

        iphdr->check = 0;

        #ifdef BPF_DEBUG 
        bpf_printk("=== Processing packet for hash addition with dynamic key ===\n");
        #endif

        // Runtime selection: use kfunc or custom SHA256 based on use_kfunc flag
        int ret = 0;
        if (config_ctx->use_kfunc == 0) {
            // Use custom SHA256 implementation
            #ifdef BPF_DEBUG 
            bpf_printk("Using custom SHA256 for verification\n");
            #endif

            ret = compute_keyed_hash_from_map_dynamic((BYTE *)&verify_ctx->original_header,
                                 sizeof(struct iphdr), verify_ctx->computed_hash, auth_data->key);
        }
        else if (config_ctx->use_kfunc == 1) {
            // Use kernel SHA256 kfunc
            #ifdef BPF_DEBUG 
            bpf_printk("Using kfunc SHA256 for verification\n");
            #endif

            __u8 hdr_stack[sizeof(struct iphdr)];
            __builtin_memcpy(hdr_stack, &verify_ctx->original_header, sizeof(struct iphdr));
            ret = bpf_sha256_hash(auth_data->key, 64,
                                       hdr_stack, 
                                       sizeof(struct iphdr),
                                       verify_ctx->computed_hash);

        }
        else if (config_ctx->use_kfunc == 2) {
            // Use crypto SHA256 kfunc
            #ifdef BPF_DEBUG 
            bpf_printk("Using crypto SHA256 for verification\n");
            #endif

            __u8 hdr_stack[sizeof(struct iphdr)];
            __builtin_memcpy(hdr_stack, &verify_ctx->original_header, sizeof(struct iphdr));
            ret = bpf_sha256_keyed_hash(auth_data->key, 64,
                                       hdr_stack, 
                                       sizeof(struct iphdr),
                                       verify_ctx->computed_hash);

        }
        else if (config_ctx->use_kfunc == 3) {
            // Use custom CHACHA20-POLY1305 implementation
            #ifdef BPF_DEBUG 
            bpf_printk("Using custom CHACHA20-POLY1305 for hash\n");
            #endif

            /* Copy to stack buffer - verifier can track bounds on stack */
            __u8 hdr_copy[60] = {};
            if (header_size > 60)
                header_size = 60;

            /* XDP uses __builtin_memcpy not bpf_skb_load_bytes */
            __builtin_memcpy(hdr_copy, (const __u8 *)&verify_ctx->original_header,
                                       sizeof(struct iphdr)); 

            ret = bpf_chacha20poly1305_hash(auth_data->key, 32, hdr_copy, sizeof(struct iphdr),
                                            verify_ctx->computed_hash);

        }
        else {
            bpf_printk("Invalid option for hash\n");
        }

        if (ret == 0) {
            if (add_ip_option_hash(ctx, iphdr, hash_result, auth_data->key) < 0) {
                bpf_printk("Failed to add hash option\n");
                action = XDP_PASS;
            } else {
                #ifdef BPF_DEBUG 
                bpf_printk("Hash option added successfully with dynamic key\n");
                #endif
            }
        } else {
            bpf_printk("Failed to compute hash\n");
            action = XDP_PASS;
        }
    } else if (eth_type == bpf_htons(ETH_P_IPV6)) {
        action = XDP_PASS;
    }

out:
    return xdp_stats_record_action(ctx, action);
}

/**
 * Simple pass-through XDP program
 */
SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx)
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

    //bpf_printk("Latency in XDP: %d ns\n", total_latency);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
