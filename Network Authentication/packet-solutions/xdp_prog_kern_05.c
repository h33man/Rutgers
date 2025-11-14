/*********************************************************************
* XDP Program for SHA256-Hash key Source IP lookup and HMAC computation
* 
* Author: Himanshu Chandra 
* Email:  himanshu.chandra@rutgers.edu
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details: Implementation of IP packet authentication using SHA-256 hashing.
*          Includes LPM trie-based key lookup for per-source-IP authentication.
*          Custom SHA-256 implementation in eBPF and kernel, runtime selection via use_kfunc flag.
*********************************************************************/
/*********************************************************************
* Filename:   sha256.c
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Implementation of the SHA-256 hashing algorithm.
              SHA-256 is one of the three algorithms in the SHA2
              specification. The others, SHA-384 and SHA-512, are not
              offered in this implementation.
              Algorithm specification can be found here:
               * http://csrc.nist.gov/publications/fips/fips180-2/fips180-2withchangenotice.pdf
              This implementation uses little endian byte order.
*********************************************************************/

/*************************** HEADER FILES ***************************/
#include "sha256.h"

extern __u8 debug;

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

                    if (debug)
                        bpf_printk("Found hash option for verification at pos %d\n", start_pos);

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

    if (!found_hash) {
        bpf_printk("Hash option not found\n");
        return -1;
    }

    verify_ctx->original_header = *safe_ip;
    verify_ctx->original_header.ihl = 5;
    verify_ctx->original_header.tot_len = bpf_htons(bpf_ntohs(verify_ctx->original_header.tot_len) - options_len);
    verify_ctx->original_header.check = 0;

    // Runtime selection: use kfunc or custom SHA256 based on use_kfunc flag
    int ret;
    if (config_ctx->use_kfunc) {
        // Use kernel SHA256 kfunc
        if (debug)
            bpf_printk("Using kfunc SHA256 for verification\n");

        ret = bpf_sha256_keyed_hash(dynamic_key, 16,
                                   (const __u8 *)&verify_ctx->original_header,
                                   sizeof(struct iphdr), 
                                   verify_ctx->computed_hash);
    } else {
        // Use custom SHA256 implementation
        if (debug)
            bpf_printk("Using custom SHA256 for verification\n");

        ret = compute_keyed_hash_from_map_dynamic((BYTE *)&verify_ctx->original_header,
                                            sizeof(struct iphdr), verify_ctx->computed_hash, dynamic_key);
    }

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

    if (hash_match) {
        if (debug)
            bpf_printk("Hash verification PASSED with dynamic key\n");
        return 0;
    } else {
        bpf_printk("Hash verification FAILED with dynamic key\n");
        return -2;
    }
}

/****************************** IP OPTION MANIPULATION ******************************/

/**
 * Remove IP option hash from packet
 */
static __always_inline int remove_ip_option_hash(struct xdp_md *ctx,
                                                  struct iphdr *ip_orig)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    uint8_t headers_copy[ETHERNET_HEADER_SIZE + sizeof(struct iphdr)];

    if ((void *)data + sizeof(headers_copy) > data_end)
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

    int header_len = new_ip->ihl * 4;
    new_ip->check = calculate_ip_checksum((const void *)new_ip, header_len);

    if (debug)
        bpf_printk("Hash option removed, new checksum: 0x%04x\n", new_ip->check);

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
    if (hash_ctx) {
        // Try to use kfunc - if available, compute hash using kfunc
        if (debug)
            bpf_printk("Attempting to compute hash using kfunc\n");
        struct iphdr *header_copy = (struct iphdr *)(headers_copy + ETHERNET_HEADER_SIZE);
        header_copy->check = 0;

        ret = bpf_sha256_keyed_hash(dynamic_key, 16, 
                                    (const __u8 *)header_copy, sizeof(*header_copy), 
                                    hash_ctx->hash_output);
        if (ret == 0) {
            if (debug)
                bpf_printk("Using kfunc SHA256 for hash addition\n");
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
            
            if (debug)
                bpf_printk("Hash added successfully (kfunc), new checksum: 0x%04x\n", new_ip->check);
            return 0;
        }
    }

    // If kfunc failed or not available, use custom SHA256
    if (debug)
        bpf_printk("Using custom SHA256 for hash addition\n");
    
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
    
    if (debug)
        bpf_printk("Hash added successfully (custom), new checksum: 0x%04x\n", new_ip->check);

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
            if (debug)
                bpf_printk("Not a UDP packet, passing through\n");
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
            if (debug)
                bpf_printk("No authentication key found for source IP %s\n", iphdr->saddr);
            action = XDP_PASS;
            goto out;
        }

        if (debug)
            bpf_printk("Found authentication key for source IP\n");

        if (iphdr->ihl > 5) {
            if (debug)
                bpf_printk("IP options present, attempting hash verification with dynamic key\n");

            int verify_result = verify_ip_hash_with_key(ctx, auth_data->key);

            if (verify_result == 0) {
                if (debug)
                    bpf_printk("Hash verification passed with dynamic key\n");

                switch (auth_data->action) {
                    case ACTION_ALLOW:
                        if (debug)
                            bpf_printk("Action: ALLOW - removing hash option\n");
                        if (remove_ip_option_hash(ctx, iphdr) == 0) {
                            if (debug)
                                bpf_printk("Hash option removed successfully\n");
                        } else {
                            bpf_printk("Failed to remove hash option\n");
                        }
                        action = XDP_PASS;
                        break;
                    case ACTION_MARK:
                        if (debug)
                            bpf_printk("Action: MARK - passing with mark\n");
                        action = XDP_PASS;
                        break;
                    case ACTION_DROP:
                        if (debug)
                            bpf_printk("Action: DROP - dropping authenticated packet\n");
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

        if (debug)
            bpf_printk("Found authentication key for source IP\n");

        iphdr->check = 0;

        if (debug)
            bpf_printk("=== Processing packet for hash addition with dynamic key ===\n");

	// Runtime selection: use kfunc or custom SHA256 based on use_kfunc flag
	int ret;
	if (config_ctx->use_kfunc) {
	    // Use kernel SHA256 kfunc
        if (debug)
	        bpf_printk("Using kfunc SHA256 for verification\n");

	    ret = bpf_sha256_keyed_hash(auth_data->key, 16,
				       (BYTE *)iphdr,
				       header_size,
				       hash_result);
	} else {
	    // Use custom SHA256 implementation
        if (debug)
	        bpf_printk("Using custom SHA256 for verification\n");

	    ret = compute_keyed_hash_from_map_dynamic((BYTE *)iphdr, header_size,
	                                                   hash_result, auth_data->key);
	}

        if (ret == 0) {
            if (add_ip_option_hash(ctx, iphdr, hash_result, auth_data->key) < 0) {
                bpf_printk("Failed to add hash option\n");
                action = XDP_PASS;
            } else {
                if (debug)
                    bpf_printk("Hash option added successfully with dynamic key\n");
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
