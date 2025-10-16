#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// Must match the eBPF program definitions
struct auth_data {
    __u32 field_mask;
    __u8 key[16];       // Changed from 32 to 16 bytes
    __u8 action;
    // Removed key_id and reserved fields - not needed
};

struct ipv4_lpm_key {
    //__u8 prefixlen;     // Changed from __u32 to __u8 (only need 0-32)
    __u32 prefixlen;     
    __u32 data;         // Keep as u32 for network byte order
};

// Field mask definitions (must match eBPF program)
#define FIELD_SRC_MAC    (1 << 0)
#define FIELD_DST_MAC    (1 << 1)
#define FIELD_VLAN       (1 << 2)
#define FIELD_SRC_IP     (1 << 3)
#define FIELD_DST_IP     (1 << 4)
#define FIELD_PROTOCOL   (1 << 5)
#define FIELD_SRC_PORT   (1 << 6)
#define FIELD_DST_PORT   (1 << 7)
#define FIELD_TCP_FLAGS  (1 << 8)

// Action definitions
#define ACTION_DROP      0
#define ACTION_ALLOW     1
#define ACTION_MARK      2

// Global variable for BPF map (only src_ip_auth_map needed)
static int src_ip_auth_map_fd = -1;

// Function to find existing BPF map by name
static int find_bpf_map(const char *map_name) {
    __u32 map_id = 0;
    
    // Iterate through all BPF maps in the system
    while (bpf_map_get_next_id(map_id, &map_id) == 0) {
        int fd = bpf_map_get_fd_by_id(map_id);
        if (fd < 0) {
            continue;
        }
        
        struct bpf_map_info info;
        __u32 info_len = sizeof(info);
        
        if (bpf_obj_get_info_by_fd(fd, &info, &info_len) == 0) {
            if (strcmp(info.name, map_name) == 0) {
                printf("Found BPF map '%s' with fd=%d\n", map_name, fd);
                return fd;
            }
        }
        
        close(fd);
    }
    
    return -1;
}

// Initialize by finding existing maps
static int init_maps(void) {
    src_ip_auth_map_fd = find_bpf_map("src_ip_key_map");
    
    if (src_ip_auth_map_fd < 0) {
        fprintf(stderr, "ERROR: Could not find src_ip_auth_map. Is the BPF program loaded?\n");
        return -1;
    }
    
    printf("Connected to existing BPF map: src_auth_fd=%d\n", src_ip_auth_map_fd);
    return 0;
}

// Convert IP address string to network byte order
static int parse_ip_prefix(const char *ip_str, struct ipv4_lpm_key *key) {
    char *ip_copy = strdup(ip_str);
    char *prefix_len_str = strchr(ip_copy, '/');
    
    if (prefix_len_str) {
        *prefix_len_str = '\0';
        prefix_len_str++;
        key->prefixlen = (__u8)atoi(prefix_len_str);
    } else {
        key->prefixlen = 32;  // Default to /32
    }
    
    if (key->prefixlen > 32) {
        fprintf(stderr, "ERROR: Invalid prefix length %d\n", key->prefixlen);
        free(ip_copy);
        return -1;
    }
    
    struct in_addr addr;
    if (inet_aton(ip_copy, &addr) == 0) {
        fprintf(stderr, "ERROR: Invalid IP address %s\n", ip_copy);
        free(ip_copy);
        return -1;
    }
    
    key->data = addr.s_addr;
    free(ip_copy);
    return 0;
}

// Parse hex key string (16 bytes = 32 hex characters)
static int parse_hex_key(const char *hex_str, __u8 *key) {
    size_t hex_len = strlen(hex_str);
    
    if (hex_len != 32) {  // Changed from 64 to 32 characters
        fprintf(stderr, "ERROR: Hex key must be exactly 32 characters (16 bytes)\n");
        return -1;
    }
    
    for (int i = 0; i < 16; i++) {  // Changed from 32 to 16 bytes
        int byte_val;
        if (sscanf(hex_str + (i * 2), "%2x", &byte_val) != 1) {
            fprintf(stderr, "ERROR: Invalid hex character at position %d\n", i * 2);
            return -1;
        }
        key[i] = (__u8)byte_val;
    }
    
    return 0;
}

// Generate a simple key from a password string (for demo purposes)
static void generate_key_from_password(const char *password, __u8 *key) {
    // Simple key derivation (NOT cryptographically secure - use PBKDF2 in production)
    memset(key, 0, 16);  // Changed from 32 to 16 bytes
    size_t pass_len = strlen(password);
    
    for (int i = 0; i < 16; i++) {  // Changed from 32 to 16 bytes
        key[i] = password[i % pass_len] ^ (i * 37);
    }
}

// Add authentication rule
static int add_auth_rule(const char *ip_prefix, __u32 field_mask, 
                        const char *key_input, __u8 action, int is_hex_key) {
    struct ipv4_lpm_key key;
    struct auth_data auth_rule;
    
    init_maps();
    if (src_ip_auth_map_fd < 0) {
        fprintf(stderr, "ERROR: Map not initialized. Run with 'init' command first.\n");
        return -1;
    }
    
    // Parse IP prefix
    if (parse_ip_prefix(ip_prefix, &key) < 0) {
        return -1;
    }
    
    // Prepare authentication data
    auth_rule.field_mask = field_mask;
    auth_rule.action = action;
    
    // Handle key input (hex or password)
    if (is_hex_key) {
        if (parse_hex_key(key_input, auth_rule.key) < 0) {
            return -1;
        }
        printf("Using provided hex key\n");
    } else {
        generate_key_from_password(key_input, auth_rule.key);
        printf("Generated key from password\n");
    }
    
    // Add to map
    if (bpf_map_update_elem(src_ip_auth_map_fd, &key, &auth_rule, BPF_ANY) != 0) {
        fprintf(stderr, "ERROR: Failed to update map: %s\n", strerror(errno));
        return -1;
    }
    
    printf("Added source authentication rule for %s\n", ip_prefix);
    return 0;
}

// Delete authentication rule
static int delete_auth_rule(const char *ip_prefix) {
    struct ipv4_lpm_key key;
    
    init_maps();
    if (src_ip_auth_map_fd < 0) {
        fprintf(stderr, "ERROR: Map not initialized\n");
        return -1;
    }
    
    if (parse_ip_prefix(ip_prefix, &key) < 0) {
        return -1;
    }
    
    if (bpf_map_delete_elem(src_ip_auth_map_fd, &key) != 0) {
        fprintf(stderr, "ERROR: Failed to delete from map: %s\n", strerror(errno));
        return -1;
    }
    
    printf("Deleted source authentication rule for %s\n", ip_prefix);
    return 0;
}

// List all authentication rules
static int list_auth_rules(void) {
    struct ipv4_lpm_key key, next_key;
    struct auth_data auth_rule;
    int found = 0;
    
    init_maps();
    if (src_ip_auth_map_fd < 0) {
        fprintf(stderr, "ERROR: Map not initialized\n");
        return -1;
    }
    
    printf("\nSource IP Authentication Rules:\n");
    printf("%-18s %-4s %-10s %-8s\n", "PREFIX", "LEN", "FIELDS", "ACTION");
    printf("------------------------------------------------\n");
    
    // Iterate through all entries
    memset(&key, 0, sizeof(key));
    while (bpf_map_get_next_key(src_ip_auth_map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(src_ip_auth_map_fd, &next_key, &auth_rule) == 0) {
            struct in_addr addr;
            addr.s_addr = next_key.data;
            
            char *action_str;
            switch (auth_rule.action) {
                case ACTION_DROP: action_str = "DROP"; break;
                case ACTION_ALLOW: action_str = "ALLOW"; break;
                case ACTION_MARK: action_str = "MARK"; break;
                default: action_str = "UNKNOWN"; break;
            }
            
            printf("%-18s %-4d 0x%-8x %-8s\n", 
                   inet_ntoa(addr), next_key.prefixlen, 
                   auth_rule.field_mask, action_str);
            found++;
        }
        key = next_key;
    }
    
    if (found == 0) {
        printf("No rules found.\n");
    } else {
        printf("Total: %d rules\n", found);
    }
    
    return 0;
}

// Show key for a specific rule (for debugging)
static int show_key(const char *ip_prefix) {
    struct ipv4_lpm_key key;
    struct auth_data auth_rule;
    
    init_maps();
    if (src_ip_auth_map_fd < 0) {
        fprintf(stderr, "ERROR: Map not initialized\n");
        return -1;
    }
    
    if (parse_ip_prefix(ip_prefix, &key) < 0) {
        return -1;
    }
    
    if (bpf_map_lookup_elem(src_ip_auth_map_fd, &key, &auth_rule) != 0) {
        fprintf(stderr, "ERROR: Rule not found for %s\n", ip_prefix);
        return -1;
    }
    
    printf("Authentication key for %s:\n", ip_prefix);
    printf("Hex: ");
    for (int i = 0; i < 16; i++) {  // Changed from 32 to 16 bytes
        printf("%02x", auth_rule.key[i]);
    }
    printf("\n");
    
    return 0;
}

// Print usage information
static void print_usage(const char *prog_name) {
    printf("Usage: %s <command> [options]\n\n", prog_name);
    printf("Commands:\n");
    printf("  init                            Find and connect to existing BPF maps\n");
    printf("  add <ip/prefix> <password>      Add rule with password-based key\n");
    printf("  add-hex <ip/prefix> <hex_key>   Add rule with 32-char hex key\n");  // Updated description
    printf("  delete <ip/prefix>              Delete authentication rule\n");
    printf("  list                            List all authentication rules\n");
    printf("  show-key <ip/prefix>            Show hex key for specific rule\n");
    printf("\nExamples:\n");
    printf("  %s init\n", prog_name);
    printf("  %s add 192.168.1.0/24 mypassword\n", prog_name);
    printf("  %s add-hex 10.0.0.0/8 abcdef0123456789abcdef0123456789\n", prog_name);  // Updated example
    printf("  %s list\n", prog_name);
    printf("  %s show-key 192.168.1.0/24\n", prog_name);
    printf("  %s delete 192.168.1.0/24\n", prog_name);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char *command = argv[1];
    
    if (strcmp(command, "init") == 0) {
        return init_maps();
        
    } else if (strcmp(command, "add") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Usage: %s add <ip/prefix> <password>\n", argv[0]);
            return 1;
        }
        // Default field mask: authenticate source and destination IPs
        return add_auth_rule(argv[2], FIELD_SRC_IP | FIELD_DST_IP, 
                            argv[3], ACTION_ALLOW, 0);  // 0 = password mode
        
    } else if (strcmp(command, "add-hex") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Usage: %s add-hex <ip/prefix> <hex_key>\n", argv[0]);
            fprintf(stderr, "Note: hex_key must be exactly 32 hex characters (16 bytes)\n");  // Updated
            return 1;
        }
        return add_auth_rule(argv[2], FIELD_SRC_IP | FIELD_DST_IP, 
                            argv[3], ACTION_ALLOW, 1);  // 1 = hex mode
        
    } else if (strcmp(command, "delete") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Usage: %s delete <ip/prefix>\n", argv[0]);
            return 1;
        }
        return delete_auth_rule(argv[2]);
        
    } else if (strcmp(command, "list") == 0) {
        return list_auth_rules();
        
    } else if (strcmp(command, "show-key") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Usage: %s show-key <ip/prefix>\n", argv[0]);
            return 1;
        }
        return show_key(argv[2]);
        
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        print_usage(argv[0]);
        return 1;
    }
    
    return 0;
}
