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

// Vault / TLS includes
#include <curl/curl.h>
#include <cjson/cJSON.h>

// Vault / TLS constants
#define VAULT_CERT_DIR        "/etc/xdp/certs"
#define VAULT_CA              VAULT_CERT_DIR "/ca.pem"
#define VAULT_CLIENT_CRT      VAULT_CERT_DIR "/client.pem"
#define VAULT_CLIENT_KEY      VAULT_CERT_DIR "/client-key.pem"
#define VAULT_SECRET_PFX      "v1/secret/data/networks"
#define VAULT_KEY_FIELD       "key"
#define VAULT_CONN_TIMEOUT_S  5L
#define VAULT_TOTAL_TIMEOUT_S 10L

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

// Global variable for BPF map (only src_ip_key_map needed)
static int src_ip_key_map_fd = -1;

// Vault helper types

// Growing buffer used as libcurl write target
struct vault_response {
    char  *data;
    size_t size;
};

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
    src_ip_key_map_fd = find_bpf_map("src_ip_key_map");

    if (src_ip_key_map_fd < 0) {
        fprintf(stderr, "ERROR: Could not find src_ip_key_map. Is the BPF program loaded?\n");
        return -1;
    }

    printf("Connected to existing BPF map: src_auth_fd=%d\n", src_ip_key_map_fd);
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
    if (src_ip_key_map_fd < 0) {
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
    if (bpf_map_update_elem(src_ip_key_map_fd, &key, &auth_rule, BPF_ANY) != 0) {
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
    if (src_ip_key_map_fd < 0) {
        fprintf(stderr, "ERROR: Map not initialized\n");
        return -1;
    }

    if (parse_ip_prefix(ip_prefix, &key) < 0) {
        return -1;
    }

    if (bpf_map_delete_elem(src_ip_key_map_fd, &key) != 0) {
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
    if (src_ip_key_map_fd < 0) {
        fprintf(stderr, "ERROR: Map not initialized\n");
        return -1;
    }

    printf("\nSource IP Authentication Rules:\n");
    printf("%-18s %-4s %-10s %-8s\n", "PREFIX", "LEN", "FIELDS", "ACTION");
    printf("------------------------------------------------\n");

    // Iterate through all entries
    memset(&key, 0, sizeof(key));
    while (bpf_map_get_next_key(src_ip_key_map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(src_ip_key_map_fd, &next_key, &auth_rule) == 0) {
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
    if (src_ip_key_map_fd < 0) {
        fprintf(stderr, "ERROR: Map not initialized\n");
        return -1;
    }

    if (parse_ip_prefix(ip_prefix, &key) < 0) {
        return -1;
    }

    if (bpf_map_lookup_elem(src_ip_key_map_fd, &key, &auth_rule) != 0) {
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

// Vault fetch implementation

// libcurl write callback appends received bytes to vault_response buffer.
static size_t vault_write_cb(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t incoming    = size * nmemb;
    struct vault_response *resp = (struct vault_response *)userdata;

    char *tmp = realloc(resp->data, resp->size + incoming + 1);
    if (!tmp) {
        fprintf(stderr, "ERROR: Out of memory in vault_write_cb\n");
        return 0;   // returning 0 causes libcurl to abort
    }
    resp->data = tmp;
    memcpy(resp->data + resp->size, ptr, incoming);
    resp->size += incoming;
    resp->data[resp->size] = '\0';
    return incoming;
}

// Apply the three TLS cert options that are common to every Vault request.
// Returns CURLE_OK on success; the caller must check and abort on failure.
static CURLcode vault_set_tls(CURL *curl) {
    CURLcode rc;
    if ((rc = curl_easy_setopt(curl, CURLOPT_CAINFO,   VAULT_CA))         != CURLE_OK) return rc;
    if ((rc = curl_easy_setopt(curl, CURLOPT_SSLCERT,  VAULT_CLIENT_CRT)) != CURLE_OK) return rc;
    if ((rc = curl_easy_setopt(curl, CURLOPT_SSLKEY,   VAULT_CLIENT_KEY)) != CURLE_OK) return rc;
    // Enforce peer and host verification never disable these in production
    if ((rc = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L))         != CURLE_OK) return rc;
    if ((rc = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L))         != CURLE_OK) return rc;
    return CURLE_OK;
}

/* POST to /v1/auth/cert/login.
   On success writes a NUL-terminated token string into token_out
   (caller must supply a buffer of at least token_out_size bytes).
   Returns 0 on success, -1 on any error.
  
   Vault cert auth flow:
     1. libcurl performs a mutual-TLS handshake (client presents client.pem).
     2. Vault validates the cert against the registered CA / cert role.
     3. Vault returns a short-lived token in auth.client_token.
     4. We use that token for the subsequent secret GET.  */
static int vault_authenticate(const char *vault_url,
                              char *token_out, size_t token_out_size) {
    CURL   *curl = NULL;
    CURLcode rc;
    long   http_code = 0;
    int    ret = -1;

    struct vault_response resp = { .data = NULL, .size = 0 };

    // Build auth URL:  https://<host>:<port>/v1/auth/cert/login
    char url[512];
    snprintf(url, sizeof(url), "%s/v1/auth/cert/login", vault_url);

    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "ERROR: curl_easy_init failed\n");
        return -1;
    }

    // POST with an empty body the cert in the TLS handshake is the credential
    if ((rc = vault_set_tls(curl))                                              != CURLE_OK) goto out;
    if ((rc = curl_easy_setopt(curl, CURLOPT_URL,            url))              != CURLE_OK) goto out;
    if ((rc = curl_easy_setopt(curl, CURLOPT_POST,           1L))               != CURLE_OK) goto out;
    if ((rc = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,  0L))               != CURLE_OK) goto out;
    if ((rc = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  vault_write_cb))   != CURLE_OK) goto out;
    if ((rc = curl_easy_setopt(curl, CURLOPT_WRITEDATA,      &resp))            != CURLE_OK) goto out;
    if ((rc = curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, VAULT_CONN_TIMEOUT_S))  != CURLE_OK) goto out;
    if ((rc = curl_easy_setopt(curl, CURLOPT_TIMEOUT,        VAULT_TOTAL_TIMEOUT_S)) != CURLE_OK) goto out;

    rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        fprintf(stderr, "ERROR: Vault auth request failed: %s\n", curl_easy_strerror(rc));
        goto out;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != 200) {
        fprintf(stderr, "ERROR: Vault auth returned HTTP %ld\n", http_code);
        if (resp.data) fprintf(stderr, "       Response: %s\n", resp.data);
        goto out;
    }

    // Parse JSON: { "auth": { "client_token": "hvs.xxx" } }
    cJSON *root = cJSON_Parse(resp.data);
    if (!root) {
        fprintf(stderr, "ERROR: Failed to parse Vault auth JSON\n");
        goto out;
    }

    cJSON *auth  = cJSON_GetObjectItem(root, "auth");
    cJSON *token = auth ? cJSON_GetObjectItem(auth, "client_token") : NULL;

    if (!cJSON_IsString(token) || !token->valuestring || token->valuestring[0] == '\0') {
        fprintf(stderr, "ERROR: client_token not found in Vault auth response\n");
        cJSON_Delete(root);
        goto out;
    }

    if (strlen(token->valuestring) >= token_out_size) {
        fprintf(stderr, "ERROR: Vault token too long for buffer\n");
        cJSON_Delete(root);
        goto out;
    }

    strncpy(token_out, token->valuestring, token_out_size - 1);
    token_out[token_out_size - 1] = '\0';
    cJSON_Delete(root);
    ret = 0;    // success

out:
    curl_easy_cleanup(curl);
    free(resp.data);
    return ret;
}

/* GET /v1/secret/data/networks/<network>/<prefixlen> using the supplied token.
   On success writes the hex key string into key_out.
   Returns 0 on success, -1 on error, -2 specifically when the key has expired
   (Vault returns 404 because delete_version_after has elapsed). */
static int vault_fetch_key(const char *vault_url,
                           const char *token,
                           const char *network_str,
                           int         prefixlen,
                           char       *key_out,
                           size_t      key_out_size) {
    CURL   *curl = NULL;
    CURLcode rc;
    long   http_code = 0;
    int    ret = -1;

    struct vault_response resp = { .data = NULL, .size = 0 };
    struct curl_slist    *headers = NULL;

    // Build secret URL:
    //   https://<host>:<port>/v1/secret/data/networks/192.168.100.0/24
    char url[512];
    snprintf(url, sizeof(url), "%s/%s/%s/%d",
             vault_url, VAULT_SECRET_PFX, network_str, prefixlen);

    // Build X-Vault-Token header
    char token_header[512];
    snprintf(token_header, sizeof(token_header), "X-Vault-Token: %s", token);

    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "ERROR: curl_easy_init failed\n");
        return -1;
    }

    headers = curl_slist_append(headers, token_header);
    if (!headers) {
        fprintf(stderr, "ERROR: curl_slist_append failed\n");
        goto out;
    }

    if ((rc = vault_set_tls(curl))                                               != CURLE_OK) goto out;
    if ((rc = curl_easy_setopt(curl, CURLOPT_URL,            url))               != CURLE_OK) goto out;
    if ((rc = curl_easy_setopt(curl, CURLOPT_HTTPHEADER,     headers))           != CURLE_OK) goto out;
    if ((rc = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  vault_write_cb))    != CURLE_OK) goto out;
    if ((rc = curl_easy_setopt(curl, CURLOPT_WRITEDATA,      &resp))             != CURLE_OK) goto out;
    if ((rc = curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, VAULT_CONN_TIMEOUT_S))  != CURLE_OK) goto out;
    if ((rc = curl_easy_setopt(curl, CURLOPT_TIMEOUT,        VAULT_TOTAL_TIMEOUT_S)) != CURLE_OK) goto out;

    rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        fprintf(stderr, "ERROR: Vault secret request failed: %s\n", curl_easy_strerror(rc));
        goto out;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    // 404 means Vault deleted the secret after delete_version_after elapsed
    if (http_code == 404) {
        fprintf(stderr, "ERROR: Key for %s/%d has expired or does not exist in Vault "
                        "(24-hour TTL elapsed or key never written)\n",
                        network_str, prefixlen);
        ret = -2;   // distinct return for expiry so caller can give a clear message
        goto out;
    }

    if (http_code != 200) {
        fprintf(stderr, "ERROR: Vault secret request returned HTTP %ld\n", http_code);
        if (resp.data) fprintf(stderr, "       Response: %s\n", resp.data);
        goto out;
    }

    // KV v2 response structure:
    // {
    //   "data": {
    //     "data": {
    //       "key": "<32 hex chars>"
    //     },
    //     "metadata": { ... }
    //   }
    // }
    cJSON *root = cJSON_Parse(resp.data);
    if (!root) {
        fprintf(stderr, "ERROR: Failed to parse Vault secret JSON\n");
        goto out;
    }

    cJSON *outer_data = cJSON_GetObjectItem(root, "data");
    cJSON *inner_data = outer_data ? cJSON_GetObjectItem(outer_data, "data") : NULL;
    cJSON *key_field  = inner_data ? cJSON_GetObjectItem(inner_data, VAULT_KEY_FIELD) : NULL;

    if (!cJSON_IsString(key_field) || !key_field->valuestring || key_field->valuestring[0] == '\0') {
        fprintf(stderr, "ERROR: Field \"%s\" not found in Vault secret response\n", VAULT_KEY_FIELD);
        cJSON_Delete(root);
        goto out;
    }

    if (strlen(key_field->valuestring) >= key_out_size) {
        fprintf(stderr, "ERROR: Key value from Vault is too long for buffer\n");
        cJSON_Delete(root);
        goto out;
    }

    strncpy(key_out, key_field->valuestring, key_out_size - 1);
    key_out[key_out_size - 1] = '\0';
    cJSON_Delete(root);
    ret = 0;    // success

out:
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(resp.data);
    return ret;
}

/* fetch_key_from_vault() - public entry point called from main()
  
   1. Parses ip_prefix (e.g. "192.168.100.2/24") into a network address
      (192.168.100.0) and prefix length (24) for the Vault path.
   2. Authenticates to Vault using the client TLS certificate.
   3. Fetches the hex key for that network prefix.
   4. Calls the existing add_auth_rule() to load the key into the eBPF map.
  
   NOTE: auth_data.key is 16 bytes (32 hex chars) as defined in the existing
   struct.  The daemon must store a 32-character hex string (16 bytes) in Vault
   under the "key" field.  If you later extend the struct to 32 bytes, update
   parse_hex_key() and the key array size accordingly.
  
   Returns 0 on success, -1 on error, -2 on key expiry.  */
static int fetch_key_from_vault(const char *ip_prefix, const char *vault_url) {
    char token[512]   = {0};
    char hex_key[128] = {0};

    // Step 1: derive network address from the user-supplied prefix 
    // The user may pass a host address (192.168.100.2/24).  We mask off the
    // host bits to get the canonical network address (192.168.100.0) that the
    // daemon used as the Vault path.
    struct ipv4_lpm_key lpm_key;
    if (parse_ip_prefix(ip_prefix, &lpm_key) < 0) {
        return -1;
    }

    // Build the network mask in network byte order, then AND with the address.
    // Special-case /0 (mask = 0x00000000) and /32 (mask = 0xFFFFFFFF).
    uint32_t mask_host = (lpm_key.prefixlen == 0)
                         ? 0u
                         : (0xFFFFFFFFu << (32u - lpm_key.prefixlen));
    uint32_t network_addr = lpm_key.data & htonl(mask_host);

    struct in_addr net;
    net.s_addr = network_addr;
    const char *network_str = inet_ntoa(net);   // e.g. "192.168.100.0"

    printf("Fetching key from Vault for network %s/%u\n",
           network_str, lpm_key.prefixlen);

    // Step 2: authenticate with TLS client certificate 
    curl_global_init(CURL_GLOBAL_DEFAULT);

    if (vault_authenticate(vault_url, token, sizeof(token)) < 0) {
        fprintf(stderr, "ERROR: Failed to authenticate to Vault at %s\n", vault_url);
        curl_global_cleanup();
        return -1;
    }
    printf("Vault authentication successful\n");

    // Step 3: fetch the secret 
    int fetch_rc = vault_fetch_key(vault_url, token,
                                   network_str, (int)lpm_key.prefixlen,
                                   hex_key, sizeof(hex_key));
    curl_global_cleanup();

    if (fetch_rc == -2) {
        // Expiry already reported inside vault_fetch_key()
        return -2;
    }
    if (fetch_rc < 0) {
        fprintf(stderr, "ERROR: Failed to fetch key from Vault\n");
        return -1;
    }

    printf("Key fetched from Vault successfully\n");

    // Step 4: load key into eBPF map via existing add_auth_rule() 
    // Pass is_hex_key=1 so add_auth_rule() calls parse_hex_key() on the value.
    return add_auth_rule(ip_prefix,
                         FIELD_SRC_IP | FIELD_DST_IP,
                         hex_key,
                         ACTION_ALLOW,
                         1 /* is_hex_key */);
}

static void print_usage(const char *prog_name) {
    printf("Usage: %s <command> [options]\n\n", prog_name);
    printf("Commands:\n");
    printf("  init                                    Find and connect to existing BPF maps\n");
    printf("  add <ip/prefix> <password>              Add rule with password-based key\n");
    printf("  add-hex <ip/prefix> <hex_key>           Add rule with 32-char hex key\n");
    printf("  add-key <ip/prefix> <vault_url>         Fetch key from Vault and add rule\n");
    printf("  delete <ip/prefix>                      Delete authentication rule\n");
    printf("  list                                    List all authentication rules\n");
    printf("  show-key <ip/prefix>                    Show hex key for specific rule\n");
    printf("\nExamples:\n");
    printf("  %s init\n", prog_name);
    printf("  %s add 192.168.1.0/24 mypassword\n", prog_name);
    printf("  %s add-hex 10.0.0.0/8 abcdef0123456789abcdef0123456789\n", prog_name);
    printf("  %s add-key 192.168.100.2/24 https://192.168.100.3:8200\n", prog_name);
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
            fprintf(stderr, "Note: hex_key must be exactly 32 hex characters (16 bytes)\n");
            return 1;
        }
        return add_auth_rule(argv[2], FIELD_SRC_IP | FIELD_DST_IP,
                            argv[3], ACTION_ALLOW, 1);  // 1 = hex mode

    } else if (strcmp(command, "add-key") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Usage: %s add-key <ip/prefix> <vault_url>\n", argv[0]);
            fprintf(stderr, "  e.g. %s add-key 192.168.100.2/24 https://192.168.100.3:8200\n",
                    argv[0]);
            return 1;
        }
        int rc = fetch_key_from_vault(argv[2], argv[3]);
        if (rc == -2) {
            fprintf(stderr, "ERROR: Key has expired. "
                            "Wait for the daemon to write a new key and retry.\n");
            return 1;
        }
        return (rc == 0) ? 0 : 1;

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
