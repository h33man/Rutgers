#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdint.h>

// Vault / TLS includes
#include <curl/curl.h>
#include <cjson/cJSON.h>

// Vault / TLS constants
#define VAULT_CERT_DIR        "/etc/liha/certs"
#define VAULT_CA              VAULT_CERT_DIR "/ca.pem"
#define VAULT_CLIENT_CRT      VAULT_CERT_DIR "/client.pem"
#define VAULT_CLIENT_KEY      VAULT_CERT_DIR "/client-key.pem"
#define VAULT_SECRET_PFX      "v1/secret/data/networks"
#define VAULT_KEY_FIELD       "key"
#define VAULT_CONN_TIMEOUT_S  5L
#define VAULT_TOTAL_TIMEOUT_S 10L

struct ipv4_lpm_key {
    uint32_t prefixlen;
    uint32_t data;
};

// Vault helper types

// Growing buffer used as libcurl write target
struct vault_response {
    char  *data;
    size_t size;
};

// Convert IP address string to network byte order
static int parse_ip_prefix(const char *ip_str, struct ipv4_lpm_key *key) {
    char *ip_copy = strdup(ip_str);
    char *prefix_len_str = strchr(ip_copy, '/');

    if (prefix_len_str) {
        *prefix_len_str = '\0';
        prefix_len_str++;
        key->prefixlen = (uint8_t)atoi(prefix_len_str);
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

// libcurl write callback appends received bytes to vault_response buffer.
static size_t vault_write_cb(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t incoming    = size * nmemb;
    struct vault_response *resp = (struct vault_response *)userdata;

    char *tmp = realloc(resp->data, resp->size + incoming + 1);
    if (!tmp) {
        fprintf(stderr, "ERROR: Out of memory in vault_write_cb\n");
        return 0;
    }
    resp->data = tmp;
    memcpy(resp->data + resp->size, ptr, incoming);
    resp->size += incoming;
    resp->data[resp->size] = '\0';
    return incoming;
}

// Apply the three TLS cert options that are common to every Vault request.
static CURLcode vault_set_tls(CURL *curl) {
    CURLcode rc;
    if ((rc = curl_easy_setopt(curl, CURLOPT_CAINFO,   VAULT_CA))         != CURLE_OK) return rc;
    if ((rc = curl_easy_setopt(curl, CURLOPT_SSLCERT,  VAULT_CLIENT_CRT)) != CURLE_OK) return rc;
    if ((rc = curl_easy_setopt(curl, CURLOPT_SSLKEY,   VAULT_CLIENT_KEY)) != CURLE_OK) return rc;
    if ((rc = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L))         != CURLE_OK) return rc;
    if ((rc = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L))         != CURLE_OK) return rc;
    return CURLE_OK;
}

/* POST to /v1/auth/cert/login. Returns 0 on success, -1 on error. */
static int vault_authenticate(const char *vault_url,
                              char *token_out, size_t token_out_size) {
    CURL   *curl = NULL;
    CURLcode rc;
    long   http_code = 0;
    int    ret = -1;

    struct vault_response resp = { .data = NULL, .size = 0 };

    char url[512];
    snprintf(url, sizeof(url), "%s/v1/auth/cert/login", vault_url);

    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "ERROR: curl_easy_init failed\n");
        return -1;
    }

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
    ret = 0;

out:
    curl_easy_cleanup(curl);
    free(resp.data);
    return ret;
}

/* GET /v1/secret/data/networks/<network>/<prefixlen>.
   Returns 0 on success, -1 on error, -2 on key expiry. */
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

    char url[512];
    snprintf(url, sizeof(url), "%s/%s/%s/%d",
             vault_url, VAULT_SECRET_PFX, network_str, prefixlen);

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

    if (http_code == 404) {
        fprintf(stderr, "ERROR: Key for %s/%d has expired or does not exist in Vault "
                        "(24-hour TTL elapsed or key never written)\n",
                        network_str, prefixlen);
        ret = -2;
        goto out;
    }

    if (http_code != 200) {
        fprintf(stderr, "ERROR: Vault secret request returned HTTP %ld\n", http_code);
        if (resp.data) fprintf(stderr, "       Response: %s\n", resp.data);
        goto out;
    }

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
    ret = 0;

out:
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(resp.data);
    return ret;
}

/* Fetch key from Vault for the given IP prefix and print it.
   Returns 0 on success, -1 on error, -2 on key expiry. */
static int fetch_and_print_key(const char *ip_prefix, const char *vault_url) {
    char token[512]   = {0};
    char hex_key[256] = {0};

    struct ipv4_lpm_key lpm_key;
    if (parse_ip_prefix(ip_prefix, &lpm_key) < 0) {
        return -1;
    }

    uint32_t mask_host = (lpm_key.prefixlen == 0)
                         ? 0u
                         : (0xFFFFFFFFu << (32u - lpm_key.prefixlen));
    uint32_t network_addr = lpm_key.data & htonl(mask_host);

    struct in_addr net;
    net.s_addr = network_addr;
    const char *network_str = inet_ntoa(net);

    printf("Fetching key from Vault for network %s/%u\n",
           network_str, lpm_key.prefixlen);

    curl_global_init(CURL_GLOBAL_DEFAULT);

    if (vault_authenticate(vault_url, token, sizeof(token)) < 0) {
        fprintf(stderr, "ERROR: Failed to authenticate to Vault at %s\n", vault_url);
        curl_global_cleanup();
        return -1;
    }
    printf("Vault authentication successful\n");

    int fetch_rc = vault_fetch_key(vault_url, token,
                                   network_str, (int)lpm_key.prefixlen,
                                   hex_key, sizeof(hex_key));
    curl_global_cleanup();

    if (fetch_rc == -2) {
        return -2;
    }
    if (fetch_rc < 0) {
        fprintf(stderr, "ERROR: Failed to fetch key from Vault\n");
        return -1;
    }

    printf("Key fetched successfully\n");
    printf("Key (hex): %s\n", hex_key);

    return 0;
}

static void print_usage(const char *prog_name) {
    printf("Usage: %s <ip/prefix> <vault_url>\n\n", prog_name);
    printf("  Fetches the key for the given IP prefix from Vault and prints it.\n\n");
    printf("Arguments:\n");
    printf("  <ip/prefix>   IP prefix (e.g. 192.168.100.2/24)\n");
    printf("  <vault_url>   Vault server URL (e.g. https://192.168.100.3:8200)\n\n");
    printf("Examples:\n");
    printf("  %s 192.168.100.2/24 https://192.168.100.3:8200\n", prog_name);
    printf("  %s 10.0.0.1/8 https://vault.example.com:8200\n", prog_name);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        print_usage(argv[0]);
        return 1;
    }

    const char *ip_prefix = argv[1];
    const char *vault_url = argv[2];

    int rc = fetch_and_print_key(ip_prefix, vault_url);
    if (rc == -2) {
        fprintf(stderr, "ERROR: Key has expired. "
                        "Wait for the daemon to write a new key and retry.\n");
        return 1;
    }
    return (rc == 0) ? 0 : 1;
}
