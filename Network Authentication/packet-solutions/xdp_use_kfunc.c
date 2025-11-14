/*
 * toggle_kfunc_final.c - Final working version using raw buffer approach
 * 
 * This is modeled after the working approach in xdp_bpf_user.c:
 * Only read/write using simple types and raw buffers.
 * 
 * Compile: gcc -o toggle_kfunc toggle_kfunc_final.c -lbpf
 * Usage: ./toggle_kfunc <map_name> [0|1]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define BPF_MAP_DIR "/sys/fs/bpf"

void print_usage(const char *prog_name)
{
    printf("Usage: %s <map_name> [0|1]\n", prog_name);
    printf("  map_name: Name of the BPF map (e.g., 'verify_map')\n");
    printf("  0|1:      0 = use custom SHA256, 1 = use kfunc SHA256\n");
    printf("\nExamples:\n");
    printf("  %s verify_map 1        # Enable kfunc SHA256\n", prog_name);
    printf("  %s verify_map 0        # Use custom SHA256\n", prog_name);
    printf("  %s verify_map          # Show current setting\n", prog_name);
}

// Find existing BPF map by name (borrowed from xdp_bpf_user.c)
static int find_bpf_map(const char *map_name) {
    __u32 map_id = 0;
    
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

int main(int argc, char **argv)
{
    int map_fd;
    unsigned int key = 0;
    unsigned char new_use_kfunc;
    unsigned char *value_buffer;
    struct bpf_map_info info = {};
    __u32 info_len = sizeof(info);

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *map_name = argv[1];

    // Determine the use_kfunc value
    if (argc >= 3) {
        new_use_kfunc = atoi(argv[2]);
        //if (new_use_kfunc != 0 && new_use_kfunc != 1) {
        if (new_use_kfunc > 255) {
            fprintf(stderr, "Error: use_kfunc must be 0 or 1\n");
            return 1;
        }
    } else {
        new_use_kfunc = 0xFF; // Sentinel for read-only
    }

    // Find the map (like the working xdp_bpf_user.c does)
    map_fd = find_bpf_map(map_name);
    if (map_fd < 0) {
        fprintf(stderr, "Error: Could not find BPF map '%s'\n", map_name);
        fprintf(stderr, "Is the XDP program loaded?\n");
        return 1;
    }

    // Get map info for the value size
    if (bpf_obj_get_info_by_fd(map_fd, &info, &info_len) != 0) {
        fprintf(stderr, "Error: Could not get map info: %s\n", strerror(errno));
        close(map_fd);
        return 1;
    }

    printf("Map: %s\n", map_name);
    printf("  Type: %u\n", info.type);
    printf("  Key size: %u bytes\n", info.key_size);
    printf("  Value size: %u bytes\n", info.value_size);

    // Allocate raw buffer of exact value size
    value_buffer = malloc(info.value_size);
    if (!value_buffer) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        close(map_fd);
        return 1;
    }

    // Read entire value as raw bytes
    if (bpf_map_lookup_elem(map_fd, &key, value_buffer) != 0) {
        fprintf(stderr, "Error: Could not read from map: %s\n", strerror(errno));
        free(value_buffer);
        close(map_fd);
        return 1;
    }

    // The use_kfunc field is the LAST byte
    unsigned char current_use_kfunc = value_buffer[info.value_size - 1];

    printf("\nCurrent use_kfunc: %u\n", current_use_kfunc);
    if (current_use_kfunc) {
        printf("  -> Using kfunc SHA256\n");
    } else {
        printf("  -> Using custom SHA256\n");
    }

    if (new_use_kfunc != 0xFF) {
        // Modify the last byte
        value_buffer[info.value_size - 1] = new_use_kfunc;

        // Write entire value back
        if (bpf_map_update_elem(map_fd, &key, value_buffer, 0) != 0) {
            fprintf(stderr, "Error: Could not update map: %s\n", strerror(errno));
            free(value_buffer);
            close(map_fd);
            return 1;
        }

        printf("\nSuccessfully updated use_kfunc to: %u\n", new_use_kfunc);
        if (new_use_kfunc) {
            printf("  -> Now using kfunc SHA256\n");
        } else {
            printf("  -> Now using custom SHA256\n");
        }

        // Verify
        memset(value_buffer, 0, info.value_size);
        if (bpf_map_lookup_elem(map_fd, &key, value_buffer) == 0) {
            unsigned char verify_value = value_buffer[info.value_size - 1];
            if (verify_value == new_use_kfunc) {
                printf("Verification: Setting confirmed.\n");
            } else {
                printf("Warning: Verification failed.\n");
            }
        }
    }

    free(value_buffer);
    close(map_fd);
    return 0;
}
