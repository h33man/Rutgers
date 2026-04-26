// xdp_loader.c - Loads XDP program with BPF_F_XDP_HAS_FRAGS for jumbo frame (9000 MTU) support
// Usage: sudo ./xdp_loader <iface> <attach|detach>
// Example: sudo ./xdp_loader enp175s0f0np0 attach

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>

#define OBJ_FILE        "xdp_prog_kern_05.o"
#define PROG_NAME       "xdp_ip_hash_verify_func"
#define PIN_PATH        "/sys/fs/bpf/xdp_verify"

static int do_attach(const char *iface)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    int prog_fd = -1;
    int ifindex, err;

    ifindex = if_nametoindex(iface);
    if (!ifindex) {
        fprintf(stderr, "Error: interface '%s' not found: %s\n",
                iface, strerror(errno));
        return 1;
    }

    obj = bpf_object__open(OBJ_FILE);
    if (!obj) {
        fprintf(stderr, "Error: failed to open %s: %s\n",
                OBJ_FILE, strerror(errno));
        return 1;
    }

    // Set type + flags on ALL programs in the object before load.
    // Required because our SEC names are non-standard (e.g. "xdp_ip_hash_verify")
    // so libbpf can't auto-detect the program type from the section name.
    struct bpf_program *p;
    bpf_object__for_each_program(p, obj) {
        bpf_program__set_type(p, BPF_PROG_TYPE_XDP);
        bpf_program__set_expected_attach_type(p, BPF_XDP);
    }

    prog = bpf_object__find_program_by_name(obj, PROG_NAME);
    if (!prog) {
        fprintf(stderr, "Error: program '%s' not found in %s\n",
                PROG_NAME, OBJ_FILE);
        bpf_object__close(obj);
        return 1;
    }

    // KEY FLAG: marks the program as multi-buffer/fragment aware.
    // This is what the mlx5 driver checks for MTU > 3458 (jumbo frames).
    // Must be set AFTER set_type() and BEFORE bpf_object__load().
    err = bpf_program__set_flags(prog, BPF_F_XDP_HAS_FRAGS);
    if (err) {
        fprintf(stderr, "Error: failed to set BPF_F_XDP_HAS_FRAGS: %s\n",
                strerror(-err));
        bpf_object__close(obj);
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Error: failed to load BPF object: %s\n",
                strerror(-err));
        bpf_object__close(obj);
        return 1;
    }

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Error: invalid program fd\n");
        bpf_object__close(obj);
        return 1;
    }

    // Pin the program so it stays loaded after this process exits
    err = bpf_obj_pin(prog_fd, PIN_PATH);
    if (err) {
        fprintf(stderr, "Warning: failed to pin program to %s: %s\n",
                PIN_PATH, strerror(errno));
        // Non-fatal, continue with attach
    } else {
        printf("Program pinned at %s\n", PIN_PATH);
    }

    // Attach in native (driver) mode - XDP_FLAGS_DRV_MODE
    err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE, NULL);
    if (err) {
        fprintf(stderr, "Error: native XDP attach failed: %s\n",
                strerror(-err));
        fprintf(stderr, "Trying generic (skb) mode...\n");

        // Fallback to generic mode
        err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
        if (err) {
            fprintf(stderr, "Error: generic XDP attach also failed: %s\n",
                    strerror(-err));
            bpf_object__close(obj);
            return 1;
        }
        printf("Attached in GENERIC (skb) mode to %s\n", iface);
    } else {
        printf("Attached in NATIVE (driver) mode to %s\n", iface);
    }

    bpf_object__close(obj);
    return 0;
}

static int do_detach(const char *iface)
{
    int ifindex, err;

    ifindex = if_nametoindex(iface);
    if (!ifindex) {
        fprintf(stderr, "Error: interface '%s' not found: %s\n",
                iface, strerror(errno));
        return 1;
    }

    // Try detaching both modes
    err = bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL);
    if (err)
        err = bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    if (err) {
        fprintf(stderr, "Error: XDP detach failed: %s\n", strerror(-err));
        return 1;
    }

    // Remove pin
    remove(PIN_PATH);

    printf("Detached XDP from %s\n", iface);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <iface> <attach|detach>\n", argv[0]);
        fprintf(stderr, "Example: %s enp175s0f0np0 attach\n", argv[0]);
        return 1;
    }

    const char *iface = argv[1];
    const char *cmd   = argv[2];

    if (strcmp(cmd, "attach") == 0)
        return do_attach(iface);
    else if (strcmp(cmd, "detach") == 0)
        return do_detach(iface);
    else {
        fprintf(stderr, "Error: unknown command '%s', use attach or detach\n", cmd);
        return 1;
    }
}
