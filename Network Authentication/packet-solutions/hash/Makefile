# Makefile — crypto kfunc kernel modules + XDP instrumentation programs
#
# Kernel modules (each from hash_kfunc.c with a different ALGO_ flag):
#   sha256_kfunc.ko   sha512_kfunc.ko   hmac_kfunc.ko
# Plus standalone:
#   blake3_kfunc.ko
#
# XDP BPF object files (each from xdp_hash_bench.c with a different ALGO_ flag):
#   xdp_sha256.o  xdp_sha512.o  xdp_hmac_sha256.o
#   xdp_hmac_sha512.o  xdp_blake3.o  xdp_pure_ebpf.o
#
# Usage:
#   make all                  # build everything
#   make modules              # kernel modules only
#   make xdp                  # XDP BPF objects only
#   make sha256               # sha256_kfunc.ko only
#   make xdp_sha256.o         # single XDP variant only
#   make load_sha256          # load XDP SHA-256 variant onto IFACE
#   make unload               # detach XDP from IFACE
#   make instrcount           # print verified instruction counts for all variants
#   make clean
#
# Variables:
#   KDIR   kernel source dir  (default: running kernel)
#   CLANG  clang binary       (default: clang)
#   IFACE  veth interface for load/unload targets (default: veth0)

KDIR   ?= /lib/modules/$(shell uname -r)/build
CLANG  ?= clang
IFACE  ?= veth0
PWD    := $(shell pwd)

# Kernel include paths for BPF program compilation
BPF_INCLUDES := -I/usr/include \
                -I/usr/include/x86_64-linux-gnu \
                -I$(PWD)/../../lib/install/include/ \
                -I$(PWD)/..

# Clang flags common to all XDP variants
BPF_CFLAGS := -O2 -g \
              -target bpf \
              -Wall \
              -DBPF_F_XDP_HAS_FRAGS \
              $(BPF_INCLUDES)

# --------------------------------------------------------------------------
# Top-level targets
# --------------------------------------------------------------------------
.PHONY: all modules xdp clean load_sha256 load_sha512 load_hmac_sha256 \
        load_hmac_sha512 load_blake3 load_pure_ebpf unload instrcount \
        sha256 sha512 hmac blake3 chacha20 kfunc_sha256

all: xdp #modules xdp

modules: sha256 sha512 hmac blake3

xdp: xdp_blank.o xdp_parse_only.o xdp_sha256.o xdp_sha512.o \
     xdp_hmac_sha256.o xdp_hmac_sha512.o xdp_blake3.o \
     xdp_chacha20.o xdp_kfunc_sha256.o \
     xdp_pure_ebpf.o xdp_packet_resize.o

# --------------------------------------------------------------------------
# Kernel module targets — one build/ subdir per algo, each with its Kbuild
# --------------------------------------------------------------------------
sha256: $(PWD)/build/sha256/Kbuild
	$(MAKE) -C $(KDIR) M=$(PWD)/build/sha256 modules

sha512: $(PWD)/build/sha512/Kbuild
	$(MAKE) -C $(KDIR) M=$(PWD)/build/sha512 modules

hmac: $(PWD)/build/hmac/Kbuild
	$(MAKE) -C $(KDIR) M=$(PWD)/build/hmac modules

blake3: $(PWD)/build/blake3/Kbuild
	$(MAKE) -C $(KDIR) M=$(PWD)/build/blake3 modules

$(PWD)/build/sha256/Kbuild:
	mkdir -p $(PWD)/build/sha256
	ln -sf $(PWD)/hash_kfunc.c $(PWD)/build/sha256/sha256_kfunc.c
	printf 'ccflags-y := -DALGO_SHA256\nobj-m     := sha256_kfunc.o\n' > $@

$(PWD)/build/sha512/Kbuild:
	mkdir -p $(PWD)/build/sha512
	ln -sf $(PWD)/hash_kfunc.c $(PWD)/build/sha512/sha512_kfunc.c
	printf 'ccflags-y := -DALGO_SHA512\nobj-m     := sha512_kfunc.o\n' > $@

$(PWD)/build/hmac/Kbuild:
	mkdir -p $(PWD)/build/hmac
	ln -sf $(PWD)/hash_kfunc.c $(PWD)/build/hmac/hmac_kfunc.c
	printf 'ccflags-y := -DALGO_HMAC\nobj-m     := hmac_kfunc.o\n' > $@

$(PWD)/build/blake3/Kbuild:
	mkdir -p $(PWD)/build/blake3
	ln -sf $(PWD)/blake3_kfunc.c $(PWD)/build/blake3/blake3_kfunc.c
	printf 'ccflags-y :=\nobj-m     := blake3_kfunc.o\n' > $@

# --------------------------------------------------------------------------
# XDP BPF object targets — one .o per algo variant
# --------------------------------------------------------------------------
xdp_blank.o: xdp_hash_bench.c
	$(CLANG) $(BPF_CFLAGS) -DALGO_BLANK -o $@ -c $<

xdp_parse_only.o: xdp_hash_bench.c
	$(CLANG) $(BPF_CFLAGS) -DALGO_PARSE_ONLY -o $@ -c $<

xdp_sha256.o: xdp_hash_bench.c
	$(CLANG) $(BPF_CFLAGS) -DALGO_SHA256 -o $@ -c $<

xdp_sha512.o: xdp_hash_bench.c
	$(CLANG) $(BPF_CFLAGS) -DALGO_SHA512 -o $@ -c $<

xdp_hmac_sha256.o: xdp_hash_bench.c
	$(CLANG) $(BPF_CFLAGS) -DALGO_HMAC_SHA256 -o $@ -c $<

xdp_hmac_sha512.o: xdp_hash_bench.c
	$(CLANG) $(BPF_CFLAGS) -DALGO_HMAC_SHA512 -o $@ -c $<

xdp_blake3.o: xdp_hash_bench.c
	$(CLANG) $(BPF_CFLAGS) -DALGO_BLAKE3 -o $@ -c $<

xdp_chacha20.o: xdp_hash_bench.c
	$(CLANG) $(BPF_CFLAGS) -DALGO_CHACHA20 -o $@ -c $<

xdp_kfunc_sha256.o: xdp_hash_bench.c
	$(CLANG) $(BPF_CFLAGS) -DALGO_KFUNC_SHA256 -o $@ -c $<

xdp_pure_ebpf.o: xdp_hash_bench.c
	$(CLANG) $(BPF_CFLAGS) -DALGO_PURE_EBPF -o $@ -c $<

xdp_packet_resize.o: xdp_hash_bench.c
	$(CLANG) $(BPF_CFLAGS) -DALGO_PACKET_RESIZE -o $@ -c $<

# --------------------------------------------------------------------------
# Load / unload helpers — pin each program under /sys/fs/bpf/ so
# bpftool can inspect it after attachment.
# Run as root.
# --------------------------------------------------------------------------
load_sha256: xdp_sha256.o
	bpftool prog load $< /sys/fs/bpf/xdp_hash_bench
	bpftool net attach xdp pinned /sys/fs/bpf/xdp_hash_bench dev $(IFACE)

load_sha512: xdp_sha512.o
	bpftool prog load $< /sys/fs/bpf/xdp_hash_bench
	bpftool net attach xdp pinned /sys/fs/bpf/xdp_hash_bench dev $(IFACE)

load_hmac_sha256: xdp_hmac_sha256.o
	bpftool prog load $< /sys/fs/bpf/xdp_hash_bench
	bpftool net attach xdp pinned /sys/fs/bpf/xdp_hash_bench dev $(IFACE)

load_hmac_sha512: xdp_hmac_sha512.o
	bpftool prog load $< /sys/fs/bpf/xdp_hash_bench
	bpftool net attach xdp pinned /sys/fs/bpf/xdp_hash_bench dev $(IFACE)

load_blake3: xdp_blake3.o
	bpftool prog load $< /sys/fs/bpf/xdp_hash_bench
	bpftool net attach xdp pinned /sys/fs/bpf/xdp_hash_bench dev $(IFACE)

load_chacha20: xdp_chacha20.o
	bpftool prog load $< /sys/fs/bpf/xdp_hash_bench
	bpftool net attach xdp pinned /sys/fs/bpf/xdp_hash_bench dev $(IFACE)

load_kfunc_sha256: xdp_kfunc_sha256.o
	bpftool prog load $< /sys/fs/bpf/xdp_hash_bench
	bpftool net attach xdp pinned /sys/fs/bpf/xdp_hash_bench dev $(IFACE)

load_pure_ebpf: xdp_pure_ebpf.o
	bpftool prog load $< /sys/fs/bpf/xdp_hash_bench
	bpftool net attach xdp pinned /sys/fs/bpf/xdp_hash_bench dev $(IFACE)

unload:
	bpftool net detach xdp dev $(IFACE) || true
	rm -f /sys/fs/bpf/xdp_hash_bench

# --------------------------------------------------------------------------
# instrcount — load each variant, print BPF instruction count and verifier
# steps for each variant. Produces the measurement table for the paper.
#
# Prerequisites (run as root before this target):
#   insmod build/sha256/sha256_kfunc.ko
#   insmod build/sha512/sha512_kfunc.ko
#   insmod build/hmac/hmac_kfunc.ko
#   insmod build/blake3/blake3_kfunc.ko
#
# The kfunc .ko files MUST be loaded or the verifier will reject the
# kfunc variants and report incorrect (truncated) instruction counts.
# --------------------------------------------------------------------------
instrcount: xdp
	@echo ""
	@echo "Checking kfunc modules are loaded..."
	@for mod in sha256_crypto sha512_crypto hmac_crypto blake3_kfunc; do \
	    if ! lsmod | grep -q "^$$mod"; then \
	        echo "WARNING: $$mod not loaded — kfunc variants will show wrong counts"; \
	    else \
	        echo "  OK: $$mod"; \
	    fi; \
	done
	@echo ""
	@echo "Verified instruction counts — xdp_hash_bench variants"
	@echo "======================================================="
	@# Mount bpffs if not already mounted
	@mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
	@printf "%-24s  %6s  %14s\n" "Variant" "BPF insns" "Verifier steps"; \
	printf "%-24s  %6s  %14s\n" "-------" "---------" "--------------"
	@for obj in xdp_blank.o xdp_parse_only.o xdp_sha256.o xdp_sha512.o \
	            xdp_hmac_sha256.o xdp_hmac_sha512.o xdp_blake3.o \
	            xdp_pure_ebpf.o xdp_packet_resize.o; do \
	    pin=/sys/fs/bpf/xdp_bench_tmp; \
	    rm -f $$pin; \
	    if [ "$$obj" = "xdp_pure_ebpf.o" ] || [ "$$obj" = "xdp_blank.o" ] || [ "$$obj" = "xdp_parse_only.o" ] || [ "$$obj" = "xdp_packet_resize.o" ]; then \
	        bpftool -d prog load $$obj $$pin 2>bpftool_err.txt; \
	    else \
	        mapdir=/sys/fs/bpf/xdp_bench_maps_tmp; \
	        rm -rf $$mapdir && mkdir -p $$mapdir; \
	        bpftool -d prog load $$obj $$pin pinmaps $$mapdir 2>bpftool_err.txt; \
	        rm -rf $$mapdir; \
	    fi; \
	    if [ -e $$pin ]; then \
	        count=$$(bpftool prog dump xlated pinned $$pin | \
	                 grep -c "^[[:space:]]*[0-9]\+:"); \
	        vsteps=$$(grep -oP 'processed \K[0-9]+' bpftool_err.txt | tail -1); \
	        printf "%-24s  %6d  %14s\n" $$obj $$count $${vsteps:--}; \
	        rm -f $$pin; \
	    else \
	        printf "%-24s  FAILED TO LOAD:\n" $$obj; \
	        grep -v 'libbpf\|Warning\|debug' bpftool_err.txt | tail -3 | sed 's/^/    /'; \
	    fi; \
	done
	@echo ""

# --------------------------------------------------------------------------
# diagload — load a single variant with full verifier output for debugging.
# Usage: make diagload OBJ=xdp_sha256.o
# --------------------------------------------------------------------------
diagload:
	@test -n "$(OBJ)" || (echo "Usage: make diagload OBJ=xdp_sha256.o"; exit 1)
	@mapdir=/sys/fs/bpf/xdp_diag_maps; \
	 rm -rf $$mapdir && mkdir -p $$mapdir; \
	 bpftool -d prog load $(OBJ) /sys/fs/bpf/xdp_diag_tmp \
	        pinmaps $$mapdir 2>&1; \
	 rm -f /sys/fs/bpf/xdp_diag_tmp; \
	 rm -rf $$mapdir

# --------------------------------------------------------------------------
clean:
	$(MAKE) -C $(KDIR) M=$(PWD)/build/sha256 clean 2>/dev/null || true
	$(MAKE) -C $(KDIR) M=$(PWD)/build/sha512 clean 2>/dev/null || true
	$(MAKE) -C $(KDIR) M=$(PWD)/build/hmac   clean 2>/dev/null || true
	$(MAKE) -C $(KDIR) M=$(PWD)/build/blake3 clean 2>/dev/null || true
	rm -f xdp_*.o bpftool_err.txt
