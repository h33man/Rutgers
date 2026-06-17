# Makefile — crypto kfunc kernel modules
#
# Builds four separate .ko files, each matching the chacha20_kfunc.c style:
#
#   sha256_crypto.ko   — SHA-256 keyed hash (Crypto API, SIMD-accelerated)
#   sha512_crypto.ko   — SHA-512 keyed hash (Crypto API, SIMD-accelerated)
#   hmac_crypto.ko     — HMAC-SHA256 + HMAC-SHA512 (Crypto API, SIMD-accelerated)
#   blake3_kfunc.ko   — BLAKE3 hash (self-contained scalar C, no Crypto API)
#
# Usage:
#   make all                     # build all four modules
#   make sha256                  # build only sha256_crypto.ko
#   make sha512                  # build only sha512_crypto.ko
#   make hmac                    # build only hmac_crypto.ko
#   make blake3                  # build only blake3_kfunc.ko
#   make clean                   # remove build artefacts
#   make KDIR=/path/to/kernel    # override kernel source directory
#
# Each module can be loaded independently:
#   insmod sha256_crypto.ko
#   insmod sha512_crypto.ko
#   insmod hmac_crypto.ko
#   insmod blake3_kfunc.ko

KDIR ?= /lib/modules/$(shell uname -r)/build

# --------------------------------------------------------------------------
# Module definitions — each obj-m entry builds one .ko
# --------------------------------------------------------------------------
obj-m += sha256_kfunc.o
obj-m += chacha20_kfunc.o
obj-m += sha256_crypto.o
obj-m += sha512_crypto.o
obj-m += hmac_crypto.o
obj-m += blake3_kfunc.o

# --------------------------------------------------------------------------
# Compiler flags
# --------------------------------------------------------------------------
# -Wmissing-prototypes: suppressed via __bpf_kfunc_start/end_defs() inside
# each source file, but we add it globally so non-kfunc functions are still
# checked.
ccflags-y := -Wall -Wmissing-prototypes

# --------------------------------------------------------------------------
# Top-level targets
# --------------------------------------------------------------------------
.PHONY: all sha256_kfunc chacha20_kfunc sha256 sha512 hmac blake3 clean modules_install

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Per-module convenience targets — build only the requested .ko
sha256_kfunc:
	$(MAKE) -C $(KDIR) M=$(PWD) sha256_kfunc.ko

chacha20_kfunc:
	$(MAKE) -C $(KDIR) M=$(PWD) chacha20_kfunc.ko

sha256:
	$(MAKE) -C $(KDIR) M=$(PWD) sha256_crypto.ko

sha512:
	$(MAKE) -C $(KDIR) M=$(PWD) sha512_crypto.ko

hmac:
	$(MAKE) -C $(KDIR) M=$(PWD) hmac_crypto.ko

blake3:
	$(MAKE) -C $(KDIR) M=$(PWD) blake3_kfunc.ko

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# Install all built modules to the running kernel's extra modules directory.
# Run as root or with sudo.
modules_install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
