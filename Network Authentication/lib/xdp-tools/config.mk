# Generated config
# user can control verbosity similar to kernel builds (e.g., V=1)
ifeq ("$(origin V)", "command line")
  VERBOSE = $(V)
endif
ifndef VERBOSE
  VERBOSE = 0
endif
ifeq ($(VERBOSE),1)
  Q =
else
  Q = @
endif
ifeq ($(VERBOSE),0)
MAKEFLAGS += --no-print-directory
endif


ifeq ($(VERBOSE), 0)
    QUIET_CC       = @echo '    CC       '$@;
    QUIET_CLANG    = @echo '    CLANG    '$@;
    QUIET_LLC      = @echo '    LLC      '$@;
    QUIET_LINK     = @echo '    LINK     '$@;
    QUIET_INSTALL  = @echo '    INSTALL  '$@;
    QUIET_M4       = @echo '    M4       '$@;
    QUIET_GEN      = @echo '    GEN      '$@;
endif
PRODUCTION:=0
DYNAMIC_LIBXDP:=0
MAX_DISPATCHER_ACTIONS:=10
BPF_TARGET:=bpf
PKG_CONFIG:=pkg-config
CC:=gcc
LD:=ld
OBJCOPY:=objcopy
CLANG:=clang
LLC:=llc
M4:=m4
EMACS:=
ARCH_INCLUDES:=-I/usr/include/x86_64-linux-gnu/ 
READELF:=readelf
BPFTOOL:=bpftool
HAVE_FEATURES+=BPFTOOL
HAVE_FEATURES+=LIBBPF_PERF_BUFFER__CONSUME
HAVE_FEATURES+=LIBBPF_BTF__LOAD_FROM_KERNEL_BY_ID
HAVE_FEATURES+=LIBBPF_BTF__TYPE_CNT
HAVE_FEATURES+=LIBBPF_BPF_OBJECT__NEXT_MAP
HAVE_FEATURES+=LIBBPF_BPF_OBJECT__NEXT_PROGRAM
HAVE_FEATURES+=LIBBPF_BPF_PROGRAM__INSN_CNT
HAVE_FEATURES+=LIBBPF_BPF_PROGRAM__TYPE
HAVE_FEATURES+=LIBBPF_BPF_PROGRAM__FLAGS
HAVE_FEATURES+=LIBBPF_BPF_PROGRAM__EXPECTED_ATTACH_TYPE
HAVE_FEATURES+=LIBBPF_BPF_MAP_CREATE
HAVE_FEATURES+=LIBBPF_PERF_BUFFER__NEW_RAW
HAVE_FEATURES+=LIBBPF_BPF_XDP_ATTACH
HAVE_FEATURES+=LIBBPF_BPF_MAP__SET_AUTOCREATE
HAVE_FEATURES+=LIBBPF_BPF_PROG_TEST_RUN_OPTS
HAVE_FEATURES+=LIBBPF_BPF_XDP_QUERY
SYSTEM_LIBBPF:=n
LIBBPF_VERSION=1.2.0
CFLAGS += -I/home/ubuntu/xdp-tutorial2/lib/install/include
BPF_CFLAGS += -I/home/ubuntu/xdp-tutorial2/lib/install/include
LDFLAGS += -L/home/ubuntu/xdp-tutorial2/lib/libbpf/src
LDLIBS += -l:libbpf.a
OBJECT_LIBBPF = 
HAVE_ZLIB:=y
CFLAGS += -DHAVE_ZLIB
LDLIBS +=  -lz
HAVE_ELF:=y
CFLAGS += -DHAVE_ELF
LDLIBS +=  -lelf
HAVE_PCAP:=y
HAVE_FEATURES += SECURE_GETENV
