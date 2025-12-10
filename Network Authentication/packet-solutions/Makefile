# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
#CFLAGS += -DBPF_DEBUG
#EXTRA_CFLAGS += -DBPF_DEBUG

XDP_TARGETS  := tc_prog_kern_02 xdp_prog_kern_05 
USER_TARGETS := xdp_prog_user xdp_bpf_user xdp_use_kfunc

COMMON_DIR := ../common

COPY_LOADER := xdp-loader
COPY_STATS  := xdp_stats
EXTRA_DEPS  := $(COMMON_DIR)/parsing_helpers.h

COMMON_OBJS := $(COMMON_DIR)/common_user_bpf_xdp.o
include $(COMMON_DIR)/common.mk
