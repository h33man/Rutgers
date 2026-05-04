# Makefile for sha256_kfunc
obj-m := sha256_kfunc.o chacha20_kfunc.o sha256_crypto.o

KBUILD_CFLAGS += -g

KDIR := /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD)

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

