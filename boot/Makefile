TOOLCHAIN ?= /w/openwrt-nokia/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.4.0_musl
CC = $(TOOLCHAIN)/bin/aarch64-openwrt-linux-musl-gcc
CFLAGS = -Os -Wall -Wextra -Wno-unused-parameter
LDFLAGS = -static -s

obsdkexec: obsdkexec.c
	STAGING_DIR=$(TOOLCHAIN) $(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f obsdkexec

.PHONY: clean
