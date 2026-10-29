#!/bin/sh
set -eux

ROOT=$(pwd)
SYS_URL=${OPENBSD_SYS_URL:-https://cdn.openbsd.org/pub/OpenBSD/8.0/sys.tar.gz}
WORK="$ROOT/work"
SRC="$WORK/src"
OBJ="$WORK/obj"
CC="clang-21 --target=aarch64-unknown-openbsd"
LD=ld.lld-21
JOBS=$(sysctl -n hw.ncpu)

mkdir -p "$WORK" "$ROOT/dist" "$OBJ"
ftp -o "$WORK/sys.tar.gz" "$SYS_URL"
mkdir -p "$SRC"
tar -xzf "$WORK/sys.tar.gz" -C "$SRC"
cd "$SRC/sys"
patch -p1 < "$ROOT/openbsd-an7581.patch"

cd "$SRC/sys/arch/arm64/conf"
config -b "$OBJ/RAMDISK" -s "$SRC/sys" RAMDISK
make -C "$OBJ/RAMDISK" -j"$JOBS" CC="$CC" LD="$LD" > "$OBJ/RAMDISK/build.log" 2>&1 || true
/usr/local/bin/llvm-objcopy-21 --strip-debug "$OBJ/RAMDISK/bsd.gdb" "$OBJ/RAMDISK/bsd"
cp "$OBJ/RAMDISK/bsd" "$ROOT/dist/bsd.rd"

ftp -o "$WORK/installer.bsd.rd" https://cdn.openbsd.org/pub/OpenBSD/8.0/arm64/bsd.rd
rdsetroot -x "$WORK/installer.bsd.rd" "$WORK/disk.fs"
# Add EN8811H firmware and its redistribution license to the installer's root.
mkdir -p "$WORK/mnt"
vnconfig vnd0 "$WORK/disk.fs"
mount /dev/vnd0a "$WORK/mnt"
install -d -o root -g wheel -m 755 "$WORK/mnt/etc/firmware/airoha"
install -o root -g wheel -m 644 \
    "$ROOT/firmware/airoha/EthMD32.dm.bin" \
    "$ROOT/firmware/airoha/EthMD32.DSP.bin" \
    "$WORK/mnt/etc/firmware/airoha/"
install -o root -g wheel -m 644 \
    "$ROOT/firmware/airoha/LICENSE.airoha" "$WORK/mnt/etc/firmware/airoha/"
umount "$WORK/mnt"
vnconfig -u vnd0
rdsetroot "$ROOT/dist/bsd.rd" "$WORK/disk.fs"

# The kexec-loaded kernel cannot rely on a boot loader to identify its root disk.
sed 's/^config[[:space:]]*bsd[[:space:]]*swap generic$/config bsd root on sd0a swap on sd0b/' \
    "$SRC/sys/arch/arm64/conf/GENERIC" > "$WORK/GENERIC"
mv "$WORK/GENERIC" "$SRC/sys/arch/arm64/conf/GENERIC"
config -b "$OBJ/GENERIC.MP" -s "$SRC/sys" GENERIC.MP
make -C "$OBJ/GENERIC.MP" -j"$JOBS" CC="$CC" LD="$LD" > "$OBJ/GENERIC.MP/build.log" 2>&1 || true
/usr/local/bin/llvm-objcopy-21 --strip-debug "$OBJ/GENERIC.MP/bsd.gdb" "$OBJ/GENERIC.MP/bsd"
cp "$OBJ/GENERIC.MP/bsd" "$ROOT/dist/bsd.mp"
