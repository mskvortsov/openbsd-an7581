#!/bin/sh
# Boot an OpenBSD/arm64 kernel on yasnogor via kexec.
#   obsd-boot.sh [obsdkexec options] /tmp/bsd.rd
# Loads first, so a bad kernel or a kexec-less Linux fails while the
# watchdog is still on and OpenWrt is still fully up.
set -e
cd "$(dirname "$0")"

# Hand Linux's MACs to aireth(4): GDM1 is eth0 (the switch conduit),
# GDM4 is lan1 (WAN; the ISP may know it).
macs=
for map in eth0:ethernet@1 lan1:ethernet@4; do
	ifc=${map%%:*} node=${map#*:}
	[ -r /sys/class/net/$ifc/address ] &&
	    macs="$macs -m /soc/ethernet@1fb50000/$node=$(cat /sys/class/net/$ifc/address)"
done

./obsdkexec $macs "$@"

# procd feeds the hardware watchdog (24 s); OpenBSD has no driver for it.
# Magic close lets airoha_wdt actually stop the timer when procd lets go.
ubus call system watchdog '{"magicclose": true}' >/dev/null
ubus call system watchdog '{"stop": true}' >/dev/null
sleep 1
# "offline": procd wrote 'V' and closed /dev/watchdog, so the kernel
# stopped the timer.  "stopped" would mean the fd is still held open.
ubus call system watchdog | grep -q '"offline"' || {
	echo "watchdog still running, not jumping" >&2
	exit 1
}

# Removing fw4's flowtable makes airoha_eth tear down the flows bound in
# the PPE; aireth(4) keeps the FE as Linux left it, so leave no offload
# state behind.  Not committed: OpenWrt boots with offload on again.
/etc/init.d/firewall stop
nft list flowtables 2>/dev/null | grep -q flowtable &&
    echo "warning: a flowtable is still loaded" >&2

# airoha_eth never stops its QDMAs, not even for kexec: rings stay posted
# with Linux buffers that become OpenBSD memory.  Taking a port down
# points its GDM forwarding at DROP, so no new frames reach them; aireth(4)
# then disables the rings.  Switch ports first, the conduit (eth0) last.
for i in /sys/class/net/*; do
	case "$(readlink "$i/device/driver" 2>/dev/null)" in
	*/mt7530-mmio) ip link set dev "${i##*/}" down ;;
	esac
done
ip link set dev eth0 down 2>/dev/null || :

echo "jumping to OpenBSD; watch the UART (115200 8N1)"
./obsdkexec -x
