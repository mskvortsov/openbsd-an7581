# OpenBSD for AN7581

1. Copy the files to a router running OpenWrt:
- boot/obsd-boot.sh
- boot/obsdkexec
- bsd.rd and bsd.mp (from the Releases section)

2. Boot into an OpenBSD installer:
```
./obsd-boot.sh bsd.rd
```

Connect via UART and install the system onto a USB disk and reboot back into OpenWrt.

3. Boot into the installed system:
```
./obsd-boot.sh bsd.mp
```
