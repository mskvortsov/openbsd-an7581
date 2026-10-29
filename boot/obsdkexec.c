/*
 * obsdkexec - kexec an OpenBSD/arm64 kernel from Linux.
 *
 * kexec-tools only knows the Linux arm64 boot protocol (Image header,
 * x0 = dtb).  OpenBSD's locore0.S wants what efiboot hands it:
 *
 *	x0 = esym (PA), x1 = 0, x2 = fdt (PA)
 *	kernel loaded 2 MiB into a 2 MiB aligned, 64 MiB block of free RAM
 *	MMU and D-cache off, EL2 or EL1
 *
 * so we bypass kexec-tools and call kexec_load(2) directly with three
 * segments: the kernel image, a patched copy of the live device tree,
 * and a tiny trampoline that sets up those registers.  Linux enters the
 * trampoline at EL2 with the MMU off (cpu_soft_restart).
 *
 * The device tree is patched so OpenBSD finds its console:
 *	compatible = "ns16550"  ->  "ns16550a", "ns16550"	(com_fdt match)
 *	/chosen/bootargs        ->  -b argument
 */

#include <sys/mman.h>
#include <sys/random.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include <elf.h>
#include <endian.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/kexec.h>
#include <linux/reboot.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

#ifndef PT_OPENBSD_RANDOMIZE
#define PT_OPENBSD_RANDOMIZE	0x65a3dbe6
#endif

#define KERNBASE	0xffffff8000000000ULL
#define BLOCK_SIZE	(UINT64_C(64) << 20)
#define PAGE		4096ULL
#define ROUND(x, a)	(((x) + (a) - 1) & ~((a) - 1))

/* Defaults for the Nokia XG-040G-MD: first 64 MiB of 0x8a000000-0x9fffffff. */
#define DEF_BLOCK	UINT64_C(0x8a000000)

struct buf {
	uint8_t	*p;
	size_t	 len, cap;
};

static void
buf_put(struct buf *b, const void *p, size_t len)
{
	if (b->len + len > b->cap) {
		b->cap = ROUND(b->len + len + 4096, 4096);
		if ((b->p = realloc(b->p, b->cap)) == NULL)
			err(1, "realloc");
	}
	memcpy(b->p + b->len, p, len);
	b->len += len;
}

static void
buf_put32(struct buf *b, uint32_t v)
{
	v = htobe32(v);
	buf_put(b, &v, 4);
}

static void
buf_align4(struct buf *b)
{
	static const uint8_t zero[4];

	buf_put(b, zero, ROUND(b->len, 4) - b->len);
}

static void *
read_file(const char *path, size_t *lenp)
{
	struct buf b = { 0 };
	uint8_t chunk[65536];
	ssize_t n;
	int fd;

	/* /sys/firmware/fdt has st_size 0 on some kernels: read to EOF. */
	if ((fd = open(path, O_RDONLY)) == -1)
		err(1, "%s", path);
	while ((n = read(fd, chunk, sizeof(chunk))) > 0)
		buf_put(&b, chunk, n);
	if (n == -1)
		err(1, "%s", path);
	close(fd);
	*lenp = b.len;
	return b.p;
}

/*
 * Kernel
 */

struct kernel {
	uint8_t		*img;		/* KERNBASE + 2 MiB .. round_page(esym) */
	size_t		 len;
	uint64_t	 vbase;		/* VA of img[0] */
	uint64_t	 entry;		/* VA */
	uint64_t	 vend;		/* VA of esym: _end, or end of symbols */
	size_t		 nsym;		/* bytes of symbol data after _end */
};

#define ELF_CTF		".SUNW_ctf"

/* The sections loadfile(9) copies after the kernel for ddb and ksyms. */
static int
sym_section(const Elf64_Shdr *sh, const char *shstr, size_t shstrsz)
{
	const char *name = sh->sh_name < shstrsz ? shstr + sh->sh_name : "";

	return sh->sh_type == SHT_SYMTAB || sh->sh_type == SHT_STRTAB ||
	    strcmp(name, ".debug_line") == 0 || strcmp(name, ELF_CTF) == 0;
}

/*
 * Lay out the symbol table at sym the way loadfile_elf.c's LOAD_SYM |
 * LOAD_HDR does: ELF header, section headers, then the symbol sections,
 * each 8-byte aligned, with sh_offset relative to the ELF header.
 * Returns the size; with sym == NULL only counts.
 */
static size_t
load_syms(const uint8_t *f, size_t flen, uint8_t *sym)
{
	const Elf64_Ehdr *eh = (const Elf64_Ehdr *)f;
	const Elf64_Shdr *shp;
	Elf64_Shdr *nsh = NULL;
	Elf64_Ehdr neh;
	const char *shstr;
	size_t shsz, shstrsz, off;
	int i, havesyms = 0;

	if (eh->e_shoff == 0 || eh->e_shnum == 0 ||
	    eh->e_shentsize != sizeof(Elf64_Shdr) ||
	    eh->e_shoff + (size_t)eh->e_shnum * sizeof(Elf64_Shdr) > flen ||
	    eh->e_shstrndx >= eh->e_shnum)
		return 0;
	shp = (const Elf64_Shdr *)(f + eh->e_shoff);
	shsz = eh->e_shnum * sizeof(Elf64_Shdr);
	if (shp[eh->e_shstrndx].sh_offset + shp[eh->e_shstrndx].sh_size > flen)
		return 0;
	shstr = (const char *)f + shp[eh->e_shstrndx].sh_offset;
	shstrsz = shp[eh->e_shstrndx].sh_size;

	for (i = 0; i < eh->e_shnum; i++)
		if (shp[i].sh_type == SHT_SYMTAB)
			havesyms = 1;
	if (!havesyms)
		return 0;

	if (sym != NULL) {
		nsh = (Elf64_Shdr *)(sym + sizeof(Elf64_Ehdr));
		memcpy(nsh, shp, shsz);
	}
	off = ROUND(sizeof(Elf64_Ehdr) + shsz, 8);
	for (i = 0; i < eh->e_shnum; i++) {
		if (!sym_section(&shp[i], shstr, shstrsz))
			continue;
		if (shp[i].sh_offset + shp[i].sh_size > flen)
			errx(1, "kernel: section %d past end of file", i);
		if (sym != NULL) {
			memcpy(sym + off, f + shp[i].sh_offset, shp[i].sh_size);
			nsh[i].sh_offset = off;
			nsh[i].sh_flags |= SHF_ALLOC;
		}
		off += ROUND(shp[i].sh_size, 8);
	}

	if (sym != NULL) {
		neh = *eh;
		neh.e_phoff = 0;
		neh.e_shoff = sizeof(Elf64_Ehdr);
		neh.e_phentsize = 0;
		neh.e_phnum = 0;
		memcpy(sym, &neh, sizeof(neh));
	}
	return off;
}

static void
load_kernel(const char *path, struct kernel *k)
{
	Elf64_Ehdr *eh;
	Elf64_Phdr *ph;
	uint8_t *f;
	size_t flen, symoff;
	uint64_t lo = UINT64_MAX, hi = 0;
	int i;

	f = read_file(path, &flen);
	eh = (Elf64_Ehdr *)f;
	if (flen < sizeof(*eh) || memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
	    eh->e_ident[EI_CLASS] != ELFCLASS64 || eh->e_machine != EM_AARCH64)
		errx(1, "%s: not an arm64 ELF (gzipped? gunzip it first)", path);
	if (eh->e_phoff + (size_t)eh->e_phnum * sizeof(*ph) > flen)
		errx(1, "%s: truncated program headers", path);
	ph = (Elf64_Phdr *)(f + eh->e_phoff);

	for (i = 0; i < eh->e_phnum; i++) {
		if (ph[i].p_type != PT_LOAD)
			continue;
		if (ph[i].p_vaddr < lo)
			lo = ph[i].p_vaddr;
		if (ph[i].p_vaddr + ph[i].p_memsz > hi)
			hi = ph[i].p_vaddr + ph[i].p_memsz;
	}
	if (lo == UINT64_MAX)
		errx(1, "%s: no PT_LOAD segments", path);
	if (lo < KERNBASE || (lo - KERNBASE) % (2 << 20) != 0)
		errx(1, "%s: unexpected link address 0x%" PRIx64, path, lo);
	symoff = ROUND(hi - lo, 8);
	k->nsym = load_syms(f, flen, NULL);
	if (lo + symoff + k->nsym - KERNBASE > BLOCK_SIZE)
		errx(1, "%s: kernel and symbols do not fit in 64 MiB", path);

	k->vbase = lo;
	k->vend = k->nsym ? lo + symoff + k->nsym : hi;
	k->entry = eh->e_entry;
	k->len = ROUND(k->vend - lo, PAGE);
	if ((k->img = calloc(1, k->len)) == NULL)
		err(1, "calloc");
	if (k->nsym)
		load_syms(f, flen, k->img + symoff);

	for (i = 0; i < eh->e_phnum; i++) {
		if (ph[i].p_type != PT_LOAD)
			continue;
		if (ph[i].p_offset + ph[i].p_filesz > flen ||
		    ph[i].p_filesz > ph[i].p_memsz)
			errx(1, "%s: bad segment %d", path, i);
		memcpy(k->img + (ph[i].p_vaddr - lo), f + ph[i].p_offset,
		    ph[i].p_filesz);
	}

	/* What loadfile(9) does for the boot loader: seed the kernel. */
	for (i = 0; i < eh->e_phnum; i++) {
		uint8_t *p;
		size_t n, r;

		if (ph[i].p_type != PT_OPENBSD_RANDOMIZE)
			continue;
		if (ph[i].p_vaddr < lo || ph[i].p_vaddr + ph[i].p_memsz > hi)
			errx(1, "%s: randomize segment outside image", path);
		p = k->img + (ph[i].p_vaddr - lo);
		for (n = 0; n < ph[i].p_memsz; n += r) {
			ssize_t got = getrandom(p + n, ph[i].p_memsz - n, 0);
			if (got == -1)
				err(1, "getrandom");
			r = got;
		}
	}

	free(f);
}

/*
 * Device tree
 */

#define FDT_MAGIC	0xd00dfeed
#define FDT_BEGIN_NODE	1
#define FDT_END_NODE	2
#define FDT_PROP	3
#define FDT_NOP		4
#define FDT_END		9

struct fdt_header {
	uint32_t magic, totalsize, off_dt_struct, off_dt_strings;
	uint32_t off_mem_rsvmap, version, last_comp_version;
	uint32_t boot_cpuid_phys, size_dt_strings, size_dt_struct;
};

static uint32_t
rd32(const uint8_t *p)
{
	uint32_t v;

	memcpy(&v, p, 4);
	return be32toh(v);
}

/* Offset of name in the strings block, appending it if missing. */
static uint32_t
fdt_string(struct buf *s, const char *name)
{
	size_t off, n = strlen(name) + 1;

	for (off = 0; off < s->len; off += strlen((char *)s->p + off) + 1)
		if (strcmp((char *)s->p + off, name) == 0)
			return off;
	off = s->len;
	buf_put(s, name, n);
	return off;
}

static void
fdt_prop(struct buf *st, struct buf *s, const char *name, const void *val,
    size_t len)
{
	buf_put32(st, FDT_PROP);
	buf_put32(st, len);
	buf_put32(st, fdt_string(s, name));
	buf_put(st, val, len);
	buf_align4(st);
}

/* -m: local-mac-address for a node, e.g. Linux's MAC of the same port. */
struct macprop {
	const char	*path;
	uint8_t		 mac[6];
	int		 done;
};
static struct macprop macs[4];
static int nmacs;

static void
add_mac(const char *arg)
{
	struct macprop *mp;
	const char *eq = strchr(arg, '=');
	char *path;

	if (nmacs == nitems(macs))
		errx(1, "-m: at most %zu", nitems(macs));
	mp = &macs[nmacs];
	if (eq == NULL || eq == arg || sscanf(eq + 1,
	    "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mp->mac[0], &mp->mac[1],
	    &mp->mac[2], &mp->mac[3], &mp->mac[4], &mp->mac[5]) != 6)
		errx(1, "-m %s: want /node/path=aa:bb:cc:dd:ee:ff", arg);
	if ((path = strndup(arg, eq - arg)) == NULL)
		err(1, "strndup");
	mp->path = path;
	nmacs++;
}

static const char compat_old[] = "ns16550";		/* incl. NUL */
static const char compat_new[] = "ns16550a\0ns16550";	/* incl. NUL */

/*
 * Rebuild the blob token by token.  This is the whole of libfdt we need:
 * replace one compatible value, /chosen/bootargs and the -m MACs.
 */
static void *
patch_fdt(const uint8_t *in, size_t inlen, const char *bootargs, size_t *outlen)
{
	const struct fdt_header *h = (const void *)in;
	struct buf st = { 0 }, s = { 0 }, out = { 0 };
	struct fdt_header oh;
	const uint8_t *p, *end, *strs;
	uint8_t *zero;
	size_t pad;
	uint32_t rsv, tok, len, nameoff;
	int depth = 0, in_chosen = 0, ncompat = 0, mac_depth = -1, i;
	char path[512];
	size_t plen[64];

	if (inlen < sizeof(*h) || be32toh(h->magic) != FDT_MAGIC)
		errx(1, "device tree: bad magic");
	if (be32toh(h->totalsize) > inlen || be32toh(h->version) < 17)
		errx(1, "device tree: truncated or too old (v%u)",
		    be32toh(h->version));

	p = in + be32toh(h->off_dt_struct);
	end = p + be32toh(h->size_dt_struct);
	strs = in + be32toh(h->off_dt_strings);
	buf_put(&s, strs, be32toh(h->size_dt_strings));

	while (p < end) {
		tok = rd32(p);
		p += 4;
		switch (tok) {
		case FDT_BEGIN_NODE: {
			const char *name = (const char *)p;
			size_t n = strlen(name) + 1;

			buf_put32(&st, FDT_BEGIN_NODE);
			buf_put(&st, name, n);
			buf_align4(&st);
			p += ROUND(n, 4);
			depth++;
			if (depth >= (int)nitems(plen))
				errx(1, "device tree: nested too deep");
			plen[depth] = depth == 1 ? 0 : strlen(path);
			if (depth == 1)
				path[0] = '\0';
			else if (snprintf(path + plen[depth], sizeof(path) -
			    plen[depth], "/%s", name) >= (int)(sizeof(path) -
			    plen[depth]))
				errx(1, "device tree: path too long");
			for (i = 0; i < nmacs; i++) {
				if (strcmp(path, macs[i].path) != 0)
					continue;
				fdt_prop(&st, &s, "local-mac-address",
				    macs[i].mac, sizeof(macs[i].mac));
				macs[i].done = 1;
				mac_depth = depth;
			}
			if (depth == 2 && strcmp(name, "chosen") == 0) {
				in_chosen = 1;
				fdt_prop(&st, &s, "bootargs", bootargs,
				    strlen(bootargs) + 1);
			}
			break;
		}
		case FDT_END_NODE:
			buf_put32(&st, FDT_END_NODE);
			if (depth > 0)
				path[plen[depth]] = '\0';
			if (depth == mac_depth)
				mac_depth = -1;
			if (depth-- == 2)
				in_chosen = 0;
			break;
		case FDT_PROP: {
			const char *name;

			len = rd32(p);
			nameoff = rd32(p + 4);
			p += 8;
			name = (const char *)strs + nameoff;
			if (in_chosen && strcmp(name, "bootargs") == 0) {
				/* replaced above */
			} else if (depth == mac_depth &&
			    strcmp(name, "local-mac-address") == 0) {
				/* replaced above */
			} else if (strcmp(name, "compatible") == 0 &&
			    len == sizeof(compat_old) &&
			    memcmp(p, compat_old, len) == 0) {
				fdt_prop(&st, &s, name, compat_new,
				    sizeof(compat_new));
				ncompat++;
			} else
				fdt_prop(&st, &s, name, p, len);
			p += ROUND(len, 4);
			break;
		}
		case FDT_NOP:
			break;
		case FDT_END:
			buf_put32(&st, FDT_END);
			p = end;
			break;
		default:
			errx(1, "device tree: bad token 0x%x", tok);
		}
	}
	if (ncompat == 0)
		warnx("warning: no \"ns16550\" node found; console may be silent");
	for (i = 0; i < nmacs; i++)
		if (!macs[i].done)
			warnx("warning: -m: no node %s", macs[i].path);

	/* Header, reserve map, struct, strings; then 4 KiB of slack. */
	memset(&oh, 0, sizeof(oh));
	buf_put(&out, &oh, sizeof(oh));
	while (out.len % 8)
		buf_put(&out, "", 1);
	rsv = out.len;
	for (p = in + be32toh(h->off_mem_rsvmap);; p += 16) {
		buf_put(&out, p, 16);
		if (rd32(p) == 0 && rd32(p + 4) == 0 &&
		    rd32(p + 8) == 0 && rd32(p + 12) == 0)
			break;
	}
	oh.off_mem_rsvmap = htobe32(rsv);
	oh.off_dt_struct = htobe32(out.len);
	oh.size_dt_struct = htobe32(st.len);
	buf_put(&out, st.p, st.len);
	oh.off_dt_strings = htobe32(out.len);
	oh.size_dt_strings = htobe32(s.len);
	buf_put(&out, s.p, s.len);
	pad = ROUND(out.len + 4096, PAGE) - out.len;
	if ((zero = calloc(1, pad)) == NULL)
		err(1, "calloc");
	buf_put(&out, zero, pad);
	free(zero);

	oh.magic = htobe32(FDT_MAGIC);
	oh.totalsize = htobe32(out.len);
	oh.version = htobe32(17);
	oh.last_comp_version = htobe32(16);
	oh.boot_cpuid_phys = h->boot_cpuid_phys;
	memcpy(out.p, &oh, sizeof(oh));

	free(st.p);
	free(s.p);
	*outlen = out.len;
	return out.p;
}

/*
 * Trampoline: entered by Linux's relocate_kernel at EL2, MMU off.
 * The three .quad slots are filled in below.
 */
extern const uint8_t tramp_start[], tramp_data[], tramp_end[];
__asm__(
"	.pushsection .rodata\n"
"	.balign 8\n"
"tramp_start:\n"
"	adr	x9, tramp_data\n"
"	ldp	x0, x2, [x9]\n"		/* esym, fdt */
"	ldr	x3, [x9, #16]\n"	/* entry */
"	mov	x1, xzr\n"
"	br	x3\n"
"	.balign 8\n"
"tramp_data:\n"
"	.quad	0, 0, 0\n"
"tramp_end:\n"
"	.popsection\n");

static void
write_file(const char *path, const void *p, size_t len)
{
	FILE *fp = fopen(path, "w");

	if (fp == NULL || fwrite(p, 1, len, fp) != len || fclose(fp) != 0)
		err(1, "%s", path);
}

static void
usage(void)
{
	fprintf(stderr,
	    "usage: obsdkexec [-nex] [-a block] [-b bootargs] [-d dtb]"
	    " [-K out.img] [-m path=mac] [-o out.dtb] bsd\n"
	    "  -a block    64 MiB load block, 2 MiB aligned (default 0x%" PRIx64 ")\n"
	    "  -b args     /chosen/bootargs (default \"bsd\")\n"
	    "  -d dtb      source device tree (default /sys/firmware/fdt)\n"
	    "  -o file     also write the patched device tree to file\n"
	    "  -K file     also write the assembled kernel image to file\n"
	    "  -m path=mac set local-mac-address of a device tree node\n"
	    "  -n          dry run: print the plan, do not load\n"
	    "  -e          sync and kexec into it right after loading\n"
	    "  -x          only kexec into an already loaded image\n",
	    DEF_BLOCK);
	exit(1);
}

int
main(int argc, char *argv[])
{
	const char *dtbpath = "/sys/firmware/fdt", *bootargs = "bsd";
	const char *outdtb = NULL, *outimg = NULL;
	uint64_t block = DEF_BLOCK, kpa, fdtpa, trpa, esym, entry;
	struct kexec_segment seg[3];
	struct kernel k;
	uint8_t *fdtin, *fdt, *tramp;
	size_t fdtinlen, fdtlen, trlen;
	int ch, dryrun = 0, doexec = 0, execonly = 0;

	while ((ch = getopt(argc, argv, "a:b:d:eK:m:no:x")) != -1) {
		switch (ch) {
		case 'a':
			block = strtoull(optarg, NULL, 0);
			break;
		case 'b':
			bootargs = optarg;
			break;
		case 'd':
			dtbpath = optarg;
			break;
		case 'e':
			doexec = 1;
			break;
		case 'K':
			outimg = optarg;
			break;
		case 'm':
			add_mac(optarg);
			break;
		case 'n':
			dryrun = 1;
			break;
		case 'o':
			outdtb = optarg;
			break;
		case 'x':
			execonly = 1;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (execonly)
		goto exec;
	if (argc != 1)
		usage();
	if (block % (2 << 20) != 0)
		errx(1, "block 0x%" PRIx64 " is not 2 MiB aligned", block);

	load_kernel(argv[0], &k);
	kpa = block + (k.vbase - KERNBASE);
	entry = block + (k.entry - KERNBASE);
	esym = block + (k.vend - KERNBASE);

	fdtin = read_file(dtbpath, &fdtinlen);
	fdt = patch_fdt(fdtin, fdtinlen, bootargs, &fdtlen);
	if (outdtb != NULL)
		write_file(outdtb, fdt, fdtlen);
	if (outimg != NULL)
		write_file(outimg, k.img, k.len);

	/*
	 * FDT and trampoline go right after the 64 MiB block: the kernel
	 * steals early memory from inside the block, and copies the FDT
	 * out before it hands the rest of RAM to UVM.
	 */
	fdtpa = block + BLOCK_SIZE;
	trpa = fdtpa + fdtlen;

	trlen = PAGE;
	if ((tramp = calloc(1, trlen)) == NULL)
		err(1, "calloc");
	memcpy(tramp, tramp_start, tramp_end - tramp_start);
	memcpy(tramp + (tramp_data - tramp_start), &esym, 8);
	memcpy(tramp + (tramp_data - tramp_start) + 8, &fdtpa, 8);
	memcpy(tramp + (tramp_data - tramp_start) + 16, &entry, 8);

	seg[0] = (struct kexec_segment){ k.img, k.len, (void *)kpa, k.len };
	seg[1] = (struct kexec_segment){ fdt, fdtlen, (void *)fdtpa, fdtlen };
	seg[2] = (struct kexec_segment){ tramp, trlen, (void *)trpa, trlen };

	printf("block      0x%09" PRIx64 "-0x%09" PRIx64 "\n",
	    block, block + BLOCK_SIZE);
	printf("kernel     0x%09" PRIx64 " +0x%zx  entry 0x%" PRIx64
	    "  esym 0x%" PRIx64 "  symbols %zu KiB\n", kpa, k.len, entry, esym,
	    k.nsym / 1024);
	printf("fdt        0x%09" PRIx64 " +0x%zx  bootargs \"%s\"\n",
	    fdtpa, fdtlen, bootargs);
	printf("trampoline 0x%09" PRIx64 "\n", trpa);
	if (dryrun)
		return 0;

	if (syscall(SYS_kexec_load, trpa, 3, seg, KEXEC_ARCH_DEFAULT) == -1)
		err(1, "kexec_load%s", errno == ENOSYS ?
		    " (kernel built without CONFIG_KEXEC?)" : "");
	printf("loaded\n");
	if (!doexec)
		return 0;

exec:
	sync();
	if (reboot(LINUX_REBOOT_CMD_KEXEC) == -1)
		err(1, "reboot(KEXEC)");
	return 0;
}
