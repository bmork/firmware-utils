// SPDX-License-Identifier: GPL-2.0-only
/*
 * fwsplit - unpack UBNT images
 *
 * Copyright (C) 2025 Bjørn Mork <bjorn@mork.no>
 */

#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <zlib.h>
#include "fw.h"

static char *dumpdir = NULL;

static void *map_input(const char *name, size_t *len)
{
	struct stat stat;
	void *mapped;
	int fd;

	fd = open(name, O_RDONLY);
	if (fd < 0)
		return NULL;
	if (fstat(fd, &stat) < 0) {
		close(fd);
		return NULL;
	}
	*len = stat.st_size;
	mapped = mmap(NULL, stat.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (close(fd) < 0) {
		(void) munmap(mapped, stat.st_size);
		return NULL;
	}
	return mapped;
}

static char *strmagic(void *p)
{
	static char buf[MAGIC_LENGTH + 1];

	strlcpy(buf, p, sizeof(buf));
	return buf;
}

static char *parse_header(void *img, size_t len)
{
	header_t *h = img;
	u_int32_t c = htonl(crc32(0L, img, sizeof(header_t) - 2 * sizeof(u_int32_t)));

	fprintf(stderr, "%s\n  name:\t%s\n  crc:\t0x%08x\n", strmagic(img), h->version, ntohl(h->crc));
	if (c == h->crc)
		return h->version;

	fprintf(stderr, "CRC ERROR: 0x%08x != 0x%08x)\n", h->crc, c);
	return NULL;
}

static const char *mkfname(const char *base, const char *name)
{
	static char fname[PATH_MAX];

	strlcpy(fname, dumpdir, PATH_MAX);
	strlcat(fname, "/", PATH_MAX);
	strlcat(fname, base, PATH_MAX);
	strlcat(fname, ".", PATH_MAX);
	strlcat(fname, name, PATH_MAX);
	return fname;
}

static int save_part(const char *fname, void *buf, size_t len)
{
	int fd = open(fname, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	if (fd < 0) {
		fprintf(stderr, "Cannot open %s\n", fname);
		return fd;
	}
	if (write(fd, buf, len) != len) {
		fprintf(stderr, "Failed to write to %s\n", fname);
		close(fd);
		return -1;
	}
	close(fd);
	fprintf(stderr, "    filename:\t%s\n", fname);
	return 0;
}

static void *parse_part(const char *name, void *mem)
{
	part_t* p = mem;
	part_crc_t* h = mem + sizeof(part_t) + ntohl(p->data_size);
	u_int32_t c = htonl(crc32(0L, mem, ntohl(p->data_size) + sizeof(part_t)));

	fprintf(stderr, "\n  %s\n    name:\t%s\n    index:\t%d\n    memaddr:\t0x%08x\n    baseaddr:\t0x%08x\n    entryaddr:\t0x%08x\n    data_size:\t0x%08x\n    part_size:\t0x%08x\n    crc:\t0x%08x\n",
		strmagic(mem), p->name, ntohl(p->index), ntohl(p->memaddr),
		ntohl(p->baseaddr), ntohl(p->entryaddr), ntohl(p->data_size),
		ntohl(p->part_size), ntohl(h->crc));
	if (h->crc != c) {
		fprintf(stderr, "CRC ERROR: 0x%08x != 0x%08x\n", h->crc, c);
		return NULL;
	}

	if (dumpdir)
		save_part(mkfname(name, p->name), mem + sizeof(part_t), ntohl(p->data_size));

	return (void *)h + sizeof(part_crc_t);
}

static int parse_sig(signature_t *sig, void *end)
{
	size_t remaining = end - (void *)sig - sizeof(signature_t);

	fprintf(stderr, "\n%s\n", strmagic(sig->magic));
	if (!remaining)
		return 0;

	fprintf(stderr, "ERR: %zu extra bytes after signature\n", remaining);
	return -1;
}

static void hexprint(void *p, size_t l, const char *pfx)
{
	int i;

	fprintf(stderr, "%s", pfx);
	for (i = 1; i <= l; i++) {
		fprintf(stderr, "%02hhx", *(char *)p++);
		if (i == l)
			fprintf(stderr, "\n");
		else if (i % 16 == 0)
			fprintf(stderr, "\n%s", pfx);
		else if (i % 8 == 0)
			fprintf(stderr, "  ");
		else
			fprintf(stderr, " ");
	}
}

static int parse_sig_rsa(signature_rsa_t *sig, void *end)
{
	size_t remaining = end - (void *)sig - sizeof(signature_rsa_t);

	fprintf(stderr, "\n%s\n", strmagic(sig->magic));
	hexprint(sig->rsa_signature, sizeof(sig->rsa_signature), "  ");
	if (!remaining)
		return 0;

	fprintf(stderr, "ERR: %zu extra bytes after signature\n", remaining);
	return -1;
}

static int parse(void *img, size_t len)
{
	void *p;
	char *name = parse_header(img, len);

	if (!name)
		return -1;

	p = img + sizeof(header_t);
	while (p && p + sizeof(part_t) <= img + len && strncmp(p, "END", 3)) {
		p = parse_part(name, p);
	}

	if (!p)
		return -1;

	if (p + sizeof(signature_t) <= img + len && !strncmp(p, MAGIC_END, MAGIC_LENGTH))
		return parse_sig(p, img + len);
	if (p + sizeof(signature_rsa_t) <= img + len && !strncmp(p, MAGIC_ENDS, MAGIC_LENGTH))
		return parse_sig_rsa(p, img + len);

	fprintf(stderr, "ERR: no signature at end of image\n");
	return -1;
}

static void usage(const char *name)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, " %s [options] <ubnt-image>\n\n", name);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "\t-w directory  split and save sub-images\n");
	fprintf(stderr, "\nExample:\n");
	fprintf(stderr, " %s -w /tmp BZ.mt7621_5.43.23+12533.201222.2019.bin\n\n", name);
	exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
	int ret, c;
	size_t size;
	void *img = NULL;

	while ((c = getopt(argc, argv, "h?w:")) != -1) {
		switch (c) {
		case 'w':
			dumpdir = optarg;
			break;
		default:
			usage(argv[0]);
		}
	}
	if (optind >= argc)
		usage(argv[0]);

	img = map_input(argv[optind], &size);
	ret = parse(img, size);
	(void) munmap(img, size);

	return ret;
}
