// SPDX-License-Identifier: GPL-2.0-only
/*
 * zycast - push images via multicast to a ZyXEL bootloader
 *
 * Many ZyXEL devices supports image manipulation using a multicast
 * based protocol.  The protocol is not documented publicly, and
 * both the bootloader embedded part and the official clients are
 * closed source.
 *
 * This client is based on the following description of the protocol.
 * which is reverse engineered from bootloader binaries. It is likely
 * to be both incomplete and inaccurate, as it only covers the
 * observed implementation on a limited set of devices.  No client
 * implementation or network packets were available for the protocol
 * reverse engineering.
 *
 * Protocol description:
 *
 * UDP to multicast destination address 225.0.0.0 port 5631. Source
 * address and port is arbitrary.
 *
 *  Payload is split in packets prepended with a 30 or 32 byte header:
 *
 *   4 byte signature: 'z', 'y', 'x', 0x0 [1]
 *   16 bit checksum [2][3]
 *   32 bit packet id [2][4]
 *   32 bit packet length [2][5]
 *   32 bit file length [2][6]
 *   32 bit image bitmap [2][7]
 *   2 byte ascii country code [8]
 *   8 bit  flags [9]
 *   5 or 7 byte reserved [10]
 *
 * [1] the terminating null is not actually checked by the observed
 *     implementations, but is assumed to be safest in case the
 *     signature is treated as a string
 *
 * [2] all integers are in network byte order, i.e. big endian
 *
 * [3] checksum = sum >> 16 + sum, where sum is the sum of all
 *     payload bytes
 *
 * [4] starts at 0 and is incremented by 1 for each packet.  Used both
 *     to ensure sequential, loss free, unidirectional transport, and to
 *     allow the transfer to start at any point.  The sequence must be
 *     repeated until the transfer is complete
 *
 * [5] Testing indicates that some implementations expect 1024 byte
 *     packets.  Smaller size results in a corrupt download, and larger
 *     size causes the download to hang - waiting for packet ids which
 *     does not exist.
 *
 * [6] the length of each file in case of a multi file transfer.
 *
 * [7] the lower 8 bits is a bitmap of all image types included in the
 *     transfer.  Bits 8 - 16 contains the image type for this packet.
 *     The purpose of the upper 16 bits is unknown.
 *
 *     The known image types are
 *
 *       0x01 - "bootbase" (often "Bootloader" partition)
 *       0x02 - "rom"      (often "data" partition)
 *       0x04 - "ras"      (often "Kernel" partition)
 *       0x08 - "romd"     (often "rom-d" partition)
 *       0x10 - "backup"   (often "Kernel2" partition)
 *
 *     The supported set of images vary among implementations.
 *     The protocol may support other image types.
 *
 *     WARNING: The flash offset of each supported image type is hard
 *      coded in the bootloader server implementation.  There is no
 *      relation to the bootloader configuration, and no way to verify
 *      that those values are correct without decompiling that
 *      implementations. Device specific bugs are likely, and may
 *      result in a brick.
 *
 * [8] two upper case ascii characters, like 'D','E'. The purpose
 *     is unknown, but ZyXEL devices are often configured with this
 *     as one of their device specific variables

 * [9] bitmap controlling actions taken after a complete transfer:
 *
 *       0x01 - set DebugFlag
 *       0x02 - erase "rom"
 *       0x04 - erase "rom-d"
 *
 *     Other, unknown, values may exist in the protocol.  Device
 *     support may vary.
 *
 * [10] these bytes are not used by the observed implementations.
 *      The purpose is therefore unknown. There is a risk
 *      they are interpreted by other devices, resulting in
 *      unexpected and potentially harmful behaviour.
 *
 *      Newer devices have a 32 bytes header with 7 reserved bytes
 *      instead of the original 30 bytes header with 5 reserved bytes.
 *
 *
 * Copyright (C) 2024, 2026 Bjørn Mork <bjorn@mork.no>
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

/* defaulting to 0.1 ms interpacket delay */
static int pktdelay = 100;
static int sockfd = -1;
static bool exiting;
static int protorev;

/* All integers are stored in network order (big endian) */
struct zycast_t {
	uint32_t magic;
	uint16_t chksum;
	uint32_t pid;
	uint32_t plen;
	uint32_t flen;
	uint16_t unusedbits;
	unsigned char type;
	unsigned char images;
	char cc[2];
	unsigned char flags;
} __attribute__ ((packed));

#define DEST_ADDR "225.0.0.0"
#define DEST_PORT 5631
#define CHUNK 1024
#define MAGIC 0x7a797800  /* "zyx" */

#define BIT(nr) (1 << (nr))

enum imagetype {
	BOOTBASE = 0,
	ROM,
	RAS,
	ROMD,
	BACKUP,
	XX,
	ROMD1,
	_MAX_IMAGETYPE
};

#define FLAG_SET_DEBUG  BIT(0)
#define FLAG_ERASE_ROM  BIT(1)
#define FLAG_ERASE_ROMD BIT(2)

/* must send CHUNK sized frames required regardless of actual datalen */
#define	FEAT_FILLFRAME BIT(0)

/* known protocol revisions */
struct revision_t {
	size_t hdrsize;
	uint32_t imagesupport;
	uint32_t features;
} revision[] = {
	[ 0 ] = { 30, BIT(BOOTBASE) | BIT(ROM) | BIT(RAS) | BIT(ROMD) | BIT(BACKUP), 0 },
	[ 1 ] = { 32, BIT(RAS) | BIT(ROM) | BIT(ROMD) | BIT(ROMD1), FEAT_FILLFRAME },
};
#define NUMREVISIONS (sizeof(revision) / sizeof(revision[0]))

static void errexit(const char *msg)
{
	fprintf(stderr, "ERR: %s: %s\n", msg, errno ? strerror(errno) : "unknown");
	exit(EXIT_FAILURE);
}

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

static uint16_t chksum(uint8_t *p, size_t len)
{
	int i;
	uint32_t sum = 0;

	for (i = 0; i < len; i++)
		sum += *p++;
	return (uint16_t)((sum >> 16) + sum);
}

static int pushimage(void *file, size_t len, enum imagetype type, void *buf)
{
	const struct sockaddr_in dest = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = inet_addr(DEST_ADDR),
		.sin_port = htons(DEST_PORT),
	};
	struct zycast_t *phdr = buf;
	uint32_t count = 0;
	uint32_t plen = CHUNK;
	size_t framelen = revision[protorev].hdrsize + CHUNK;

	/* constants per file */
	phdr->flen = htonl(len);
	phdr->type = BIT(type);
	phdr->plen = htonl(CHUNK);
	if (type == ROMD1)
		phdr->type += BIT(7);

	while (!exiting && (len > 0 || !count)) { /* !count to support zero length files */
		if (len < CHUNK) {
			plen = len;
			phdr->plen = htonl(len);

			/* backwards compatibility. is this required? */
			if (protorev == 0)
				framelen = revision[protorev].hdrsize + plen;
			else
				memset(buf + revision[protorev].hdrsize, 0, CHUNK);
		}
		phdr->pid = htonl(count++);
		phdr->chksum = htons(chksum(file, plen));
		if (plen)
			memcpy(buf + revision[protorev].hdrsize, file, plen);
		if (sendto(sockfd, phdr, framelen , MSG_DONTROUTE, (struct sockaddr *)&dest, sizeof(dest)) < 0)
			errexit("sendto()");
		file += plen;
		len -= plen;

		/* No need to kill the network. The target can't
		 * process packets as fast as we send them anyway.
		 */
		usleep(pktdelay);
	}
	return 0;
}

static void sig_handler(int signo)
{
	if (signo == SIGINT)
		exiting = true;
}

static void usage(const char *name)
{
	int i;

	fprintf(stderr, "Usage:\n");
	fprintf(stderr, " %s [options]\n", name);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "\t-v revision             protocol revision\n");
	fprintf(stderr, "\t-i interface            outgoing interface for multicast packets\n");
	fprintf(stderr, "\t-t microseconds         interpacket delay (default: %u)\n", pktdelay);
	fprintf(stderr, "\t-f rasimage             primary firmware image\n");
	fprintf(stderr, "\t-b backupimage          secondary firmware image (if supported)\n");
	fprintf(stderr, "\t-d rom                  data for the \"rom\" or \"data\" partition\n");
	fprintf(stderr, "\t-r romd                 data for the \"rom-d\" partition\n");
	fprintf(stderr, "\t-e                      set EngDebugFlag only (implies protocol revision 1)\n");
#ifdef DO_BOOTBASE
	fprintf(stderr, "\t-u bootloader           flash new bootloader\n");
	fprintf(stderr, "\nWARNING: bootloader upgrades are dangerous.  DON'T DO IT!\n");
#endif
	fprintf(stderr, "\n\"rasimage\" is the only image type which is supported by all devices\n");
	fprintf(stderr, "\nNOTE: some bootloaders will flash a \"rasimage\" to both primary and\n");
	fprintf(stderr, "secondary firmware partitions\n");
	fprintf(stderr, "\nREVISION: Different device generations use slightly different protocols.\n");
	fprintf(stderr, "The revision numbers used here are arbitrary and unofficial. And the list of\n");
	fprintf(stderr, "supported devices for each revision is unknown. Using the wrong revision is\n");
	fprintf(stderr, "harmless. Unrecognized packets will be silently ignored by the target device.\n");
	fprintf(stderr, "\nCurrently known revision numbers and their describing attributes:\n");
	for (i = 0; i < NUMREVISIONS; i++) {
		fprintf(stderr, "\t%u\n", i);
		fprintf(stderr, "\t\t%zu bytes header\n", revision[i].hdrsize);
		if (i == 0)
			fprintf(stderr, "\t\tdefault\n");
		if (revision[i].features && FEAT_FILLFRAME)
			fprintf(stderr, "\t\tconstant frame size\n");
	}
	fprintf(stderr, "\nExample:\n");
	fprintf(stderr, " %s -v 1 -i eth1 -f openwrt-initramfs.bin\n\n", name);
	if (sockfd >= 0)
		close(sockfd);
	exit(EXIT_FAILURE);
}

static void *bufalloc(unsigned char images)
{
	void *buf = malloc(revision[protorev].hdrsize + CHUNK);
	struct zycast_t *hdr = buf;

	if (!buf)
		errexit("malloc()");

	memset(buf, 0, revision[protorev].hdrsize + CHUNK);
	hdr->magic = htonl(MAGIC);
	hdr->flags = FLAG_SET_DEBUG;
	hdr->images = images;

	/* is this required? kept for backward compatibility */
	if (protorev == 0) {
		hdr->cc[0] = 'F';
		hdr->cc[1] = 'F';
	}

	return buf;
}

#define ADD_IMAGE(nr) \
	do { \
		images |= BIT(nr); \
		file[nr] = map_input(optarg, &len[nr]); \
		if (!file[nr]) \
			errexit(optarg); \
	} while (0)

int main(int argc, char **argv)
{

	void *file[_MAX_IMAGETYPE] = {};
	size_t len[_MAX_IMAGETYPE] = {};
	unsigned char images;
	void *pktbuf;
	int i, c;

	if (signal(SIGINT, sig_handler) == SIG_ERR)
		errexit("signal()");
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
		errexit("socket()");

	while ((c = getopt(argc, argv, "v:ei:t:f:b:d:r:x:u:")) != -1) {
		switch (c) {
		case 'v':
			protorev = atoi(optarg);
			if (protorev >= NUMREVISIONS)
				usage(argv[0]);
			break;
		case 'e':
			/* an empty rom-d image sets EngDebugFlag without flashing */
			protorev = 1;
			images = BIT(ROMD);
			break;
		case 'i':
			if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE,  optarg, strlen(optarg)) < 0)
				errexit(optarg);
			break;
		case 't':
			i = strtoul(optarg, NULL, 0);
			if (i < 1)
				i = 10000;
			pktdelay = i;
			break;
		case 'f':
			ADD_IMAGE(RAS);
			break;
		case 'b':
			ADD_IMAGE(BACKUP);
			break;
		case 'd':
			ADD_IMAGE(ROM);
			break;
		case 'r':
			ADD_IMAGE(ROMD);
			break;
		case 'x':
			ADD_IMAGE(ROMD1);
			break;
		case 'u':
#ifdef DO_BOOTBASE
			ADD_IMAGE(BOOTBASE);
			break;
#endif
		default:
			usage(argv[0]);
		}
	}

	/* simply bail out if the user tries to do anything yet unsupported */
	if ((images & revision[protorev].imagesupport) != images)
		errexit("unsupported images for this class");
	images &= revision[protorev].imagesupport;
	if (!images)
		usage(argv[0]);

	/* allocate a frame buffer */
	pktbuf = bufalloc(images);

	fprintf(stderr, "Press Ctrl+C to stop before rebooting target after upgrade\n");
	while (!exiting) {
		for (i = 0; i < _MAX_IMAGETYPE; i++) {
			if (images & BIT(i))
				pushimage(file[i], len[i], i, pktbuf);
		}
		usleep(100 * pktdelay); /* wait a bit before repeating */
	};

	fprintf(stderr, "\nClosing all files\n");
	if (sockfd >= 0)
		close(sockfd);
	for (i = 0; i < _MAX_IMAGETYPE; i++)
		if (images & BIT(i) && len[i])
			munmap(file[i], len[i]);

	free(pktbuf);
	return EXIT_SUCCESS;
}
