/* SPDX-License-Identifier: GPL-2.0+ */

#include <ctype.h>
#include <err.h>
#include <endian.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/mman.h>

#include <libfdt.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

struct record_type {
	const char kw[3];
	const char *name;
};

static const struct record_type record_types[] = {
	{"B3", "Hardware characteristics"},
	{"B4", "Manufacturing FRU control"},
	{"B7", "Test Dev"},
	{"B9", "Smart chip info"},
	{"BR", "Brand"},
	{"CC", "Card ID"},
	{"CE", "Extent CCIN"},
	{"CT", "Card type"},
	{"DR", "Description"},
	{"FC", "Feature code"},
	{"FG", "Flag field"},
	{"FL", "Frame label"},
	{"FN", "Field part number"},
	{"HE", "Hardware EC level"},
	{"HW", "Hardware level"},
	{"ID", "System ID"},
	{"LX", "Load ID"},
	{"MN", "Manufacture date"},
	{"NN", "SSD node ID"},
	{"PF", "Pad fill"},
	{"PN", "Card assembly part number"},
	{"PR", "Power field"},
	{"RB", "Reserved bytes"},
	{"RG", "Reserved bytes"},
	{"RT", "Record name"},
	{"SE", "System serial number"},
	{"SG", "System serial number"},
	{"SN", "Serial number"},
	{"SU", "System unique ID"},
	{"SZ", "Memory size"},
	{"TM", "Type-model"},
	{"TN", "Type-model"},
	{"VZ", "Version control"},
	{"WN", "Worldwide port number"},
};

static const struct record_type *get_record_type(const char kw[3])
{
	const struct record_type *type;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(record_types); i++) {
		type = &record_types[i];
		if (!memcmp(type->kw, kw, 2))
			return type;
	}

	return NULL;
}

static int map_file(const char *name, void **bufp, size_t *lenp)
{
	struct stat statbuf;
	int rc, fd;
	void *buf;

	fd = open(name, O_RDONLY);
	if (fd < 0) {
		warn("can't open %s", name);
		return -1;
	}

	rc = fstat(fd, &statbuf);
	if (rc) {
		warn("can't stat %s", name);
		rc = -1;
		goto out_close;
	}

	buf = mmap(NULL, statbuf.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		warn("can't map %s", name);
		rc = -1;
		goto out_close;
	}

	*bufp = buf;
	*lenp = statbuf.st_size;

out_close:
	close(fd);
	return rc;
}

static uint8_t printable_char(uint8_t c)
{
	if (!isprint(c) || (isspace(c) && c != ' '))
		return '.';

	return c;
}

/* 16 * 3 space chars; to pad left-over hexdump strings */
static const char spcbuf[] =
	"☺                                             ";

static void hexdump(const uint8_t *buf, size_t len)
{
	unsigned int i;
	char strbuf[17];
	int r;

	for (i = 0; i < len; i++) {
		printf("%s%02x", i % 16 ? " " :  "\t", buf[i]);
		strbuf[i % 16] = printable_char(buf[i]);
		if (i % 16 == 15) {
			strbuf[16] = '\0';
			printf("  |%s|\n", strbuf);
		}
	}

	r = len % 16;

	if (r) {
		strbuf[r] = '\0';
		printf("%s  |%s|\n", spcbuf + (r * 3), strbuf);
	}
}

static void print_one_vpd(const uint8_t *buf, uint16_t len)
{
	const struct record_type *record_type;
	uint8_t record_len;
	size_t pos;

	printf("VPD: %d bytes\n", len);

	for (pos = 0; pos < len;) {
		if (pos + 3 > len) {
			fprintf(stderr, "invalid VPD section\n");
			return;
		}

		record_len = buf[pos+2];
		record_type = get_record_type((const char *)buf + pos);

		printf("  %c%c [%02x]%s%s\n",
				printable_char(buf[pos]),
				printable_char(buf[pos+1]),
				record_len,
				record_type ? ": " : "",
				record_type ? record_type->name : "");

		if (pos + record_len >= len) {
			fprintf(stderr, "record is too long\n");
		}

		hexdump(buf + pos + 3, record_len);

		pos += 3 + record_len;
	}
}

static void print_vpd(const uint8_t *buf, size_t len)
{
	uint16_t vpd_len;
	size_t pos;

	for (pos = 0; pos < len;) {
		if (buf[pos] == 0x0) {
			pos++;
			continue;
		}

		if (pos + 3 > len) {
			fprintf(stderr, "invalid VPD header at %zx: no space\n",
					pos);
			return;
		}
		if (buf[pos] != 0x84) {
			fprintf(stderr,
				"invalid VPD header at %zd: "
				"no start marker (%02x)\n",
				pos, buf[pos]);
			return;
		}

		vpd_len = buf[pos+1] | buf[pos+2] << 8;
		if (pos + vpd_len + 3 >= len) {
			fprintf(stderr, "VPD section at %zd is too large\n",
					pos);
			return;
		}

		print_one_vpd(buf + pos + 3, vpd_len);

		pos += vpd_len + 3;

		if (buf[pos] != 0x78) {
			fprintf(stderr, "invalid VPD header at %zx: "
					"no end marker\n",
					pos);
			return;
		}

		pos++;
	}
}

static void print_fdt_vpds(const void *fdt, size_t fdtlen)
{
	char path[4096];
	const void *buf;
	int node, len;

	if (fdt_check_header(fdt)) {
		fprintf(stderr, "invalid device tree\n");
		return;
	}

	if (fdt_totalsize(fdt) > fdtlen) {
		fprintf(stderr, "truncated device tree\n");
		return;
	}

	for (node = 0; node >= 0; node = fdt_next_node(fdt, node, NULL)) {
		buf = fdt_getprop(fdt, node, "ibm,vpd", &len);
		if (buf) {
			fdt_get_path(fdt, node, path, sizeof(path));
			printf("%s\n", path);
			print_vpd(buf, len);
		}
	}
}

int main(int argc, char **argv)
{
	const char *filename;
	size_t len;
	void *buf;
	int rc;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <file>\n", argv[0]);
		return EXIT_FAILURE;
	}

	filename = argv[1];

	rc = map_file(filename, &buf, &len);
	if (rc)
		return EXIT_FAILURE;

	if (len > 4 && *(uint32_t *)(buf) == htobe32(0xd00dfeed))
		print_fdt_vpds(buf, len);
	else
		print_vpd(buf, len);

	return EXIT_SUCCESS;
}
