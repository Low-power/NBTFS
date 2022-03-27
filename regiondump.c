/*	Copyright 2015-2022 Rivoreo

	Permission is hereby granted, free of charge, to any person obtaining
	a copy of this software and associated documentation files (the
	"Software"), to deal in the Software without restriction, including
	without limitation the rights to use, copy, modify, merge, publish,
	distribute, sublicense, and/or sell copies of the Software, and to
	permit persons to whom the Software is furnished to do so, subject to
	the following conditions:

	The above copyright notice and this permission notice shall be
	included in all copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
	EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
	MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
	NONINFRINGEMENT. IN NO EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE
	FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
	CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
	WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "nbt.h"
#include <arpa/inet.h>
#include <sys/mman.h>
#include <unistd.h>
#include <locale.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>

static const char *compression_type_names[] = { "unknown", "gzip", "zlib", "none" };

int main(int argc, char **argv) {
	if(argv[1] && strcmp(argv[1], "--") == 0) {
		argc--;
		argv[1] = argv[0];
		argv++;
	}
	if(argc != 2) {
		fprintf(stderr, "Usage: %s <region-file>\n", argv[0]);
		return -1;
	}

	setlocale(LC_ALL, "");

	int fd = open(argv[1], O_RDONLY);
	if(fd == -1) {
		perror(argv[1]);
		return 1;
	}
	off_t len = lseek(fd, 0, SEEK_END);
	if(len < 0) {
		perror(argv[1]);
		return 1;
	}
	if(len < 8192) {
		fprintf(stderr, "%s: %s: Too small to be a valid region file\n", argv[0], argv[1]);
		return 1;
	}
	lseek(fd, 0, SEEK_SET);
	void *map = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
	if(!map) {
		perror("mmap");
		return 1;
	}
	close(fd);

	struct {
		void *p;
		size_t len;
	} chunks_to_dump[1024];
	memset(chunks_to_dump, 0, sizeof chunks_to_dump);

	unsigned int i;
	uint8_t *byte_p = map;
	int32_t *int_p = map;
	puts("Chunk Offset     Last-Updated             Size Used-Space Compression");
	for(i = 0; i < 1024; i++) {
		size_t chunk_size = byte_p[i * 4 + 3] * 4 * 1024;
		if(!chunk_size) continue;
		off_t chunk_offset = (ntohl(int_p[i]) >> 8) & 0xffffff;
		if(!chunk_offset) continue;
		off_t file_offset = chunk_offset * 4 * 1024;
		if(file_offset > len) {
			fprintf(stderr, "Chunk %u has invalid offset %ld that's out of file length\n",
				i, (long int)file_offset);
			continue;
		}
		time_t chunk_mtime = ntohl(int_p[1024 + i]);
		struct tm *chunk_tm = localtime(&chunk_mtime);
		char time_buffer[24];
		if(!strftime(time_buffer, sizeof time_buffer, "%F %T", chunk_tm)) {
			sprintf(time_buffer, "%d", (int)chunk_mtime);
		}
		uint8_t *chunk = (uint8_t *)map + file_offset;
		int32_t used_space;
		memcpy(&used_space, chunk, 4);
		used_space = ntohl(used_space);
		if(used_space < 0 || (size_t)used_space > chunk_size) {
			fprintf(stderr, "Chunk %u has invalid size %d\n", i, (int)used_space);
			continue;
		}
		uint8_t compression_type = chunk[4];
		printf("%5u 0x%08x %-23s %5zu %10d %s\n",
			i, (unsigned int)file_offset, time_buffer, chunk_size, (int)used_space,
			compression_type_names[
				compression_type < sizeof compression_type_names / sizeof(char *) ?
					compression_type : 0
			]);
		if(compression_type == 2) {
			chunks_to_dump[i].p = chunk + 5;
			chunks_to_dump[i].len = used_space - 1;
		}
	}

	for(i = 0; i < 1024; i++) {
		if(!chunks_to_dump[i].p) continue;
		printf("\nChunk %u:\n", i);
		struct nbt_node *node = nbt_parse_compressed(chunks_to_dump[i].p, chunks_to_dump[i].len);
		if(!node) {
			fprintf(stderr, "Failed to decode data of chunk %u, %s\n", i, nbt_error_to_string(errno));
			continue;
		}
		char *s = nbt_dump_ascii(node);
		if(s) {
			puts(s);
			free(s);
		} else {
			fprintf(stderr, "Failed to stringify data of chunk %u, %s\n", i, nbt_error_to_string(errno));
		}
		nbt_free(node);
	}

	return 0;
}
