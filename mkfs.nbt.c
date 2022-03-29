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
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

static void print_usage(const char *name) {
	fprintf(stderr, "Usage: %s [-C {gzip|zlib}] [-L <root-node-name>] [-v] <path>\n", name);
}

int main(int argc, char **argv) {
	nbt_compression_strategy compression = STRAT_GZIP;
	char *root_node_name = (char *)"";
	int verbose = 0;
	while(1) {
		int c = getopt(argc, argv, "C:L:N:vh");
		if(c == -1) break;
		switch(c) {
			case 'C':
				if(strcmp(optarg, "gzip") == 0) compression = STRAT_GZIP;
				else if(strcmp(optarg, "zlib") == 0) compression = STRAT_INFLATE;
				else {
					fprintf(stderr, "%s: Compression type %s is not supported\n",
						argv[0], optarg);
					return -1;
				}
				break;
			case 'L':
			case 'N':
				root_node_name = optarg;
				break;
			case 'v':
				verbose = 1;
				break;
			case 'h':
				print_usage(argv[0]);
				return 0;
			case '?':
				return -1;
		}
	}
	if(argc - optind != 1) {
		print_usage(argv[0]);
		return -1;
	}

	struct nbt_node root_node = {
		.type = TAG_COMPOUND,
		.name = root_node_name,
		.payload.tag_compound = malloc(sizeof(struct nbt_list))
	};
	if(!root_node.payload.tag_compound) {
		fprintf(stderr, "%s: Out of memory\n", argv[0]);
		return 1;
	}
	INIT_LIST_HEAD(&root_node.payload.tag_compound->entry);

	FILE *f = fopen(argv[optind], "wb");
	if(!f) {
		perror(argv[optind]);
		return 1;
	}

	if(verbose) {
		char *s = nbt_dump_ascii(&root_node);
		if(s) {
			fprintf(stderr, "%s: Writing following NBT tree into '%s':\n\n%s\n",
				argv[0], argv[optind], s);
			free(s);
		} else {
			fprintf(stderr, "%s: nbt_dump_ascii: %s\n", argv[0], nbt_error_to_string(errno));
		}
	}

	nbt_status status = nbt_dump_file(&root_node, f, compression);
	if(status != NBT_OK) {
		fprintf(stderr, "%s: Failed to save NBT to %s, %s\n",
			argv[0], argv[optind], nbt_error_to_string(status));
		return 1;
	}

	if(fclose(f) == EOF) {
		perror("fclose");
		return 1;
	}

	return 0;
}
