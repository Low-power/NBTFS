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
#include <string.h>
#include <stdio.h>
#include <errno.h>

int main(int argc, char **argv) {
	if(argv[1] && strcmp(argv[1], "--") == 0) {
		argc--;
		argv[1] = argv[0];
		argv++;
	}
	if(argc != 2) {
		fprintf(stderr, "Usage: %s <nbt-file>\n", argv[0]);
		return -1;
	}

	FILE *f = fopen(argv[1], "rb");
	if(!f) {
		perror(argv[1]);
		return 1;
	}

	struct nbt_node *root_node = nbt_parse_file(f);
	if(!root_node) {
		fprintf(stderr, "%s: Failed to load '%s', %s\n",
			argv[0], argv[1], nbt_error_to_string(errno));
		return 1;
	}
	fclose(f);
	nbt_status status = nbt_dump_ascii_file(root_node, stdout);
	nbt_free(root_node);
	if(status != NBT_OK) {
		fprintf(stderr, "%s: Failed to stringify NBT data from '%s', %s\n",
			argv[0], argv[1], nbt_error_to_string(status));
		return 1;
	}
	return 0;
}
