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

#define _FILE_OFFSET_BITS 64
#define FUSE_USE_VERSION 26
#include <fuse/fuse.h>
#include "nbt.h"
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#define NBT_IS_DIRECTORY(NODE) ((NODE)->type == TAG_COMPOUND || (NODE)->type == TAG_LIST)

static uid_t myuid;
static gid_t mygid;
static int read_only = 0;
static mode_t node_umask = 0;
static FILE *nbt_file;
static struct nbt_node *root_node;

static struct nbt_node *get_child_node_by_name(struct nbt_node *parent, const char *name) {
	//return nbt_find_by_name(parent, name);
	switch(parent->type) {
		int i;
		char *end_p;
		struct list_head *pos;
		case TAG_LIST:
			i = strtol(name, &end_p, 0);
			return *end_p ? NULL : nbt_list_item(parent, i);
		case TAG_COMPOUND:
			list_for_each(pos, &parent->payload.tag_compound->entry) {
				struct nbt_node *entry = list_entry(pos, struct nbt_list, entry)->data;
				if(entry->name && strcmp(entry->name, name) == 0) return entry;
			}
	}
	return NULL;
}

static struct nbt_node *get_node(struct nbt_node *parent, const char *path) {
	if(*path == '/') path++;
	if(!*path) return parent;
	size_t name_len = 1;
	while(path[name_len] && path[name_len] != '/') name_len++;
	char name[name_len + 1];
	memcpy(name, path, name_len);
	name[name_len] = 0;
	struct nbt_node *node = get_child_node_by_name(parent, name);
	if(!node) return NULL;
	return get_node(node, path + name_len);
}

static size_t get_size(struct nbt_node *node) {
	switch(node->type) {
		case TAG_BYTE:
			return snprintf(NULL, 0, "%hhd\n", (char)node->payload.tag_byte);
		case TAG_SHORT:
			return snprintf(NULL, 0, "%d\n", (int)node->payload.tag_short);
		case TAG_INT:
			return snprintf(NULL, 0, "%d\n", (int)node->payload.tag_int);
		case TAG_LONG:
			return snprintf(NULL, 0, "%lld\n", (long long int)node->payload.tag_long);
		case TAG_FLOAT:
			return snprintf(NULL, 0, "%f\n", (double)node->payload.tag_float);
		case TAG_DOUBLE:
			return snprintf(NULL, 0, "%f\n", node->payload.tag_double);
		case TAG_BYTE_ARRAY:
			return node->payload.tag_byte_array.length;
		case TAG_STRING:
			return strlen(node->payload.tag_string);
		case TAG_LIST:
		case TAG_COMPOUND:
			return nbt_size(node);
		case TAG_INT_ARRAY:
			return node->payload.tag_int_array.length * 4;
		case TAG_LONG_ARRAY:
			return node->payload.tag_long_array.length * 8;
		default:
			return 0;
	}
}

static int nbt_fgetattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
	struct nbt_node *node = (struct nbt_node *)fi->fh;
	memset(stbuf, 0, sizeof *stbuf);
	stbuf->st_uid = myuid;
	stbuf->st_gid = mygid;
	stbuf->st_ino = (ino_t)node;
	stbuf->st_mode = NBT_IS_DIRECTORY(node) ? (0777 | S_IFDIR) : (0666 | S_IFREG);
	stbuf->st_mode &= ~node_umask;
	stbuf->st_nlink = 1;
	stbuf->st_size = get_size(node);
	return 0;
}

static int nbt_getattr(const char *path, struct stat *stbuf) {
	struct nbt_node *node = get_node(root_node, path);
	if(!node) return -ENOENT;
	struct fuse_file_info fi = { .fh = (uint64_t)node };
	return nbt_fgetattr(path, stbuf, &fi);
}

static int nbt_open(const char *path, struct fuse_file_info *fi) {
	struct nbt_node *node = get_node(root_node, path);
	if(!node) return -ENOENT;
	fi->fh = (uint64_t)node;
	return 0;
}

static int nbt_read(const char *path, char *out_buf, size_t size, off_t offset, struct fuse_file_info *fi) {
	char buffer[4096];
	size_t length;
	struct nbt_node *node = (struct nbt_node *)fi->fh;
	switch(node->type) {
		case TAG_BYTE:
			length = sprintf(buffer, "%hhd\n", (char)node->payload.tag_byte);
			break;
		case TAG_SHORT:
			length = sprintf(buffer, "%d\n", (int)node->payload.tag_short);
			break;
		case TAG_INT:
			length = sprintf(buffer, "%d\n", (int)node->payload.tag_int);
			break;
		case TAG_LONG:
			length = sprintf(buffer, "%lld\n", (long long int)node->payload.tag_long);
			break;
		case TAG_FLOAT:
			length = sprintf(buffer, "%f\n", (double)node->payload.tag_float);
			break;
		case TAG_DOUBLE:
			length = sprintf(buffer, "%f\n", node->payload.tag_double);
			break;
		case TAG_BYTE_ARRAY:
			length = node->payload.tag_byte_array.length;
			if(length <= offset) return 0;
			length -= offset;
			if(length > sizeof buffer) length = sizeof buffer;
			memcpy(buffer, node->payload.tag_byte_array.data + offset, length);
			offset = 0;
			break;
		case TAG_STRING:
			length = strlen(node->payload.tag_string);
			if(length <= offset) return 0;
			length -= offset;
			if(length > sizeof buffer) length = sizeof buffer;
			memcpy(buffer, node->payload.tag_string + offset, length);
			offset = 0;
			break;
		case TAG_LIST:
		case TAG_COMPOUND:
			return -EISDIR;
		case TAG_INT_ARRAY:
		case TAG_LONG_ARRAY:
			return -EPERM;
		default:
			return -EIO;
	}
	if(offset + size > length) {
		if((size_t)offset >= length) return 0;
		size = length - offset;
	}
	memcpy(out_buf, buffer + offset, size);
	return size;
}

static int nbt_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
	struct nbt_node *node = (struct nbt_node *)fi->fh;
	switch(node->type) {
		unsigned int i;
		char text_buffer[32];
		struct list_head *pos;
		case TAG_LIST:
			i = 0;
			list_for_each(pos, &node->payload.tag_compound->entry) {
				sprintf(text_buffer, "%u", i++);
				filler(buf, text_buffer, NULL, 0);
			}
			break;
		case TAG_COMPOUND:
			list_for_each(pos, &node->payload.tag_compound->entry) {
				struct nbt_node *entry = list_entry(pos, struct nbt_list, entry)->data;
				if(entry->name) filler(buf, entry->name, NULL, 0);
			}
			break;
		default:
			return -ENOTDIR;
	}
	return 0;
}

static char *parse_extended_options(char *o) {
	char *fuse_opt = NULL;
	size_t fuse_opt_len = 0;
	char *comma;
	do {
		comma = strchr(o, ',');
		if(comma) *comma++ = 0;
		if(strcmp(o, "ro") == 0) read_only = 1;
		else if(strcmp(o, "rw") == 0) read_only = 0;
		else if(strncmp(o, "umask=", 6) == 0) node_umask = strtol(o + 6, NULL, 8) & 0777;
		else {
			if(fuse_opt_len) {
				fuse_opt[fuse_opt_len++] = ',';
			}
			size_t i = fuse_opt_len;
			size_t len = strlen(o);
			fuse_opt_len += len;
			fuse_opt = realloc(fuse_opt, fuse_opt_len + 1);
			if(!fuse_opt) {
				perror("parse_extended_options: realloc");
				exit(1);
			}
			memcpy(fuse_opt + i, o, len + 1);
		}
	} while(comma && *(o = comma));
	return fuse_opt;
}

static void print_usage(const char *name) {
	fprintf(stderr, "Usage: %s [-o <fs-options>] [-fnrvw] <nbt-file> <mount-point>\n",
		name);
}

static struct fuse_operations operations = {
	.fgetattr	= nbt_fgetattr,
	.getattr	= nbt_getattr,
	.open		= nbt_open,
	.opendir	= nbt_open,
	.read		= nbt_read,
	.readdir	= nbt_readdir,
};

int main(int argc, char **argv) {
	int fuse_argc = 1;
	char **fuse_argv = malloc(2 * sizeof(char *));
	if(!fuse_argv) {
		perror("malloc");
		return 1;
	}
	char *fuse_extended_options;
	int verbose = 0;
	while(1) {
		int c = getopt(argc, argv, "fo:nrvwF:t:h");
		if(c == -1) break;
		switch(c) {
			case 'f':
				fuse_argc++;
				fuse_argv = realloc(fuse_argv, (fuse_argc + 1) * sizeof(char *));
				if(!fuse_argv) {
					perror("realloc");
					return 1;
				}
				fuse_argv[fuse_argc - 1] = "-f";
				break;
			case 'o':
				fuse_extended_options = parse_extended_options(optarg);
				if(fuse_extended_options) {
					fuse_argc += 2;
					fuse_argv = realloc(fuse_argv, (fuse_argc + 1) * sizeof(char *));
					if(!fuse_argv) {
						perror("realloc");
						return 1;
					}
					fuse_argv[fuse_argc - 2] = "-o";
					fuse_argv[fuse_argc - 1] = fuse_extended_options;
				}
				break;
			case 'n':
				break;
			case 'r':
				read_only = 1;
				break;
			case 'v':
				verbose++;
				break;
			case 'w':
				read_only = 0;
				break;
			case 'F':
			case 't':
				if(strcmp(optarg, "nbt")) {
					fprintf(stderr, "%s: The file system type may only be specified as 'nbt'\n",
						argv[0]);
					return -1;
				}
				break;
			case 'h':
				print_usage(argv[0]);
				return 0;
			case '?':
				print_usage(argv[0]);
				return -1;
		}
	}
	if(argc - optind != 2) {
		print_usage(argv[0]);
		return -1;
	}
	myuid = getuid();
	mygid = getgid();
	nbt_file = fopen(argv[optind], read_only ? "rb" : "r+b");
	if(!nbt_file) {
		perror(argv[optind]);
		return 1;
	}
	root_node = nbt_parse_file(nbt_file);
	if(!root_node) {
		fprintf(stderr, "%s: Failed to mount %s, %s\n", argv[0], argv[optind], nbt_error_to_string(errno));
		return 1;
	}
	fuse_argc += argc - optind - 1;
	fuse_argv = realloc(fuse_argv, (fuse_argc + 1) * sizeof(char *));
	if(!fuse_argv) {
		perror("realloc");
		return 1;
	}
	fuse_argv[0] = argv[optind];
	memcpy(fuse_argv + (fuse_argc - (argc - optind - 1)), argv + optind + 1, (argc - optind) * sizeof(char *));
	return fuse_main(fuse_argc, fuse_argv, &operations, NULL);
}
