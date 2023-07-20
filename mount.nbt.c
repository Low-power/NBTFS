/*	Copyright 2015-2023 Rivoreo

	This Source Code Form is subject to the terms of the Mozilla Public
	License, v. 2.0. If a copy of the MPL was not distributed with this
	file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/

#include "version.h"
#define _FILE_OFFSET_BITS 64
#define FUSE_USE_VERSION 26
#include <fuse/fuse.h>
#include <fuse/fuse_lowlevel.h>		/* For fuse_req_t and fuse_ino_t */
#include "nbt.h"
#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "syncrw.h"
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <assert.h>

#define IS_LIST_EMPTY(LIST) (&(LIST)->entry == (LIST)->entry.flink)
// NBT_IS_DIRECTORY is not used for region root node
#define NBT_IS_DIRECTORY(NODE) ((NODE)->type == NORMAL_NODE && ((NODE)->node->type == TAG_COMPOUND || (NODE)->node->type == TAG_LIST || (NODE)->node->type == TAG_INT_ARRAY || (NODE)->node->type == TAG_LONG_ARRAY))
#define SET_MODIFIED(NODE) do { if((NODE)->chunk) (NODE)->chunk->is_modified = 1; else is_modified = 1; } while(0)

struct wrapped_nbt_node {
	struct wrapped_nbt_node *self;
	enum {
		NORMAL_NODE, REGION_ROOT_NODE, LIST_TYPE_NODE, ARRAY_ELEMENT_NODE
	} type;
	struct nbt_node *node;
	union {
		struct list_head *head;
		int index;
	} pos;
	struct chunk_info *chunk;
};

static uid_t myuid;
static gid_t mygid;
static int read_only = 0;
static mode_t node_umask = 0;
static int use_type_prefix = 0;
static int is_region = 0;
static const char *write_file_path = NULL;
static int compression = -1;

static struct wrapped_nbt_node root_node = { .self = &root_node };

static int need_full_write;
static int region_fd = -1;
static size_t region_file_size = 0;
static void *region_map = NULL;
static struct chunk_info {
	uint32_t raw_offset_and_size;
	uint32_t raw_mtime;
	off_t file_offset;
	size_t file_size;
	void *map_begin;
	size_t length;
	struct nbt_node *nbt_node;
	int is_modified;
} region_chunks[1024];

static FILE *nbt_file = NULL;
static int is_modified = 0;

static nbt_type get_nbt_type_by_name_prefix(const char *name, size_t len) {
	switch(len) {
		case 4:
			if(strncmp(name, "byte", 4) == 0) return TAG_BYTE;
			else if(strncmp(name, "int8", 4) == 0) return TAG_BYTE;
			else if(strncmp(name, "list", 4) == 0) return TAG_LIST;
			else break;
		case 5:
			if(strncmp(name, "int16", 5) == 0) return TAG_SHORT;
			else if(strncmp(name, "int32", 5) == 0) return TAG_INT;
			else if(strncmp(name, "int64", 5) == 0) return TAG_LONG;
			else if(strncmp(name, "float", 5) == 0) return TAG_FLOAT;
			else break;
		case 6:
			if(strncmp(name, "string", 6) == 0) return TAG_STRING;
			else if(strncmp(name, "single", 6) == 0) return TAG_FLOAT;
			else if(strncmp(name, "double", 6) == 0) return TAG_DOUBLE;
			else break;
		case 7:
			if(strncmp(name, "float32", 7) == 0) return TAG_FLOAT;
			else if(strncmp(name, "float64", 7) == 0) return TAG_DOUBLE;
			else break;
		case 8:
			if(strncmp(name, "compound", 8) == 0) return TAG_COMPOUND;
			else break;
		case 9:
			if(strncmp(name, "bytearray", 9) == 0) return TAG_BYTE_ARRAY;
			else if(strncmp(name, "int8array", 9) == 0) return TAG_BYTE_ARRAY;
			else break;
		case 10:
			if(strncmp(name, "int32array", 10) == 0) return TAG_INT_ARRAY;
			else if(strncmp(name, "int64array", 10) == 0) return TAG_LONG_ARRAY;
			else break;
	}
	return TAG_INVALID;
}

static const char *get_node_type_name(const struct nbt_node *node) {
	switch(node->type) {
		case TAG_BYTE:
			return "int8";
		case TAG_SHORT:
			return "int16";
		case TAG_INT:
			return "int32";
		case TAG_LONG:
			return "int64";
		case TAG_FLOAT:
			return "float32";
		case TAG_DOUBLE:
			return "float64";
		case TAG_STRING:
			return "string";
		case TAG_LIST:
			return "list";
		case TAG_COMPOUND:
			return "compound";
		case TAG_BYTE_ARRAY:
			return "int8array";
		case TAG_INT_ARRAY:
			return "int32array";
		case TAG_LONG_ARRAY:
			return "int64array";
		default:
			return NULL;
	}
}

static struct wrapped_nbt_node *get_child_node_by_name(struct wrapped_nbt_node *parent, const char *name) {
	if(is_region && parent->type == REGION_ROOT_NODE) {
		char *end_p;
		unsigned int i = strtoul(name, &end_p, 0);
		if(*end_p) return NULL;
		if(i >= 1024) return NULL;
		struct chunk_info *info = region_chunks + i;
		if(!info->nbt_node) {
			if(!info->map_begin) return NULL;
			info->nbt_node = nbt_parse_compressed((char *)info->map_begin + 1, info->length - 1);
			if(!info->nbt_node) return NULL;
		}
		struct wrapped_nbt_node *r = malloc(sizeof(struct wrapped_nbt_node));
		if(!r) return NULL;
		r->self = r;
		r->type = NORMAL_NODE;
		r->node = info->nbt_node;
		r->pos.head = NULL;
		r->chunk = info;
		return r;
	}

	if(parent->type != NORMAL_NODE) return NULL;

	nbt_type type = TAG_INVALID;
	const char *colon = strchr(name, ':');
	if(colon) {
		type = get_nbt_type_by_name_prefix(name, colon - name);
		if(type == TAG_INVALID) return NULL;
		name = colon + 1;
	}
	switch(parent->node->type) {
			long int i, j;
			char *end_p;
			struct list_head *pos;
		case TAG_LIST:
			if(type != TAG_INVALID) return NULL;
			if(strcmp(name, ".type") == 0) {
				struct nbt_node *type_name_node = malloc(sizeof(struct nbt_node));
				if(!type_name_node) return NULL;
				type_name_node->type = 128;
				type_name_node->payload.tag_list = parent->node->payload.tag_list;
				struct wrapped_nbt_node *r = malloc(sizeof(struct wrapped_nbt_node));
				if(!r) {
					free(type_name_node);
					errno = ENOMEM;
					return NULL;
				}
				r->self = r;
				r->type = LIST_TYPE_NODE;
				r->node = type_name_node;
				r->pos.head = NULL;
				r->chunk = parent->chunk;
				return r;
			}
			i = strtol(name, &end_p, 0);
			if(*end_p) return NULL;
			j = 0;
			list_for_each(pos, &parent->node->payload.tag_list->entry) {
				if(j++ == i) {
					struct wrapped_nbt_node *r = malloc(sizeof(struct wrapped_nbt_node));
					if(!r) return NULL;
					r->self = r;
					r->type = NORMAL_NODE;
					r->node = list_entry(pos, struct nbt_list, entry)->data;
					r->pos.head = pos;
					r->chunk = parent->chunk;
					return r;
				}
			}
			break;
		case TAG_COMPOUND:
			list_for_each(pos, &parent->node->payload.tag_compound->entry) {
				struct nbt_node *entry = list_entry(pos, struct nbt_list, entry)->data;
				if(type != TAG_INVALID && entry->type != type) continue;
				if(entry->name && strcmp(entry->name, name) == 0) {
					struct wrapped_nbt_node *r = malloc(sizeof(struct wrapped_nbt_node));
					if(!r) return NULL;
					r->self = r;
					r->type = NORMAL_NODE;
					r->node = entry;
					r->pos.head = pos;
					r->chunk = parent->chunk;
					return r;
				}
			}
			break;
		case TAG_INT_ARRAY:
			j = parent->node->payload.tag_int_array.length;
			goto array;
		case TAG_LONG_ARRAY:
			j = parent->node->payload.tag_long_array.length;
		array:
			i = strtol(name, &end_p, 0);
			if(*end_p) return NULL;
			if(i < 0 || i >= j) return NULL;
			struct wrapped_nbt_node *r = malloc(sizeof(struct wrapped_nbt_node));
			if(!r) return NULL;
			r->self = r;
			r->type = ARRAY_ELEMENT_NODE;
			r->node = parent->node;
			r->pos.index = i;
			r->chunk = parent->chunk;
			return r;
	}
	return NULL;
}

static void free_wrapped_node(struct wrapped_nbt_node *node) {
	if(node && node->type == LIST_TYPE_NODE) free(node->node);
	free(node);
}

static struct wrapped_nbt_node *get_node(struct wrapped_nbt_node *parent, const char *path) {
	if(*path == '/') path++;
	if(!*path) return parent;
	size_t name_len = 1;
	while(path[name_len] && path[name_len] != '/') name_len++;
	char name[name_len + 1];
	memcpy(name, path, name_len);
	name[name_len] = 0;
	struct wrapped_nbt_node *node = get_child_node_by_name(parent, name);
	if(!node) return NULL;
	struct wrapped_nbt_node *r = get_node(node, path + name_len);
	if(node != r) free_wrapped_node(node);
	return r;
}

static int init_node(struct nbt_node *node) {
	switch(node->type) {
		case TAG_BYTE:
			node->payload.tag_byte = 0;
			break;
		case TAG_SHORT:
			node->payload.tag_short = 0;
			break;
		case TAG_INT:
			node->payload.tag_int = 0;
			break;
		case TAG_LONG:
			node->payload.tag_long = 0;
			break;
		case TAG_FLOAT:
			node->payload.tag_float = 0;
			break;
		case TAG_DOUBLE:
			node->payload.tag_double = 0;
			break;
		case TAG_STRING:
			node->payload.tag_string = malloc(1);
			if(!node->payload.tag_string) return -1;
			*node->payload.tag_string = 0;
			break;
		case TAG_LIST:
			node->payload.tag_list = malloc(sizeof(struct nbt_list));
			if(!node->payload.tag_compound) return -1;
			node->payload.tag_compound->data = malloc(sizeof(struct nbt_node));
			if(!node->payload.tag_compound->data) {
				free(node->payload.tag_compound);
				errno = ENOMEM;
				return -1;
			}
			memset(node->payload.tag_compound->data, 0, sizeof(struct nbt_node));
			//node->payload.tag_compound->data->type = TAG_INVALID;
			INIT_LIST_HEAD(&node->payload.tag_compound->entry);
			break;
		case TAG_COMPOUND:
			node->payload.tag_compound = malloc(sizeof(struct nbt_list));
			if(!node->payload.tag_compound) return -1;
			node->payload.tag_compound->data = NULL;
			INIT_LIST_HEAD(&node->payload.tag_compound->entry);
			break;
		case TAG_BYTE_ARRAY:
			node->payload.tag_byte_array.data = NULL;
			node->payload.tag_byte_array.length = 0;
			break;
		case TAG_INT_ARRAY:
			node->payload.tag_int_array.data = NULL;
			node->payload.tag_int_array.length = 0;
			break;
		case TAG_LONG_ARRAY:
			node->payload.tag_long_array.data = NULL;
			node->payload.tag_long_array.length = 0;
			break;
		default:
			errno = EINVAL;
			return -1;
	}
	return 0;
}

static struct wrapped_nbt_node *create_node(struct wrapped_nbt_node *parent, const char *path) {
	struct wrapped_nbt_node *orig_parent_node = parent;
	if(*path == '/') path++;
	const char *p = strrchr(path, '/');
	if(p) {
		size_t node_path_len = ++p - path;
		char node_path[node_path_len + 1];
		memcpy(node_path, path, node_path_len);
		node_path[node_path_len] = 0;
		errno = ENOENT;
		parent = get_node(parent, node_path);
		if(!parent) return NULL;
		path = p;
	} else if(is_region && parent->type == REGION_ROOT_NODE) {
		errno = EINVAL;
		return NULL;
	}
	if(parent->type != NORMAL_NODE) {
		if(parent != orig_parent_node) free(parent);
		errno = ENOTDIR;
		return NULL;
	}
	nbt_type type;
	const char *name;
	struct list_head *parent_list_head;
	switch(parent->node->type) {
			unsigned long int i;
			char *end_p;
			struct list_head *pos;
		case TAG_LIST:
			i = strtoul(path, &end_p, 0);
			if(*end_p) {
				if(parent != orig_parent_node) free(parent);
				errno = EINVAL;
				return NULL;
			}
			type = parent->node->payload.tag_list->data->type;
			if(type == TAG_INVALID) {
				if(parent != orig_parent_node) free(parent);
				errno = EPERM;
				return NULL;
			}
			name = NULL;
			parent_list_head = &parent->node->payload.tag_list->entry;
			if(i != list_length(parent_list_head)) {
				if(parent != orig_parent_node) free(parent);
				errno = EPERM;
				return NULL;
			}
			break;
		case TAG_COMPOUND:
			p = strchr(path, ':');
			if(!p) {
				if(parent != orig_parent_node) free(parent);
				errno = EINVAL;
				return NULL;
			}
			type = get_nbt_type_by_name_prefix(path, p - path);
			if(type == TAG_INVALID) {
				if(parent != orig_parent_node) free(parent);
				errno = EINVAL;
				return NULL;
			}
			name = p + 1;
			if(!*name) {
				if(parent != orig_parent_node) free(parent);
				errno = EINVAL;
				return NULL;
			}
			parent_list_head = &parent->node->payload.tag_compound->entry;
			list_for_each(pos, parent_list_head) {
				struct nbt_node *entry = list_entry(pos, struct nbt_list, entry)->data;
				if(entry->name && strcmp(entry->name, name) == 0) {
					if(parent != orig_parent_node) free(parent);
					errno = EEXIST;
					return NULL;
				}
			}
			break;

#define EXTEND_ARRAY_AND_RETURN_LAST_ELEMENT(NODE_PAYLOAD) do {				\
		long int i = strtol(path, &end_p, 0);					\
		if(*end_p) {								\
			if(parent != orig_parent_node) free(parent);			\
			errno = EINVAL;							\
			return NULL;							\
		}									\
		if(i < (NODE_PAYLOAD).length) {						\
			if(parent != orig_parent_node) free(parent);			\
			errno = EEXIST;							\
			return NULL;							\
		}									\
		struct wrapped_nbt_node *r = malloc(sizeof(struct wrapped_nbt_node));	\
		if(!r) {								\
			if(parent != orig_parent_node) free(parent);			\
			errno = ENOMEM;							\
			return NULL;							\
		}									\
		void *p = realloc((NODE_PAYLOAD).data, (i + 1) * sizeof *(NODE_PAYLOAD).data);	\
		if(!p) {								\
			if(parent != orig_parent_node) free(parent);			\
			free(r);							\
			errno = ENOMEM;							\
			return NULL;							\
		}									\
		(NODE_PAYLOAD).data = p;						\
		size_t extended_size = (i + 1 - (NODE_PAYLOAD).length) * sizeof *(NODE_PAYLOAD).data;	\
		memset((NODE_PAYLOAD).data + (NODE_PAYLOAD).length, 0, extended_size);	\
		(NODE_PAYLOAD).length = i + 1;						\
		r->self = r;								\
		r->type = ARRAY_ELEMENT_NODE;						\
		r->node = parent->node;							\
		r->pos.index = i;							\
		r->chunk = parent->chunk;						\
		return r;								\
	} while(0)

		case TAG_INT_ARRAY:
			EXTEND_ARRAY_AND_RETURN_LAST_ELEMENT(parent->node->payload.tag_int_array);
		case TAG_LONG_ARRAY:
			EXTEND_ARRAY_AND_RETURN_LAST_ELEMENT(parent->node->payload.tag_long_array);

#undef EXTEND_ARRAY_AND_RETURN_LAST_ELEMENT

		default:
			if(parent != orig_parent_node) free(parent);
			errno = ENOTDIR;
			return NULL;
	}
	struct nbt_node *node = malloc(sizeof(struct nbt_node));
	if(!node) return NULL;
	node->type = type;
	if(name) {
		node->name = strdup(name);
		if(!node->name) {
			free(node);
			if(parent != orig_parent_node) free(parent);
			errno = ENOMEM;
			return NULL;
		}
	} else {
		node->name = NULL;
	}
	if(init_node(node) < 0) {
		free(node);
		if(parent != orig_parent_node) free(parent);
		return NULL;
	}
	struct wrapped_nbt_node *r = malloc(sizeof(struct wrapped_nbt_node));
	if(!r) {
		nbt_free(node);
		if(parent != orig_parent_node) free(parent);
		errno = ENOMEM;
		return NULL;
	}
	r->self = r;
	r->type = NORMAL_NODE;
	r->node = node;
	r->chunk = parent->chunk;
	if(parent != orig_parent_node) free(parent);
	struct nbt_list *new_list = malloc(sizeof(struct nbt_list));
	if(!new_list) {
		nbt_free(node);
		free(r);
		errno = ENOMEM;
		return NULL;
	}
	new_list->data = node;
	list_add_tail(&new_list->entry, parent_list_head);
	r->pos.head = &new_list->entry;
	SET_MODIFIED(r);
	return r;
}

static struct wrapped_nbt_node *file_info_to_nbt_node(const struct fuse_file_info *fi) {
	struct wrapped_nbt_node *node = (struct wrapped_nbt_node *)fi->fh;
	if(node->self == node) return node;
	struct fuse_dir_handle {
		pthread_mutex_t lock;
		struct fuse *fuse;
		fuse_req_t req;
		char *contents;
		int allocated;
		unsigned int len;
		unsigned int size;
		unsigned int needlen;
		int filled;
		uint64_t fh;
		int error;
		fuse_ino_t nodeid;
	} *dirh = (struct fuse_dir_handle *)fi->fh;
	node = (struct wrapped_nbt_node *)dirh->fh;
	assert(node->self == node);
	return node;
}

static size_t get_size(struct wrapped_nbt_node *node) {
	switch(node->type) {
			const char *s;
		case NORMAL_NODE:
			break;
		case LIST_TYPE_NODE:
			s = get_node_type_name(node->node->payload.tag_list->data);
			return s ? strlen(s) + 1 : 8;
		case ARRAY_ELEMENT_NODE:
			switch(node->node->type) {
				case TAG_INT_ARRAY:
					return snprintf(NULL, 0, "%d\n", (int)node->node->payload.tag_int_array.data[node->pos.index]);
				case TAG_LONG_ARRAY:
					return snprintf(NULL, 0, "%lld\n", (long long int)node->node->payload.tag_long_array.data[node->pos.index]);
			}
			// Fallthrough
		default:
			return 0;
	}
	switch(node->node->type) {
		case TAG_BYTE:
			return snprintf(NULL, 0, "%hhd\n", (char)node->node->payload.tag_byte);
		case TAG_SHORT:
			return snprintf(NULL, 0, "%d\n", (int)node->node->payload.tag_short);
		case TAG_INT:
			return snprintf(NULL, 0, "%d\n", (int)node->node->payload.tag_int);
		case TAG_LONG:
			return snprintf(NULL, 0, "%lld\n", (long long int)node->node->payload.tag_long);
		case TAG_FLOAT:
			return snprintf(NULL, 0, "%f\n", (double)node->node->payload.tag_float);
		case TAG_DOUBLE:
			return snprintf(NULL, 0, "%f\n", node->node->payload.tag_double);
		case TAG_STRING:
			if(!node->node->payload.tag_string) return 0;
			return strlen(node->node->payload.tag_string) + 1;
		case TAG_LIST:
		case TAG_COMPOUND:
			return nbt_size(node->node);
		case TAG_BYTE_ARRAY:
			return node->node->payload.tag_byte_array.length;
		case TAG_INT_ARRAY:
			return node->node->payload.tag_int_array.length * 4;
		case TAG_LONG_ARRAY:
			return node->node->payload.tag_long_array.length * 8;
		default:
			return 0;
	}
}

static int nbt_release(const char *path, struct fuse_file_info *fi) {
	struct wrapped_nbt_node *node = (struct wrapped_nbt_node *)fi->fh;
	if(node == &root_node) return 0;
	free_wrapped_node(node);
	return 0;
}

static int nbt_fgetattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
	struct wrapped_nbt_node *node = file_info_to_nbt_node(fi);
	memset(stbuf, 0, sizeof *stbuf);
	stbuf->st_uid = myuid;
	stbuf->st_gid = mygid;
	stbuf->st_nlink = 1;
	if(is_region && node->type == REGION_ROOT_NODE) {
		stbuf->st_ino = 1;
		stbuf->st_mode = (0777 | S_IFDIR) & ~node_umask;
	} else {
		stbuf->st_ino = (ino_t)node;
		stbuf->st_mode = NBT_IS_DIRECTORY(node) ? (0777 | S_IFDIR) : (0666 | S_IFREG);
		stbuf->st_mode &= ~node_umask;
		stbuf->st_size = get_size(node);
	}
	return 0;
}

static int nbt_getattr(const char *path, struct stat *stbuf) {
	errno = ENOENT;
	struct wrapped_nbt_node *node = get_node(&root_node, path);
	if(!node) return -errno;
	struct fuse_file_info fi = { .fh = (uint64_t)node };
	int ne = nbt_fgetattr(path, stbuf, &fi);
	nbt_release(path, &fi);
	return ne;
}

static int nbt_ftruncate(const char *path, off_t length, struct fuse_file_info *fi) {
	if(read_only) return -EROFS;
	struct wrapped_nbt_node *node = file_info_to_nbt_node(fi);
	switch(node->type) {
		case NORMAL_NODE:
			break;
		case REGION_ROOT_NODE:
			if(!is_region) {
				syslog(LOG_ERR, "REGION_ROOT_NODE (%s) appears in non-region mount", path);
				return -EIO;
			}
			return -EISDIR;
		case LIST_TYPE_NODE:
			if(!IS_LIST_EMPTY(node->node->payload.tag_list)) return -ENOTEMPTY;
			// Silently ignore
			return 0;
		case ARRAY_ELEMENT_NODE:
			if(length == (node->node->type == TAG_INT_ARRAY ? 4 : 8)) return 0;
			if(length) return -EINVAL;
			switch(node->node->type) {
				case TAG_INT_ARRAY:
					node->node->payload.tag_int_array.data[node->pos.index] = 0;
					break;
				case TAG_LONG_ARRAY:
					node->node->payload.tag_long_array.data[node->pos.index] =
0;
					break;
				default:
					return -EIO;
			}
			SET_MODIFIED(node);
			return 0;
		default:
			return -EIO;
	}
	switch(node->node->type) {
			void *p;
		case TAG_BYTE:
			if(length == 1) return 0;
			if(length) return -EINVAL;
			node->node->payload.tag_byte = 0;
			break;
		case TAG_SHORT:
			if(length == 2) return 0;
			if(length) return -EINVAL;
			node->node->payload.tag_short = 0;
			break;
		case TAG_INT:
			if(length == 4) return 0;
			if(length) return -EINVAL;
			node->node->payload.tag_int = 0;
			break;
		case TAG_LONG:
			if(length == 8) return 0;
			if(length) return -EINVAL;
			node->node->payload.tag_long = 0;
			break;
		case TAG_FLOAT:
			if(length == 4) return 0;
			if(length) return -EINVAL;
			node->node->payload.tag_float = 0;
			break;
		case TAG_DOUBLE:
			if(length == 8) return 0;
			if(length) return -EINVAL;
			node->node->payload.tag_double = 0;
			break;
		case TAG_STRING:
			p = realloc(node->node->payload.tag_string, length + 1);
			if(!p) return -ENOMEM;
			node->node->payload.tag_string = p;
			node->node->payload.tag_string[length] = 0;
			break;
		case TAG_BYTE_ARRAY:
			p = realloc(node->node->payload.tag_byte_array.data, length);
			if(length && !p) return -ENOMEM;
			node->node->payload.tag_byte_array.data = p;
			node->node->payload.tag_byte_array.length = length;
			break;
		case TAG_INT_ARRAY:
			if(length % 4) return -EINVAL;
			p = realloc(node->node->payload.tag_int_array.data, length);
			if(length && !p) return -ENOMEM;
			node->node->payload.tag_int_array.data = p;
			node->node->payload.tag_int_array.length = length / 4;
			break;
		case TAG_LONG_ARRAY:
			if(length % 8) return -EINVAL;
			p = realloc(node->node->payload.tag_long_array.data, length);
			if(length && !p) return -ENOMEM;
			node->node->payload.tag_long_array.data = p;
			node->node->payload.tag_long_array.length = length / 8;
			break;
		case TAG_LIST:
		case TAG_COMPOUND:
			return -EISDIR;
		default:
			return -EIO;
	}
	SET_MODIFIED(node);
	return 0;
}

static int nbt_truncate(const char *path, off_t length) {
	if(read_only) return -EROFS;
	struct wrapped_nbt_node *node = get_node(&root_node, path);
	if(!node) return -ENOENT;
	struct fuse_file_info fi = { .fh = (uint64_t)node };
	int ne = nbt_ftruncate(path, length, &fi);
	nbt_release(path, &fi);
	return ne;
}

static int nbt_open(const char *path, struct fuse_file_info *fi) {
	if((fi->flags & (O_RDONLY|O_WRONLY|O_RDWR)) == O_RDONLY) {
		if(fi->flags & O_TRUNC) return -EINVAL;
	} else if(read_only) return -EROFS;
	struct wrapped_nbt_node *node = get_node(&root_node, path);
	if(!node) return -ENOENT;
	fi->fh = (uint64_t)node;
	if(fi->flags & O_TRUNC) {
		int ne = nbt_ftruncate(path, 0, fi);
		if(ne) {
			free(node);
			return ne;
		}
	}
	return 0;
}

static int nbt_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
	if(read_only) return -EROFS;
	errno = ENOENT;
	struct wrapped_nbt_node *node = create_node(&root_node, path);
	if(!node) return -errno;
	fi->fh = (uint64_t)node;
	return 0;
}

static int nbt_mkdir(const char *path, mode_t mode) {
	if(read_only) return -EROFS;
	errno = ENOENT;
	struct wrapped_nbt_node *node = create_node(&root_node, path);
	if(!node) return -errno;
	free(node);
	return 0;
}

// Return negative errno
static int get_parent_node(const char *path, struct wrapped_nbt_node **parent, const char **child_name) {
	if(*path == '/') path++;
	*child_name = strrchr(path, '/');
	if(*child_name) {
		size_t node_path_len = ++(*child_name) - path;
		char node_path[node_path_len + 1];
		memcpy(node_path, path, node_path_len);
		node_path[node_path_len] = 0;
		*parent = get_node(&root_node, node_path);
		if(!*parent) return -ENOENT;
		if(!NBT_IS_DIRECTORY(*parent)) {
			if(*parent != &root_node) free_wrapped_node(*parent);
			return -ENOTDIR;
		}
	} else {
		*parent = &root_node;
		*child_name = path;
	}
	return 0;
}

static int nbt_remove_node(const char *path, int dir_only) {
	struct wrapped_nbt_node *node = NULL;
	struct wrapped_nbt_node *parent_node;
	const char *name;
	int ne = get_parent_node(path, &parent_node, &name);
	if(ne) return ne;
	if(!*name) {
		// Attempt to remove root node
		ne = -EINVAL;
		goto cleanup;
	}
	if(parent_node->type == REGION_ROOT_NODE) {
		// TODO
		ne = -EPERM;
		goto cleanup;
	}
	if(read_only) {
		ne = -EROFS;
		goto cleanup;
	}
	errno = ENOENT;
	node = get_child_node_by_name(parent_node, name);
	if(!node) {
		ne = -errno;
		goto cleanup;
	}
	if(node == &root_node) {
		node = NULL;
		ne = -EINVAL;
		goto cleanup;
	}
	switch(node->type) {
			void **p;
			int32_t *len;
			unsigned int element_size;
		case NORMAL_NODE:
			if(!node->pos.head) goto missing_link_head;
			break;
		case LIST_TYPE_NODE:
		missing_link_head:
			ne = -EPERM;
			goto cleanup;
		case ARRAY_ELEMENT_NODE:
			if(dir_only) {
				ne = -ENOTDIR;
				goto cleanup;
			}
			switch(node->node->type) {
				case TAG_INT_ARRAY:
					p = (void **)&node->node->payload.tag_int_array.data;
					len = &node->node->payload.tag_int_array.length;
					element_size = 4;
					break;
				case TAG_LONG_ARRAY:
					p = (void **)&node->node->payload.tag_long_array.data;
					len = &node->node->payload.tag_long_array.length;
					element_size = 8;
					break;
				default:
					goto eio;
			}
			if(node->pos.index + 1 < *len) {
				ne = -EBUSY;
				goto cleanup;
			}
			if(node->pos.index >= *len) {
				ne = -ENOENT;
				goto cleanup;
			}
			*p = realloc(*p, node->pos.index * element_size);
			(*len)--;
			SET_MODIFIED(node);
			ne = 0;
			goto cleanup;
		default:
		eio:
			ne = -EIO;
			goto cleanup;
	}
	if(dir_only) switch(node->node->type) {
		case TAG_LIST:
			if(!IS_LIST_EMPTY(node->node->payload.tag_list)) {
				ne = -ENOTEMPTY;
				goto cleanup;
			}
			break;
		case TAG_COMPOUND:
			if(!IS_LIST_EMPTY(node->node->payload.tag_compound)) {
				ne = -ENOTEMPTY;
				goto cleanup;
			}
			break;
		default:
			ne = -ENOTDIR;
			goto cleanup;
	}
	list_del(node->pos.head);
	free(list_entry(node->pos.head, struct nbt_list, entry));
	nbt_free(node->node);
	SET_MODIFIED(node);
	free(node);
	ne = 0;
cleanup:
	free_wrapped_node(node);
	if(parent_node != &root_node) free_wrapped_node(parent_node);
	return ne;
}

static int nbt_unlink(const char *path) {
	return nbt_remove_node(path, 0);
}

static int nbt_rmdir(const char *path) {
	return nbt_remove_node(path, 1);
}

static int nbt_read(const char *path, char *out_buf, size_t size, off_t offset, struct fuse_file_info *fi) {
	char buffer[4096];
	size_t length = 0;
	struct wrapped_nbt_node *node = file_info_to_nbt_node(fi);
	switch(node->type) {
		case NORMAL_NODE:
			break;
		case REGION_ROOT_NODE:
			if(!is_region) {
				syslog(LOG_ERR, "REGION_ROOT_NODE (%s) appears in non-region mount", path);
				return -EIO;
			}
			return -EISDIR;
		case LIST_TYPE_NODE:
			goto copy_list_type;
		case ARRAY_ELEMENT_NODE:
			switch(node->node->type) {
				case TAG_INT_ARRAY:
					length = sprintf(buffer, "%d\n",
						(int)node->node->payload.tag_int_array.data[node->pos.index]);
					break;
				case TAG_LONG_ARRAY:
					length = sprintf(buffer, "%lld\n",
						(long long int)node->node->payload.tag_long_array.data[node->pos.index]);
					break;
				default:
					return -EIO;
			}
			break;
		default:
			return -EIO;
	}
	if(!length) switch(node->node->type) {
			const char *p;
		case TAG_BYTE:
			length = sprintf(buffer, "%hhd\n", (char)node->node->payload.tag_byte);
			break;
		case TAG_SHORT:
			length = sprintf(buffer, "%d\n", (int)node->node->payload.tag_short);
			break;
		case TAG_INT:
			length = sprintf(buffer, "%d\n", (int)node->node->payload.tag_int);
			break;
		case TAG_LONG:
			length = sprintf(buffer, "%lld\n", (long long int)node->node->payload.tag_long);
			break;
		case TAG_FLOAT:
			length = sprintf(buffer, "%f\n", (double)node->node->payload.tag_float);
			break;
		case TAG_DOUBLE:
			length = sprintf(buffer, "%f\n", node->node->payload.tag_double);
			break;
		case TAG_STRING:
			p = node->node->payload.tag_string;
			if(!p) return 0;
			goto copy_string;
		//case 128:
		copy_list_type:
			p = get_node_type_name(node->node->payload.tag_list->data);
			if(!p) p = "invalid";
		copy_string:
			length = strlen(p);
			if(length < offset) return 0;
			length -= offset;
			if(length > sizeof buffer) length = sizeof buffer;
			memcpy(buffer, p + offset, length);
			if(length < sizeof buffer) buffer[length++] = '\n';
			offset = 0;
			break;
		case TAG_LIST:
		case TAG_COMPOUND:
			return -EISDIR;
		case TAG_BYTE_ARRAY:
			p = (const char *)node->node->payload.tag_byte_array.data;
			length = node->node->payload.tag_byte_array.length;
			goto copy_array;
		case TAG_INT_ARRAY:
			if(offset % 4 || size % 4) return -EINVAL;
			p = (const char *)node->node->payload.tag_int_array.data;
			length = node->node->payload.tag_int_array.length * 4;
			goto copy_array;
		case TAG_LONG_ARRAY:
			if(offset % 8 || size % 8) return -EINVAL;
			p = (const char *)node->node->payload.tag_long_array.data;
			length = node->node->payload.tag_long_array.length * 8;
		copy_array:
			if(length <= offset) return 0;
			length -= offset;
			if(length > sizeof buffer) length = sizeof buffer;
			memcpy(buffer, p + offset, length);
			offset = 0;
			break;
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
	unsigned int i;
	struct wrapped_nbt_node *node = (struct wrapped_nbt_node *)fi->fh;
	switch(node->type) {
		case NORMAL_NODE:
			break;
		case REGION_ROOT_NODE:
			if(!is_region) {
				syslog(LOG_ERR, "REGION_ROOT_NODE (%s) appears in non-region mount", path);
				return -EIO;
			}
			for(i = 0; i < 1024; i++) {
				const struct chunk_info *info = region_chunks + i;
				if(!info->map_begin) continue;
				char text_buffer[5];
				sprintf(text_buffer, "%u", i);
				filler(buf, text_buffer, NULL, 0);
			}
			return 0;
		default:
			return -ENOTDIR;
	}
	switch(node->node->type) {
			char text_buffer[32];
			struct list_head *pos;
		case TAG_LIST:
			filler(buf, ".type", NULL, 0);
			i = 0;
			list_for_each(pos, &node->node->payload.tag_compound->entry) {
				sprintf(text_buffer, "%u", i++);
				filler(buf, text_buffer, NULL, 0);
			}
			break;
		case TAG_COMPOUND:
			list_for_each(pos, &node->node->payload.tag_compound->entry) {
				struct nbt_node *entry = list_entry(pos, struct nbt_list, entry)->data;
				if(!entry->name) continue;
				if(use_type_prefix) {
					const char *prefix = get_node_type_name(entry);
					if(prefix) {
						size_t prefix_len = strlen(prefix);
						size_t name_len = strlen(entry->name);
						char text_buffer[prefix_len + 1 + name_len + 1];
						memcpy(text_buffer, prefix, prefix_len);
						text_buffer[prefix_len] = ':';
						memcpy(text_buffer + prefix_len + 1, entry->name, name_len);
						text_buffer[prefix_len + 1 + name_len] = 0;
						filler(buf, text_buffer, NULL, 0);
						continue;
					}
				}
				filler(buf, entry->name, NULL, 0);
			}
			break;
		case TAG_INT_ARRAY:
		case TAG_LONG_ARRAY:
			i = node->node->type == TAG_INT_ARRAY ?
				node->node->payload.tag_int_array.length : node->node->payload.tag_long_array.length;
			while(i > 0) {
				sprintf(text_buffer, "%u", --i);
				filler(buf, text_buffer, NULL, 0);
			}
			break;
		default:
			return -ENOTDIR;
	}
	return 0;
}

static int nbt_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
	if(read_only) return -EROFS;
	if(!size) return 0;
	struct wrapped_nbt_node *node = file_info_to_nbt_node(fi);
	switch(node->type) {
		case NORMAL_NODE:
			break;
		case REGION_ROOT_NODE:
			if(!is_region) {
				syslog(LOG_ERR, "REGION_ROOT_NODE (%s) appears in non-region mount", path);
				return -EIO;
			}
			return -EISDIR;
		case LIST_TYPE_NODE:
			if(offset) return -EINVAL;
			if(!IS_LIST_EMPTY(node->node->payload.tag_list)) return -ENOTEMPTY;
			size_t copy_len = buf[size - 1] == '\n' ? size - 1 : size;
			nbt_type type = get_nbt_type_by_name_prefix(buf, copy_len);
			if(type == TAG_INVALID) return -EINVAL;
			node->node->payload.tag_list->data->type = type;
			SET_MODIFIED(node);
			return size;
		case ARRAY_ELEMENT_NODE:
			goto parse_number;
		default:
			return -EIO;
	}
	switch(node->node->type) {
			static const void *parse_number_labels[] = {
				[TAG_BYTE] = &&parse_byte,
				[TAG_SHORT] = &&parse_short,
				[TAG_INT] = &&parse_int,
				[TAG_LONG] = &&parse_long,
				[TAG_FLOAT] = &&parse_float,
				[TAG_DOUBLE] = &&parse_double,
				[TAG_INT_ARRAY] = &&parse_int_for_array,
				[TAG_LONG_ARRAY] = &&parse_long_for_array
			};
			char *end_p;
			size_t orig_len, copy_len;
			int need_end_byte;
		case TAG_BYTE:
		case TAG_SHORT:
		case TAG_INT:
		case TAG_LONG:
		case TAG_FLOAT:
		case TAG_DOUBLE:
		parse_number:
			if(offset) return -EINVAL;
			{
				char text_buffer[size + 1];
				memcpy(text_buffer, buf, size);
				text_buffer[size] = 0;
				goto *parse_number_labels[node->node->type];
		parse_byte:
				node->node->payload.tag_byte = strtol(text_buffer, &end_p, 0);
				goto parse_number_end;
		parse_short:
				node->node->payload.tag_short = strtol(text_buffer, &end_p, 0);
				goto parse_number_end;
		parse_int:
				node->node->payload.tag_int = strtol(text_buffer, &end_p, 0);
				goto parse_number_end;
		parse_long:
				node->node->payload.tag_long = strtoll(text_buffer, &end_p, 0);
				goto parse_number_end;
		parse_float:
				node->node->payload.tag_float = strtof(text_buffer, &end_p);
				goto parse_number_end;
		parse_double:
				node->node->payload.tag_double = strtod(text_buffer, &end_p);
				goto parse_number_end;
		parse_int_for_array:
				node->node->payload.tag_int_array.data[node->pos.index] =
					strtol(text_buffer, &end_p, 0);
				goto parse_number_end;
		parse_long_for_array:
				node->node->payload.tag_long_array.data[node->pos.index] =
					strtoll(text_buffer, &end_p, 0);
		parse_number_end:
				if(*end_p && !isspace(*end_p)) return -EINVAL;
				SET_MODIFIED(node);
				return *end_p ? end_p - text_buffer + 1 : (int)size;
			}
		case TAG_STRING:
			orig_len = strlen(node->node->payload.tag_string) + 1;
			copy_len = buf[size - 1] == '\n' ? size - 1 : size;
			need_end_byte = 1;
			goto copy_bytes;
		case TAG_BYTE_ARRAY:
			orig_len = node->node->payload.tag_byte_array.length;
			copy_len = size;
			need_end_byte = 0;
		copy_bytes:
			{
				void **target_p = node->node->type == TAG_STRING ?
					(void **)&node->node->payload.tag_string : (void **)&node->node->payload.tag_byte_array.data;
				size_t total_len = offset + copy_len + need_end_byte;
				if(total_len > orig_len) {
					void *p = realloc(*target_p, total_len);
					if(!p) return -ENOMEM;
					*target_p = p;
					if(node->node->type == TAG_BYTE_ARRAY) {
						node->node->payload.tag_byte_array.length = total_len;
					}
				}
				memcpy((char *)*target_p + offset, buf, copy_len);
				if(need_end_byte) ((char *)*target_p)[offset + copy_len] = 0;
			}
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
	SET_MODIFIED(node);
	return size;
}

// Return negative errno
static int move_node(struct nbt_node *node, struct list_head *list_head, struct nbt_node *target_parent_node) {
	struct list_head *parent_list_head;
	switch(target_parent_node->type) {
		case TAG_LIST:
			parent_list_head = &target_parent_node->payload.tag_list->entry;
			break;
		case TAG_COMPOUND:
			parent_list_head = &target_parent_node->payload.tag_compound->entry;
			break;
		default:
			return -EIO;
	}
	struct nbt_list *new_list = malloc(sizeof(struct nbt_list));
	if(!new_list) return -ENOMEM;
	new_list->data = node;
	list_add_tail(&new_list->entry, parent_list_head);
	list_del(list_head);
	free(list_entry(list_head, struct nbt_list, entry));
	return 0;
}

static int nbt_rename(const char *old_path, const char *new_path) {
	struct wrapped_nbt_node *old_parent_node, *new_parent_node;
	const char *old_name, *new_name;
	struct wrapped_nbt_node *node = NULL, *existing_node_at_new_path = NULL;
	char *duplicated_new_name = NULL;
	int ne = get_parent_node(old_path, &old_parent_node, &old_name);
	if(ne) return ne;
	if(old_parent_node->type != NORMAL_NODE) return -EPERM;
	if(old_parent_node->node->type != TAG_LIST && old_parent_node->node->type != TAG_COMPOUND) {
		return -EPERM;
	}
	if(!*old_name) {
		// Attempt to rename root node
		//if(old_parent_node != &root_node) free(old_parent_node);
		assert(old_parent_node == &root_node);
		return -EINVAL;
	}
	ne = get_parent_node(new_path, &new_parent_node, &new_name);
	if(ne) {
		if(old_parent_node != &root_node) free(old_parent_node);
		return ne;
	}
	if(!*new_name) {
		assert(new_parent_node == &root_node);
		ne = -EINVAL;
		goto cleanup;
	}
	if(new_parent_node->type != NORMAL_NODE) {
		ne = -EPERM;
		goto cleanup;
	}
	if(new_parent_node->node->type != TAG_LIST && new_parent_node->node->type != TAG_COMPOUND) {
		ne = -EPERM;
		goto cleanup;
	}
	if(read_only) {
		ne = -EROFS;
		goto cleanup;
	}
	node = get_child_node_by_name(old_parent_node, old_name);
	if(!node) {
		ne = -errno;
		goto cleanup;
	}
	if(node->type != NORMAL_NODE) {
		ne = -EPERM;
		goto cleanup;
	}
#if 0
	const char *colon = strchr(old_name, ':');
	if(colon) old_name = colon + 1;
#else
	old_name = node->node->name;
#endif
	const char *colon = strchr(new_name, ':');
	if(colon) {
		if(new_parent_node->node->type != TAG_COMPOUND) {
			ne = -ENOENT;
			goto cleanup;
		}
		nbt_type type = get_nbt_type_by_name_prefix(new_name, colon - new_name);
		if(type == TAG_INVALID) {
			ne = -ENOENT;
			goto cleanup;
		}
		if(node->node->type != type) {
			ne = -EINVAL;
			goto cleanup;
		}
		new_name = colon + 1;
	}
	if(new_parent_node->node->type == TAG_LIST) {
		char *end_p;
		unsigned long int i = strtoul(new_name, &end_p, 0);
		if(*end_p) {
			ne = -EINVAL;
			goto cleanup;
		}
		if(node->node->type != new_parent_node->node->payload.tag_list->data->type) {
			ne = -EINVAL;
			goto cleanup;
		}
		struct list_head *pos;
		unsigned long int j = 0;
		list_for_each(pos, &new_parent_node->node->payload.tag_list->entry) {
			if(j++ != i) continue;
			struct nbt_list *list = list_entry(pos, struct nbt_list, entry);
			struct nbt_node *entry = list->data;
			switch(entry->type) {
				case TAG_LIST:
					if(!IS_LIST_EMPTY(entry->payload.tag_list)) {
						ne = -ENOTEMPTY;
						goto cleanup;
					}
					break;
				case TAG_COMPOUND:
					if(!IS_LIST_EMPTY(entry->payload.tag_compound)) {
						ne = -ENOTEMPTY;
						goto cleanup;
					}
					break;
			}
			free(entry->payload.tag_compound);
			free(entry);
			list->data = node->node;
			list_del(node->pos.head);
			free(list_entry(node->pos.head, struct nbt_list, entry));
			free(node->node->name);
			node->node->name = NULL;
			SET_MODIFIED(old_parent_node);
			SET_MODIFIED(new_parent_node);
			ne = 0;
			goto cleanup;
		}
		if(j < i) {
			ne = -EINVAL;
			goto cleanup;
		}
	} else if(!old_name || strcmp(old_name, new_name)) {
		duplicated_new_name = strdup(new_name);
		if(!duplicated_new_name) {
			ne = -ENOMEM;
			goto cleanup;
		}
	}
	existing_node_at_new_path = get_child_node_by_name(new_parent_node, new_name);
	if(existing_node_at_new_path) {
		if(existing_node_at_new_path->type != NORMAL_NODE) {
			ne = -EPERM;
			goto cleanup;
		}
		switch(NBT_IS_DIRECTORY(node) - NBT_IS_DIRECTORY(existing_node_at_new_path)) {
			case 0:
				break;
			case -1:
				ne = -EISDIR;
				goto cleanup;
			case 1:
				ne = -ENOTDIR;
				goto cleanup;
			default:
				ne = -EIO;
				goto cleanup;
		}
		switch(existing_node_at_new_path->node->type) {
			case TAG_LIST:
				if(!IS_LIST_EMPTY(existing_node_at_new_path->node->payload.tag_list)) {
					ne = -ENOTEMPTY;
					goto cleanup;
				}
				break;
			case TAG_COMPOUND:
				if(!IS_LIST_EMPTY(existing_node_at_new_path->node->payload.tag_compound)) {
					ne = -ENOTEMPTY;
					goto cleanup;
				}
				break;
		}
	}
	if(old_parent_node != new_parent_node) {
		ne = move_node(node->node, node->pos.head, new_parent_node->node);
		if(ne) goto cleanup;
	}
	if(duplicated_new_name) {
		free(node->node->name);
		node->node->name = duplicated_new_name;
		duplicated_new_name = NULL;
	}
	if(existing_node_at_new_path) {
		list_del(existing_node_at_new_path->pos.head);
		free(list_entry(existing_node_at_new_path->pos.head, struct nbt_list, entry));
		nbt_free(existing_node_at_new_path->node);
	}
	SET_MODIFIED(old_parent_node);
	SET_MODIFIED(new_parent_node);
	ne = 0;
cleanup:
	if(old_parent_node != &root_node) free(old_parent_node);
	if(new_parent_node != &root_node) free(new_parent_node);
	free_wrapped_node(node);
	free_wrapped_node(existing_node_at_new_path);
	free(duplicated_new_name);
	return ne;
}

static void handle_file_error(const char *func, int *fd) {
	syslog(LOG_ERR, "%s on fd %d failed, %s; data will not be saved", func, *fd, strerror(errno));
	close(*fd);
	*fd = -1;
}

static void nbt_destroy(void *a) {
	if(is_region) {
		unsigned int i;
		if(!read_only && region_fd != -1 && need_full_write) {
			if(lseek(region_fd, 0, SEEK_SET) < 0) {
				handle_file_error("lseek", &region_fd);
			} else if(sync_write(region_fd, region_map, 8192) < 0) {
				handle_file_error("write", &region_fd);
			}
		}
		for(i = 0; i < 1024; i++) {
			struct chunk_info *info = region_chunks + i;
			if(!info->map_begin) continue;
			if(!read_only && region_fd != -1 && (info->is_modified || need_full_write)) {
				struct buffer buffer;
				if(lseek(region_fd, info->file_offset, SEEK_SET) < 0) {
					handle_file_error("lseek", &region_fd);
				}
				if(info->is_modified) {
					syslog(LOG_DEBUG, "Chunk %u has been modified", i);
					buffer = nbt_dump_compressed(info->nbt_node, compression);
					if(!buffer.data) {
						syslog(LOG_ERR, "Failed to compress chunk %u, %s",
							i, nbt_error_to_string(errno));
					}
					if(1 + buffer.len> info->file_size) {
						// TODO: reallocate more space
						syslog(LOG_ERR, "Chunk %u is too big to store, need %zu bytes but only %zu bytes available",
							i, 1 + buffer.len, info->file_size);
						free(buffer.data);
						buffer.data = NULL;
					}
				} else {
					buffer.data = NULL;
				}
				int32_t len = htonl(buffer.data ? buffer.len + 1 : info->length);
				if(sync_write(region_fd, &len, 4) < 0) {
					handle_file_error("write", &region_fd);
				} else if(buffer.data) {
					uint8_t v = compression == STRAT_GZIP ? 1 : 2;
					if(sync_write(region_fd, &v, 1) < 0) {
						handle_file_error("write", &region_fd);
					} else if(sync_write(region_fd, buffer.data, buffer.len) < 0) {
						handle_file_error("write", &region_fd);
					}
				} else if(sync_write(region_fd, info->map_begin, info->length) < 0) {
					handle_file_error("write", &region_fd);
				}
				free(buffer.data);
			}
			nbt_free(info->nbt_node);
		}
		munmap(region_map, region_file_size);
		if(!read_only && region_fd != -1 && close(region_fd) < 0) {
			syslog(LOG_ERR, "Failed to close fd %d, %s; data may not be saved",
				region_fd, strerror(errno));
		}
	} else {
		if(!read_only && nbt_file && (is_modified || write_file_path)) {
			fseek(nbt_file, 0, SEEK_SET);
			nbt_status status = nbt_dump_file(root_node.node, nbt_file, compression);
			if(status != NBT_OK) {
				syslog(LOG_ERR, "Failed to save NBT file, %s", nbt_error_to_string(status));
			}
			if(fclose(nbt_file) == EOF) {
				syslog(LOG_ERR, "Failed to save NBT file, %s", strerror(errno));
			}
		}
		nbt_free(root_node.node);
	}
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
		else if(strcmp(o, "typeprefix") == 0) use_type_prefix = 1;
		else if(strcmp(o, "region") == 0) is_region = 1;
		else if(strncmp(o, "writefile=", 10) == 0) write_file_path = o + 10;
		else if(strncmp(o, "compression=", 12) == 0) {
			const char *a = o + 12;
			if(strcmp(a, "gzip") == 0) compression = STRAT_GZIP;
			else if(strcmp(a, "zlib") == 0) compression = STRAT_INFLATE;
			else {
				fprintf(stderr, "Compression type %s is not supported\n", a);
				exit(-1);
			}
		} else {
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

static int read_region_header(int fd) {
	unsigned int i;
	off_t len = lseek(fd, 0, SEEK_END);
	if(len < 0) {
		perror("lseek");
		return -1;
	}
	if(len < 8192) {
		fputs("File is too small to be a valid region file\n", stderr);
		return -1;
	}
	region_file_size = len;
	lseek(fd, 0, SEEK_SET);
	region_map = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
	if(!region_map) {
		perror("mmap");
		return -1;
	}
	uint8_t *byte_p = region_map;
	int32_t *int_p = region_map;
	for(i = 0; i < 1024; i++) {
		struct chunk_info *info = region_chunks + i;
		info->raw_offset_and_size = int_p[i];
		size_t chunk_size = byte_p[i * 4 + 3] * 4 * 1024;
		if(!chunk_size) continue;
		off_t chunk_offset = (ntohl(int_p[i]) >> 8) & 0xffffff;
		if(!chunk_offset) continue;
		off_t file_offset = chunk_offset * 4 * 1024;
		if(file_offset > len) {
			fprintf(stderr, "Chunk %u has invalid offset %ld that's out of file length\n",
				i, (long int)file_offset);
			if(read_only) continue;
			fputs("Cannot continue in read-write mode\n", stderr);
			return -1;
		}
		info->raw_mtime = int_p[1024 + i];
/*
		time_t chunk_mtime = ntohl(info->raw_mtime);
		struct tm *chunk_tm = localtime(&chunk_mtime);
		char time_buffer[24];
		if(!strftime(time_buffer, sizeof time_buffer, "%F %T", chunk_tm)) {
			sprintf(time_buffer, "%d", (int)chunk_mtime);
		}
*/
		uint8_t *chunk = (uint8_t *)region_map + file_offset;
		int32_t used_space;
		memcpy(&used_space, chunk, 4);
		used_space = ntohl(used_space);
		if(used_space < 0 || (size_t)used_space > chunk_size) {
			fprintf(stderr, "Chunk %u has invalid size %d\n", i, (int)used_space);
			if(read_only) continue;
			fputs("Cannot continue in read-write mode\n", stderr);
			return -1;
		}
		uint8_t compression_type = chunk[4];
		if(compression_type != 1 && compression_type != 2) {
			fprintf(stderr, "Chunk %u has unsupported compression type %hhu\n",
				i, compression_type);
			if(read_only) continue;
			fputs("Cannot continue in read-write mode\n", stderr);
			return -1;
		}
		info->file_offset = file_offset;
		info->file_size = chunk_size;
		info->map_begin = chunk + 4;
		info->length = used_space;
	}
	return 0;
}

static struct fuse_operations operations = {
	.fgetattr	= nbt_fgetattr,
	.getattr	= nbt_getattr,
	.create		= nbt_create,
	.open		= nbt_open,
	.opendir	= nbt_open,
	.release	= nbt_release,
	.releasedir	= nbt_release,
	.read		= nbt_read,
	.readdir	= nbt_readdir,
	.write		= nbt_write,
	.ftruncate	= nbt_ftruncate,
	.truncate	= nbt_truncate,
	.unlink		= nbt_unlink,
	.mkdir		= nbt_mkdir,
	.rmdir		= nbt_rmdir,
	.rename		= nbt_rename,
	.destroy	= nbt_destroy
};

int main(int argc, char **argv) {
	int fuse_argc = 2;
	char **fuse_argv = malloc(2 * sizeof(char *));
	if(!fuse_argv) {
		perror("malloc");
		return 1;
	}
	int foreground = 0;
	int verbose = 0;
	char *mount_from = NULL;
	char *mount_point = NULL;
	int i = 1;
	int end_of_options = 0;
	while(i < argc) {
		if(!end_of_options && argv[i][0] == '-') {
			const char *o = argv[i] + 1;
			switch(*o) {
				case 0:
					goto not_an_option;
				case '-':
					if(*++o) {
						fprintf(stderr, "%s: Invalid option '%s'\n",
							argv[0], argv[i]);
						return -1;
					}
					end_of_options = 1;
					break;
			}
			while(*o) switch(*o++) {
				char *fuse_extended_options;
				case 'f':
					fuse_argc++;
					fuse_argv = realloc(fuse_argv, (fuse_argc + 1) * sizeof(char *));
					if(!fuse_argv) {
						perror("realloc");
						return 1;
					}
					fuse_argv[fuse_argc - 2] = "-f";
					foreground = 1;
					break;
				case 'o':
					if(++i >= argc) {
						fprintf(stderr, "%s: Option '-o' requires an argument\n",
							argv[0]);
						return -1;
					}
					fuse_extended_options = parse_extended_options(argv[i]);
					if(fuse_extended_options) {
						fuse_argc += 2;
						fuse_argv = realloc(fuse_argv, (fuse_argc + 1) * sizeof(char *));
						if(!fuse_argv) {
							perror("realloc");
							return 1;
						}
						fuse_argv[fuse_argc - 3] = "-o";
						fuse_argv[fuse_argc - 2] = fuse_extended_options;
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
					if(++i >= argc) {
						fprintf(stderr, "%s: Option '-%c' requires an argument\n",
							argv[0], o[-1]);
						return -1;
					}
					if(strcmp(argv[i], "nbt")) {
						fprintf(stderr, "%s: The file system type may only be specified as 'nbt'\n",
							argv[0]);
						return -1;
					}
					break;
				case 'h':
					print_usage(argv[0]);
					return 0;
				case 'V':
					puts("mount.nbt (nbtfsutils) " NBTFSUTILS_VERSION);
					puts("Copyright 2015-2023 Rivoreo");
					puts("This Executable Form of the program can be redistributed under the terms of\n"
						"the Mozilla Public License, version 2.0.");
					puts("The program is provided without any warranty. See Mozilla Public License,\n"
						"version 2.0 for details.");
					return 0;
				default:
					fprintf(stderr, "%s: Invalid option '-%c'\n", argv[0], o[-1]);
					print_usage(argv[0]);
					return -1;
			}
		} else {
not_an_option:
			if(!mount_from) mount_from = argv[i];
			else if(!mount_point) mount_point = argv[i];
			else {
				print_usage(argv[0]);
				return -1;
			}
		}
		i++;
	}
	if(!mount_from || !mount_point) {
		print_usage(argv[0]);
		return -1;
	}
	if(read_only) {
		fuse_argc += 2;
		fuse_argv = realloc(fuse_argv, (fuse_argc + 1) * sizeof(char *));
		if(!fuse_argv) {
			perror("realloc");
			return 1;
		}
		fuse_argv[fuse_argc - 3] = "-o";
		fuse_argv[fuse_argc - 2] = "ro";
	}
	int logopt = LOG_PID;
#ifdef LOG_PERROR
	if(foreground || verbose) logopt |= LOG_PERROR;
#endif
	openlog("mount.nbt", logopt, LOG_DAEMON);
	myuid = getuid();
	mygid = getgid();
	if(is_region) {
		int fd = open(mount_from, read_only || write_file_path ? O_RDONLY : O_RDWR);
		if(fd == -1) {
			perror(mount_from);
			return 1;
		}
		if(!read_only) {
			if(write_file_path) {
				region_fd = open(write_file_path, O_WRONLY | O_CREAT, 0666);
				if(region_fd == -1) {
					perror(write_file_path);
					return 1;
				}
				need_full_write = 1;
			} else {
				region_fd = fd;
				need_full_write = 0;
			}
		}
		if(read_region_header(fd) < 0) return 1;
		root_node.type = REGION_ROOT_NODE;
		root_node.node = NULL;
		root_node.pos.head = NULL;
		root_node.chunk = NULL;
		if(fd != region_fd) close(fd);
		if(compression == -1) compression = STRAT_INFLATE;
		syslog(LOG_DEBUG, "Region %s loaded successfully", mount_from);
	} else {
		FILE *f = fopen(mount_from, read_only || write_file_path ? "rb" : "r+b");
		if(!f) {
			perror(mount_from);
			return 1;
		}
		if(!read_only) {
			if(write_file_path) {
				nbt_file = fopen(write_file_path, "wb");
				if(!nbt_file) {
					perror(write_file_path);
					return 1;
				}
			} else {
				nbt_file = f;
			}
		}
		root_node.type = NORMAL_NODE;
		root_node.node = nbt_parse_file(f);
		if(!root_node.node) {
			fprintf(stderr, "%s: Failed to mount %s, %s\n",
				argv[0], mount_from, nbt_error_to_string(errno));
			return 1;
		}
		root_node.pos.head = NULL;
		root_node.chunk = NULL;
		if(f != nbt_file) fclose(f);
		if(compression == -1) compression = STRAT_GZIP;
		syslog(LOG_DEBUG, "NBT %s loaded successfully", mount_from);
	}
	fuse_argv[0] = mount_from;
	fuse_argv[fuse_argc - 1] = mount_point;
	return fuse_main(fuse_argc, fuse_argv, &operations, NULL);
}
