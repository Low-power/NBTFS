/*	Copyright 2015-2022 Rivoreo

	This Source Code Form is subject to the terms of the Mozilla Public
	License, v. 2.0. If a copy of the MPL was not distributed with this
	file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/

#define _FILE_OFFSET_BITS 64
#define FUSE_USE_VERSION 26
#include <fuse/fuse.h>
#include "nbt.h"
#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>

#define NBT_IS_DIRECTORY(NODE) ((NODE)->type == TAG_COMPOUND || (NODE)->type == TAG_LIST)

static uid_t myuid;
static gid_t mygid;
static int read_only = 0;
static mode_t node_umask = 0;
static int use_type_prefix = 0;
static int is_region = 0;
static const char *write_file_path = NULL;
static int compression = -1;

static int region_fd = -1;
static size_t region_file_size = 0;
static void *region_map = NULL;
static struct chunk_info {
	uint32_t raw_offset_and_size;
	uint32_t raw_mtime;
	void *map_begin;
	size_t length;
	struct nbt_node *nbt_node;
} region_chunks[1024];
static struct nbt_node region_root_node = { .type = TAG_INVALID };

static FILE *nbt_file;
static struct nbt_node *root_node;
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

static struct nbt_node *get_child_node_by_name(struct nbt_node *parent, const char *name, struct list_head **list_node) {
	if(is_region && !parent) {
		char *end_p;
		unsigned int i = strtoul(name, &end_p, 0);
		if(*end_p) return NULL;
		if(i >= 1024) return NULL;
		struct chunk_info *info = region_chunks + i;
		if(!info->nbt_node) {
			if(!info->map_begin) return NULL;
			info->nbt_node = nbt_parse_compressed(info->map_begin, info->length);
		}
		return info->nbt_node;
	}

	nbt_type type = TAG_INVALID;
	const char *colon = strchr(name, ':');
	if(colon) {
		type = get_nbt_type_by_name_prefix(name, colon - name);
		if(type == TAG_INVALID) return NULL;
		name = colon + 1;
	}
	//return nbt_find_by_name(parent, name);
	switch(parent->type) {
			long int i, j;
			char *end_p;
			struct list_head *pos;
		case TAG_LIST:
			if(type != TAG_INVALID) return NULL;
			if(strcmp(name, ".type") == 0) {
				struct nbt_node *type_name_node = malloc(sizeof(struct nbt_node));
				if(!type_name_node) return NULL;
				type_name_node->type = 128;
				type_name_node->payload.tag_list = parent->payload.tag_list;
/*
				type_name_node->payload.tag_string =
					(char *)get_node_type_name(parent->payload.tag_list->data);
				if(!type_name_node->payload.tag_string) {
					type_name_node->payload.tag_string = (char *)"invalid";
				}
*/
				if(list_node) *list_node = NULL;
				return type_name_node;
			}
			i = strtol(name, &end_p, 0);
#if 0
			return *end_p ? NULL : nbt_list_item(parent, i);
#else
			if(*end_p) return NULL;
			j = 0;
			list_for_each(pos, &parent->payload.tag_list->entry) {
				if(j++ == i) {
					if(list_node) *list_node = pos;
					return list_entry(pos, struct nbt_list, entry)->data;
				}
			}
			break;
#endif
		case TAG_COMPOUND:
			list_for_each(pos, &parent->payload.tag_compound->entry) {
				struct nbt_node *entry = list_entry(pos, struct nbt_list, entry)->data;
				if(type != TAG_INVALID && entry->type != type) continue;
				if(entry->name && strcmp(entry->name, name) == 0) {
					if(list_node) *list_node = pos;
					return entry;
				}
			}
			break;
	}
	return NULL;
}

static struct nbt_node *get_node(struct nbt_node *parent, const char *path) {
	if(*path == '/') path++;
	if(!*path) return is_region && !parent ? &region_root_node : parent;
	size_t name_len = 1;
	while(path[name_len] && path[name_len] != '/') name_len++;
	char name[name_len + 1];
	memcpy(name, path, name_len);
	name[name_len] = 0;
	struct nbt_node *node = get_child_node_by_name(parent, name, NULL);
	if(!node) return NULL;
	return get_node(node, path + name_len);
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

static struct nbt_node *create_node(struct nbt_node *parent, const char *path) {
	if(*path == '/') path++;
	const char *p = strrchr(path, '/');
	if(p) {
		size_t node_path_len = ++p - path;
		char node_path[node_path_len + 1];
		memcpy(node_path, path, node_path_len);
		node_path[node_path_len] = 0;
		parent = get_node(parent, node_path);
		if(!parent) {
			errno = ENOENT;
			return NULL;
		}
		path = p;
	} else if(is_region && !parent) {
		errno = EINVAL;
		return NULL;
	}
	nbt_type type;
	const char *name;
	struct list_head *parent_list_head;
	switch(parent->type) {
			unsigned long int i;
			char *end_p;
			struct list_head *pos;
		case TAG_LIST:
			i = strtoul(path, &end_p, 0);
			if(*end_p) {
				errno = EINVAL;
				return NULL;
			}
			type = parent->payload.tag_list->data->type;
			if(type == TAG_INVALID) {
				errno = EPERM;
				return NULL;
			}
			name = NULL;
			parent_list_head = &parent->payload.tag_list->entry;
			if(i != list_length(parent_list_head)) {
				errno = EPERM;
				return NULL;
			}
			break;
		case TAG_COMPOUND:
			p = strchr(path, ':');
			if(!p) {
				errno = EINVAL;
				return NULL;
			}
			type = get_nbt_type_by_name_prefix(path, p - path);
			if(type == TAG_INVALID) {
				errno = EINVAL;
				return NULL;
			}
			name = p + 1;
			parent_list_head = &parent->payload.tag_compound->entry;
			list_for_each(pos, parent_list_head) {
				struct nbt_node *entry = list_entry(pos, struct nbt_list, entry)->data;
				if(entry->name && strcmp(entry->name, name) == 0) {
					errno = EEXIST;
					return NULL;
				}
			}
			break;
		default:
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
			errno = ENOMEM;
			return NULL;
		}
	} else {
		node->name = NULL;
	}
	if(init_node(node) < 0) {
		free(node);
		return NULL;
	}
	struct nbt_list *new_list = malloc(sizeof(struct nbt_list));
	if(!new_list) {
		nbt_free(node);
		errno = ENOMEM;
		return NULL;
	}
	new_list->data = node;
	list_add_tail(&new_list->entry, parent_list_head);
	is_modified = 1;
	return node;
}

static size_t get_size(struct nbt_node *node) {
	switch(node->type) {
			const char *s;
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
		case TAG_STRING:
			if(!node->payload.tag_string) return 0;
			return strlen(node->payload.tag_string) + 1;
		case 128:
			s = get_node_type_name(node->payload.tag_list->data);
			return s ? strlen(s) + 1 : 8;
		case TAG_LIST:
		case TAG_COMPOUND:
			return nbt_size(node);
		case TAG_BYTE_ARRAY:
			return node->payload.tag_byte_array.length;
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
	stbuf->st_nlink = 1;
	if(is_region && node == &region_root_node) {
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
	struct nbt_node *node = get_node(root_node, path);
	if(!node) return -ENOENT;
	struct fuse_file_info fi = { .fh = (uint64_t)node };
	return nbt_fgetattr(path, stbuf, &fi);
}

static int nbt_ftruncate(const char *path, off_t length, struct fuse_file_info *fi) {
	if(read_only) return -EROFS;
	struct nbt_node *node = (struct nbt_node *)fi->fh;
	if(is_region && node == &region_root_node) return -EISDIR;
	switch(node->type) {
			void *p;
		case TAG_BYTE:
			if(length) return -EINVAL;
			node->payload.tag_byte = 0;
			break;
		case TAG_SHORT:
			if(length) return -EINVAL;
			node->payload.tag_short = 0;
			break;
		case TAG_INT:
			if(length) return -EINVAL;
			node->payload.tag_int = 0;
			break;
		case TAG_LONG:
			if(length) return -EINVAL;
			node->payload.tag_long = 0;
			break;
		case TAG_FLOAT:
			if(length) return -EINVAL;
			node->payload.tag_float = 0;
			break;
		case TAG_DOUBLE:
			if(length) return -EINVAL;
			node->payload.tag_double = 0;
			break;
		case TAG_STRING:
			p = realloc(node->payload.tag_string, length + 1);
			if(!p) return -ENOMEM;
			node->payload.tag_string = p;
			node->payload.tag_string[length] = 0;
			break;
		case TAG_BYTE_ARRAY:
			p = realloc(node->payload.tag_byte_array.data, length);
			if(length && !p) return -ENOMEM;
			node->payload.tag_byte_array.data = p;
			node->payload.tag_byte_array.length = length;
			break;
		case TAG_LIST:
		case TAG_COMPOUND:
			return -EISDIR;
		case 128:
			if(&node->payload.tag_list->entry != node->payload.tag_list->entry.flink) {
				return -ENOTEMPTY;
			}
			// Silently ignore
			break;
		default:
			return -EPERM;
	}
	is_modified = 1;
	return 0;
}

static int nbt_truncate(const char *path, off_t length) {
	if(read_only) return -EROFS;
	struct nbt_node *node = get_node(root_node, path);
	if(!node) return -ENOENT;
	struct fuse_file_info fi = { .fh = (uint64_t)node };
	return nbt_ftruncate(path, length, &fi);
}

static int nbt_open(const char *path, struct fuse_file_info *fi) {
	if((fi->flags & (O_RDONLY|O_WRONLY|O_RDWR)) == O_RDONLY) {
		if(fi->flags & O_TRUNC) return -EINVAL;
	} else if(read_only) return -EROFS;
	struct nbt_node *node = get_node(root_node, path);
	if(!node) return -ENOENT;
	fi->fh = (uint64_t)node;
	if(fi->flags & O_TRUNC) {
		int ne = nbt_ftruncate(path, 0, fi);
		if(ne) return ne;
	}
	return 0;
}

static int nbt_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
	if(read_only) return -EROFS;
	errno = ENOENT;
	struct nbt_node *node = create_node(root_node, path);
	if(!node) return -errno;
	fi->fh = (uint64_t)node;
	return 0;
}

static int nbt_mkdir(const char *path, mode_t mode) {
	if(read_only) return -EROFS;
	errno = ENOENT;
	return create_node(root_node, path) ? 0 : -errno;
}

static int nbt_remove_node(const char *path, int dir_only) {
	struct nbt_node *parent_node;
	if(*path == '/') path++;
	const char *p = strrchr(path, '/');
	if(p) {
		size_t node_path_len = ++p - path;
		char node_path[node_path_len + 1];
		memcpy(node_path, path, node_path_len);
		node_path[node_path_len] = 0;
		parent_node = get_node(root_node, node_path);
		if(!parent_node) return -ENOENT;
	} else if(is_region) {
		// TODO
		return -EPERM;
	} else {
		parent_node = root_node;
		p = path;
	}
	if(!NBT_IS_DIRECTORY(parent_node)) return -ENOTDIR;
	if(read_only) return -EROFS;
	struct list_head *list_node;
	struct nbt_node *node = get_child_node_by_name(parent_node, p, &list_node);
	if(!node) return -ENOENT;
	if(node->type == 128 || !list_node) return -EPERM;
	if(dir_only) switch(node->type) {
		case TAG_LIST:
			if(&node->payload.tag_list->entry != node->payload.tag_list->entry.flink) {
				return -ENOTEMPTY;
			}
			break;
		case TAG_COMPOUND:
			if(&node->payload.tag_compound->entry != node->payload.tag_compound->entry.flink) {
				return -ENOTEMPTY;
			}
			break;
		default:
			return -ENOTDIR;
	}
	list_del(list_node);
	nbt_free(node);
	is_modified = 1;
	return 0;
}

static int nbt_unlink(const char *path) {
	return nbt_remove_node(path, 0);
}

static int nbt_rmdir(const char *path) {
	return nbt_remove_node(path, 1);
}

static int nbt_release(const char *path, struct fuse_file_info *fi) {
	struct nbt_node *node = (struct nbt_node *)fi->fh;
	if(node->type == 128) free(node);
	return 0;
}

static int nbt_read(const char *path, char *out_buf, size_t size, off_t offset, struct fuse_file_info *fi) {
	char buffer[4096];
	size_t length;
	struct nbt_node *node = (struct nbt_node *)fi->fh;
	if(is_region && node == &region_root_node) return -EISDIR;
	switch(node->type) {
			const char *p;
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
		case TAG_STRING:
			p = node->payload.tag_string;
			if(!p) return 0;
			goto copy_string;
		case 128:
			p = get_node_type_name(node->payload.tag_list->data);
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
			length = node->payload.tag_byte_array.length;
			if(length <= offset) return 0;
			length -= offset;
			if(length > sizeof buffer) length = sizeof buffer;
			memcpy(buffer, node->payload.tag_byte_array.data + offset, length);
			offset = 0;
			break;
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
	if(is_region && node == &region_root_node) {
		unsigned int i;
		for(i = 0; i < 1024; i++) {
			const struct chunk_info *info = region_chunks + i;
			if(!info->map_begin) continue;
			char text_buffer[5];
			sprintf(text_buffer, "%u", i);
			filler(buf, text_buffer, NULL, 0);
		}
		return 0;
	}
	switch(node->type) {
			unsigned int i;
			char text_buffer[32];
			struct list_head *pos;
		case TAG_LIST:
			filler(buf, ".type", NULL, 0);
			i = 0;
			list_for_each(pos, &node->payload.tag_compound->entry) {
				sprintf(text_buffer, "%u", i++);
				filler(buf, text_buffer, NULL, 0);
			}
			break;
		case TAG_COMPOUND:
			list_for_each(pos, &node->payload.tag_compound->entry) {
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
		default:
			return -ENOTDIR;
	}
	return 0;
}

static int nbt_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
	if(read_only) return -EROFS;
	struct nbt_node *node = (struct nbt_node *)fi->fh;
	if(is_region && node == &region_root_node) return -EISDIR;
	switch(node->type) {
			static const void *parse_number_labels[] = {
				[TAG_BYTE] = &&parse_byte,
				[TAG_SHORT] = &&parse_short,
				[TAG_INT] = &&parse_int,
				[TAG_LONG] = &&parse_long,
				[TAG_FLOAT] = &&parse_float,
				[TAG_DOUBLE] = &&parse_double
			};
			char *end_p;
			size_t orig_len, copy_len;
		case TAG_BYTE:
		case TAG_SHORT:
		case TAG_INT:
		case TAG_LONG:
		case TAG_FLOAT:
		case TAG_DOUBLE:
			if(offset) return -EINVAL;
			{
				char text_buffer[size + 1];
				memcpy(text_buffer, buf, size);
				text_buffer[size] = 0;
				goto *parse_number_labels[node->type];
		parse_byte:
				node->payload.tag_byte = strtol(text_buffer, &end_p, 0);
				goto parse_number_end;
		parse_short:
				node->payload.tag_short = strtol(text_buffer, &end_p, 0);
				goto parse_number_end;
		parse_int:
				node->payload.tag_int = strtol(text_buffer, &end_p, 0);
				goto parse_number_end;
		parse_long:
				node->payload.tag_long = strtoll(text_buffer, &end_p, 0);
				goto parse_number_end;
		parse_float:
				node->payload.tag_float = strtof(text_buffer, &end_p);
				goto parse_number_end;
		parse_double:
				node->payload.tag_double = strtod(text_buffer, &end_p);
		parse_number_end:
				if(*end_p && !isspace(*end_p)) return -EINVAL;
				is_modified = 1;
				return *end_p ? end_p - text_buffer + 1 : (int)size;
			}
		case TAG_STRING:
			orig_len = strlen(node->payload.tag_string) + 1;
			copy_len = buf[size - 1] == '\n' ? size - 1 : size;
			goto copy_bytes;
		case TAG_BYTE_ARRAY:
			orig_len = node->payload.tag_byte_array.length;
			copy_len = size;
		copy_bytes:
			{
				void **target_p = node->type == TAG_STRING ?
					(void **)&node->payload.tag_string : (void **)&node->payload.tag_byte_array.data;
				if(offset + copy_len > orig_len) {
					void *p = realloc(*target_p, offset + copy_len);
					if(!p) return -ENOMEM;
					*target_p = p;
					if(node->type == TAG_BYTE_ARRAY) {
						node->payload.tag_byte_array.length = offset + copy_len;
					}
				}
				memcpy((char *)*target_p + offset, buf, copy_len);
			}
			break;
		case TAG_LIST:
		case TAG_COMPOUND:
			return -EISDIR;
		case TAG_INT_ARRAY:
		case TAG_LONG_ARRAY:
			return -EPERM;
		case 128:
			if(offset) return -EINVAL;
			if(&node->payload.tag_list->entry != node->payload.tag_list->entry.flink) {
				return -ENOTEMPTY;
			}
			copy_len = buf[size - 1] == '\n' ? size - 1 : size;
			nbt_type type = get_nbt_type_by_name_prefix(buf, copy_len);
			if(type == TAG_INVALID) return -EINVAL;
			node->payload.tag_list->data->type = type;
			break;
		default:
			return -EIO;
	}
	is_modified = 1;
	return size;
}

static void nbt_destroy(void *a) {
	if(is_region) {
		// TODO: Save changes
		unsigned int i;
		for(i = 0; i < 1024; i++) {
			struct chunk_info *info = region_chunks + i;
			if(!info->map_begin) continue;
			nbt_free(info->nbt_node);
		}
		munmap(region_map, region_file_size);
	} else {
		if(!read_only && nbt_file && (is_modified || write_file_path)) {
			fseek(nbt_file, 0, SEEK_SET);
			nbt_status status = nbt_dump_file(root_node, nbt_file, compression);
			if(status != NBT_OK) {
				// TODO: Log error
				//nbt_error_to_string(status);
				//fprintf(stderr, "Failed to save NBT file, %s\n", nbt_error_to_string(status));
			}
			fclose(nbt_file);
		}
		nbt_free(root_node);
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
		info->map_begin = chunk + 5;
		info->length = used_space - 1;
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
	.destroy	= nbt_destroy
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
	if(is_region) {
		if(!read_only) {
			fprintf(stderr, "%s: Writable mounting region file is currently not supported\n",
				argv[0]);
			return 1;
		}
		region_fd = open(argv[optind], read_only ? O_RDONLY : O_RDWR);
		if(region_fd == -1) {
			perror(argv[optind]);
			return 1;
		}
		if(read_region_header(region_fd) < 0) return 1;
		if(compression == -1) compression = STRAT_INFLATE;
	} else {
		FILE *f = fopen(argv[optind], read_only || write_file_path ? "rb" : "r+b");
		if(!f) {
			perror(argv[optind]);
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
		root_node = nbt_parse_file(f);
		if(!root_node) {
			fprintf(stderr, "%s: Failed to mount %s, %s\n", argv[0], argv[optind], nbt_error_to_string(errno));
			return 1;
		}
		if(f != nbt_file) fclose(f);
		if(compression == -1) compression = STRAT_GZIP;
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
