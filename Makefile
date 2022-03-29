# -----------------------------------------------------------------------------
# "THE BEER-WARE LICENSE" (Revision 42):
# Lukas Niederbremer <webmaster@flippeh.de> and Clark Gaebel <cg.wowus.cg@gmail.com>
# wrote this file. As long as you retain this notice you can do whatever you
# want with this stuff. If we meet some day, and you think this stuff is worth
# it, you can buy us a beer in return.
# -----------------------------------------------------------------------------

CFLAGS += -g -Wall -Wextra -Wno-unused-parameter -Wno-switch -std=gnu99

all: nbtreader check

nbtreader: main.o libnbt.a
	$(CC) $(LDFLAGS) main.o -L. -lnbt -lz -o $@

check: check.c libnbt.a
	$(CC) $(CFLAGS) $(LDFLAGS) check.c -L. -lnbt -lz -o $@

regiondump:	regiondump.c libnbt.a
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ -L . -l nbt -l z

mount.nbt:	mount.nbt.c libnbt.a
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ -L . -l nbt -l z -l fuse

mkfs.nbt:	mkfs.nbt.c libnbt.a
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ -L . -l nbt -l z

test: check
	cd testdata && for f in *.nbt; do valgrind ../check "$$f" || exit; done

main.o: main.c

libnbt.a: buffer.o nbt_loading.o nbt_parsing.o nbt_treeops.o nbt_util.o
	ar -rcs $@ buffer.o nbt_loading.o nbt_parsing.o nbt_treeops.o nbt_util.o

buffer.o: buffer.c
nbt_loading.o: nbt_loading.c
nbt_parsing.o: nbt_parsing.c
nbt_treeops.o: nbt_treeops.c
nbt_util.o: nbt_util.c

clean:
	rm -f nbtreader check regiondump mount.nbt libnbt.a main.o buffer.o nbt_loading.o nbt_parsing.o nbt_treeops.o nbt_util.o
