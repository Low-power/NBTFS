# -----------------------------------------------------------------------------
# "THE BEER-WARE LICENSE" (Revision 42):
# Lukas Niederbremer <webmaster@flippeh.de> and Clark Gaebel <cg.wowus.cg@gmail.com>
# wrote this file. As long as you retain this notice you can do whatever you
# want with this stuff. If we meet some day, and you think this stuff is worth
# it, you can buy us a beer in return.
# -----------------------------------------------------------------------------

AR ?= ar
CFLAGS += -g -Wall -Wextra -Wno-unused-parameter -Wno-switch -Wno-pointer-to-int-cast -Wno-int-to-pointer-cast -std=gnu99
CFLAGS += -D _FILE_OFFSET_BITS=64

LIBNBT_OBJECTS := buffer.o nbt_loading.o nbt_parsing.o nbt_treeops.o nbt_util.o

all:	nbtdump check regiondump mkfs.nbt mount.nbt

mount.nbt:	mount.nbt.c syncwrite.o libnbt.a
	$(CC) $(CFLAGS) $(LDFLAGS) mount.nbt.c syncwrite.o -o $@ -L . -l nbt -l z -l fuse $(LIBS)

# For GNU Make
%:	%.c libnbt.a
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ -L . -l nbt -l z $(LIBS)

# For BSD make
.c:	libnbt.a
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ -L . -l nbt -l z $(LIBS)

test: check
	cd testdata && for f in *.nbt; do valgrind ../check "$$f" || exit; done

libnbt.a:	$(LIBNBT_OBJECTS)
	$(AR) -rcs $@ buffer.o nbt_loading.o nbt_parsing.o nbt_treeops.o nbt_util.o

clean:
	rm -f nbtdump check regiondump mount.nbt mkfs.nbt libnbt.a syncwrite.o $(LIBNBT_OBJECTS)
