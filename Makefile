# -----------------------------------------------------------------------------
# "THE BEER-WARE LICENSE" (Revision 42):
# Lukas Niederbremer <webmaster@flippeh.de> and Clark Gaebel <cg.wowus.cg@gmail.com>
# wrote this file. As long as you retain this notice you can do whatever you
# want with this stuff. If we meet some day, and you think this stuff is worth
# it, you can buy us a beer in return.
# -----------------------------------------------------------------------------

AR ?= ar
INSTALL ?= install
CFLAGS += -Wall -Wextra -Wno-unused-parameter -Wno-switch -Wno-pointer-to-int-cast -Wno-int-to-pointer-cast -std=gnu99
CFLAGS += -D _FILE_OFFSET_BITS=64

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
SBINDIR ?= $(PREFIX)/sbin
DATADIR ?= $(PREFIX)/share
MANDIR ?= $(DATADIR)/man

LIBNBT_OBJECTS := buffer.o nbt_loading.o nbt_parsing.o nbt_treeops.o nbt_util.o

all:	nbtdump check regiondump mkfs.nbt mount.nbt

version.h:	.git/logs/HEAD
	export TZ=UTC; \
	if [ -f .git/HEAD ]; then \
		printf "#define NBTFSUTILS_VERSION \"%s\"\\n" "`git show --format=%cd_%h --date short --quiet | sed -e 's/-//g' -e 's/_/-/'`" > $@; \
	elif [ -f $@ ]; then \
		touch $@; \
	else \
		printf "#define NBTFSUTILS_VERSION \"local-snapshot-%s\"\\n" "`date +%Y%m%d`" > $@; \
	fi

mount.nbt:	mount.nbt.c version.h syncwrite.o libnbt.a
	$(CC) $(CFLAGS) $(LDFLAGS) mount.nbt.c syncwrite.o -o $@ -L . -l nbt -l z -l fuse $(LIBS)

# For GNU Make
%:	%.c version.h libnbt.a
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ -L . -l nbt -l z $(LIBS)

# For BSD make
.c:	version.h libnbt.a
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ -L . -l nbt -l z $(LIBS)

test: check
	cd testdata && for f in *.nbt; do valgrind ../check "$$f" || exit; done

libnbt.a:	$(LIBNBT_OBJECTS)
	$(AR) -rcs $@ buffer.o nbt_loading.o nbt_parsing.o nbt_treeops.o nbt_util.o

clean:
	rm -f nbtdump check regiondump mount.nbt mkfs.nbt libnbt.a syncwrite.o $(LIBNBT_OBJECTS)

install:	all
	for d in "$(DESTDIR)$(BINDIR)" \
		"$(DESTDIR)$(SBINDIR)" \
		"$(DESTDIR)$(DATADIR)" \
		"$(DESTDIR)$(MANDIR)/man1" \
		"$(DESTDIR)$(MANDIR)/man8"; \
	do [ -d "$$d" ] || mkdir -p "$$d" || exit; done
	$(INSTALL) -m 755 nbtdump "$(DESTDIR)$(BINDIR)/"
	$(INSTALL) -m 755 regiondump "$(DESTDIR)$(BINDIR)/"
	$(INSTALL) -m 755 mkfs.nbt "$(DESTDIR)$(SBINDIR)/"
	$(INSTALL) -m 755 mount.nbt "$(DESTDIR)$(SBINDIR)/"
	$(INSTALL) -m 644 nbtdump.1 "$(DESTDIR)$(MANDIR)/man1/"
	$(INSTALL) -m 644 regiondump.1 "$(DESTDIR)$(MANDIR)/man1/"
	$(INSTALL) -m 644 mkfs.nbt.8 "$(DESTDIR)$(MANDIR)/man8/"
	$(INSTALL) -m 644 mount.nbt.8 "$(DESTDIR)$(MANDIR)/man8/"

.PHONY:	clean install
