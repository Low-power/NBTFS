# Revised Makefile for nbtfsutils
# Copyright 2015-2023 Rivoreo

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
# IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


# The original notice from cNBT project follows:

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
INCLUDEDIR ?= $(PREFIX)/include
LIBDIR ?= $(PREFIX)/lib

PIC_OPTION ?= -fPIC
SONAME_OPTION ?= --soname

LIBNBT_OBJECTS := buffer.o nbt_loading.o nbt_parsing.o nbt_treeops.o nbt_util.o
SHARED_LIBNBT_OBJECTS := buffer.pic.o nbt_loading.pic.o nbt_parsing.pic.o nbt_treeops.pic.o nbt_util.pic.o

all:	nbtdump check regiondump mkfs.nbt mount.nbt

.git/logs/HEAD:

version.h:	.git/logs/HEAD
	export TZ=UTC; \
	if [ -f .git/HEAD ]; then \
		printf "#define NBTFSUTILS_VERSION \"%s\"\\n" "`git show --format=%cd_%h --date short --quiet | sed -e 1!d -e 's/-//g' -e 's/_/-/'`" > $@; \
	elif [ ! -f $@ ]; then \
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

libnbt.a:	$(LIBNBT_OBJECTS)
	$(AR) -rcs $@ $(LIBNBT_OBJECTS)

libnbt.so.1:	$(SHARED_LIBNBT_OBJECTS)
	$(CC) $(LDFLAGS) --shared -Wl,$(SONAME_OPTION),$@ $(SHARED_LIBNBT_OBJECTS) -o $@ -l z $(LIBS)

libnbt.so:	libnbt.so.1
	ln -sf libnbt.so.1 $@

.SUFFIXES:	.pic.o

# For GNU Make
%.pic.o:	%.c
	$(CC) $(CFLAGS) $(PIC_OPTION) -c $< -o $@

# For BSD make
.c.pic.o:
	$(CC) $(CFLAGS) $(PIC_OPTION) -c $< -o $@

test: check
	cd testdata && for f in *.nbt; do valgrind ../check "$$f" || exit; done

clean:
	rm -f nbtdump check regiondump mount.nbt mkfs.nbt libnbt.a libnbt.so.1 libnbt.so syncwrite.o $(LIBNBT_OBJECTS) $(SHARED_LIBNBT_OBJECTS)

install-commands:	all
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

install-headers:	buffer.h list.h nbt.h version.h
	[ -d "$(DESTDIR)$(INCLUDEDIR)/nbt" ] || mkdir -p "$(DESTDIR)$(INCLUDEDIR)/nbt"
	for f in buffer.h list.h nbt.h version.h; do $(INSTALL) -m 644 $$f "$(DESTDIR)$(INCLUDEDIR)/nbt/"; done

install-static-library:	libnbt.a
	[ -d "$(DESTDIR)$(LIBDIR)" ] || mkdir -p "$(DESTDIR)$(LIBDIR)"
	$(INSTALL) -m 644 libnbt.a "$(DESTDIR)$(LIBDIR)/"

install-shared-library:	libnbt.so.1
	[ -d "$(DESTDIR)$(LIBDIR)" ] || mkdir -p "$(DESTDIR)$(LIBDIR)"
	$(INSTALL) -m 755 libnbt.so.1 "$(DESTDIR)$(LIBDIR)/"

install-dev:	install-headers install-static-library install-shared-library
	ln -sf libnbt.so.1 "$(DESTDIR)$(LIBDIR)/libnbt.so"

install:	install-commands

.PHONY:	clean install-commands install-headers install-static-library install-shared-library install-dev install
