ARCH ?= aarch64
CROSS_COMPILE ?= $(ARCH)-linux-gnu-
DESTDIR ?=

CC = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar

OBJS = $(patsubst %.c, %.o, $(wildcard *.c lib/*.c))

CFLAGS += -Iinclude
CFLAGS += -Ilib/qbman_userspace/include
CFLAGS += -Ilib/mc/include
CFLAGS += -D_GNU_SOURCE
CFLAGS += -O0 -g3
CFLAGS += -pthread
CFLAGS += ${EXTRA_CFLAGS}
CFLAGS += -Wall
CFLAGS += -Wextra -Wformat
CFLAGS += -std=gnu99
CFLAGS += -Wmissing-prototypes
CFLAGS += -Wpointer-arith
CFLAGS += -Wundef
CFLAGS += -Wstrict-prototypes
CFLAGS += -fdiagnostics-color

LDFLAGS = -static -Wl,--hash-style=gnu ${EXTRA_CFLAGS}

PREFIX = $(DESTDIR)/sbin

HEADER_DEPENDENCIES = $(subst .o,.d,$(OBJS))

BIN =./bin

MKDIR = mkdir -p

EXECS = $(BIN)/dce-api-perf-test

all: $(EXECS)

$(BIN)/%: tests/%.o libdce.a libqbman.a
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)


libdce.a: $(OBJS)
	$(MKDIR) $(BIN)
	$(AR) rcs $@ $(OBJS)

install:
	install -d $(PREFIX)
	install -m 755 $(EXECS) $(PREFIX)

clean:
	rm -f $(OBJS) \
	      $(HEADER_DEPENDENCIES) \
	      $(EXECS) \
	      libdce.a \
	      libqbman.a \
	      lib/qbman_userspace/lib*/libqbman.a \
	      tests/*.o

%.d: %.c
	@($(CC) $(CFLAGS) -M $< | \
	  sed 's,\($(notdir $*)\.o\) *:,$(dir $@)\1 $@: ,' > $@.tmp); \
	 mv $@.tmp $@

libqbman.a:
	cd lib/qbman_userspace && make clean && $(MAKE)
	cp lib/qbman_userspace/lib_$(ARCH)_static/libqbman.a .

-include $(HEADER_DEPENDENCIES)



