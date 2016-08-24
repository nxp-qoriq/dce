CROSS_COMPILE ?=
DESTDIR ?=

CC = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar

OBJS = dce.o \
       dce-fd-frc.o \
       dce-fd.o \
       dce-fcr.o \
       lib/fsl_mc_sys.o \
       lib/dprc.o \
       lib/dpio.o \
       lib/dpdcei.o \
       lib/vfio_utils.o \
       lib/allocator.o \
       lib/dpio_service.o \
       dce-scf-compression.o \
       dce-scf-decompression.o \
       dpdcei-drv.o \

CFLAGS = -Iinclude \
	 -Ilib/qbman_userspace/include \
	 -D_GNU_SOURCE \
	 -O2 \
	 -pthread \
	 ${EXTRA_CFLAGS} \
	 -Wall \
	 -Wextra -Wformat \
	 -std=gnu99 \
	 -Wmissing-prototypes \
	 -Wpointer-arith \
	 -Wundef \
	 -Wstrict-prototypes \
	 -fdiagnostics-color
	 #-fmax-errors=4 \
	 # -Winline \
	 #-Werror

LDFLAGS = -static -Wl,--hash-style=gnu ${EXTRA_CFLAGS}

PREFIX = $(DESTDIR)/sbin

HEADER_DEPENDENCIES = $(subst .o,.d,$(OBJS))

BIN =./bin

MKDIR = mkdir -p

EXECS = $(BIN)/dce-api-perf-test

all: $(EXECS)

$(BIN)/%: tests/%.o libdce.a libqbman.a
	$(CC) $(CFLAGS) $^ -o $@


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

export ARCH=aarch64

libqbman.a:
	cd lib/qbman_userspace && $(MAKE)
	cp lib/qbman_userspace/lib_aarch64_static/libqbman.a .

-include $(HEADER_DEPENDENCIES)



