# libspscan: make, make check, make install [PREFIX=/usr/local]

CC ?= cc
CFLAGS ?= -O2
PREFIX ?= /usr/local
LIBDIR ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include

SOVERSION = 0
VERSION = 0.1.0
WARN = -Wall -Wextra -Wno-unused-function -Wno-unused-parameter
SECP = secp256k1/src
SECP_FLAGS = -I$(SECP) -I secp256k1/include -DENABLE_MODULE_EXTRAKEYS=1 \
	-DENABLE_MODULE_SILENTPAYMENTS=1 -DSECP256K1_NO_API_VISIBILITY_ATTRIBUTES=1
ALL_CFLAGS = -std=c99 -fPIC -fvisibility=hidden $(WARN) $(CFLAGS)

OBJS = build/spscan.o build/precomputed_ecmult.o build/precomputed_ecmult_gen.o

all: libspscan.so libspscan.a

build:
	mkdir -p build

build/spscan.o: src/spscan.c include/spscan.h | build
	$(CC) $(ALL_CFLAGS) $(SECP_FLAGS) -c $< -o $@

build/precomputed_%.o: $(SECP)/precomputed_%.c | build
	$(CC) $(ALL_CFLAGS) $(SECP_FLAGS) -w -c $< -o $@

libspscan.so: $(OBJS)
	$(CC) -shared -Wl,-soname,libspscan.so.$(SOVERSION) -Wl,-Bsymbolic $(LDFLAGS) -o $@ $(OBJS)

libspscan.a: $(OBJS)
	$(AR) rcs $@ $(OBJS)

# Built with VERIFY, which turns on libsecp256k1's internal consistency checks
# (field element magnitudes and the like).
build/test_spscan: tests/test_spscan.c src/spscan.c include/spscan.h build/precomputed_ecmult.o build/precomputed_ecmult_gen.o
	$(CC) $(ALL_CFLAGS) $(SECP_FLAGS) -DVERIFY -o $@ $< build/precomputed_ecmult.o build/precomputed_ecmult_gen.o

build/libspscan-verify.so: src/spscan.c include/spscan.h build/precomputed_ecmult.o build/precomputed_ecmult_gen.o
	$(CC) $(ALL_CFLAGS) $(SECP_FLAGS) -DVERIFY -shared -o $@ $< build/precomputed_ecmult.o build/precomputed_ecmult_gen.o

check: build/test_spscan build/libspscan-verify.so libspscan.so
	./build/test_spscan
	@if nm -D --defined-only libspscan.so | awk '{print $$3}' | grep -v '^spscan_'; then \
		echo "libspscan.so exports symbols other than spscan_*"; exit 1; fi

install: all
	install -d $(DESTDIR)$(LIBDIR) $(DESTDIR)$(INCLUDEDIR) $(DESTDIR)$(LIBDIR)/pkgconfig
	install -m 644 include/spscan.h $(DESTDIR)$(INCLUDEDIR)/
	install -m 644 libspscan.a $(DESTDIR)$(LIBDIR)/
	install -m 755 libspscan.so $(DESTDIR)$(LIBDIR)/libspscan.so.$(VERSION)
	ln -sf libspscan.so.$(VERSION) $(DESTDIR)$(LIBDIR)/libspscan.so.$(SOVERSION)
	ln -sf libspscan.so.$(SOVERSION) $(DESTDIR)$(LIBDIR)/libspscan.so
	printf 'prefix=%s\nlibdir=%s\nincludedir=%s\n\nName: libspscan\nDescription: BIP352 silent payment scanning\nVersion: %s\nLibs: -L$${libdir} -lspscan\nCflags: -I$${includedir}\n' \
		'$(PREFIX)' '$(LIBDIR)' '$(INCLUDEDIR)' '$(VERSION)' > $(DESTDIR)$(LIBDIR)/pkgconfig/libspscan.pc

# WebAssembly build for browsers: freestanding wasm32, no libc (wasm/libc.c has
# the few functions needed), no imports. Needs clang and wasm-ld (LLVM >= 15).
WASM_CC ?= clang
WASM_LD ?= wasm-ld
WASM_CFLAGS = --target=wasm32 -nostdinc -isystem $(shell $(WASM_CC) -print-resource-dir)/include \
	-isystem wasm/include -std=c99 -O2 -fvisibility=hidden $(WARN) -DUSE_FORCE_WIDEMUL_INT64=1
WASM_EXPORTS = spscan_version spscan_receiver_create spscan_receiver_destroy \
	spscan_receiver_scan_pubkey spscan_scan \
	spscan_gcs_match_any spscan_filter_check malloc free
WASM_OBJS = build/wasm/spscan.o build/wasm/precomputed_ecmult.o build/wasm/precomputed_ecmult_gen.o \
	build/wasm/libc.o

wasm: spscan.wasm

build/wasm:
	mkdir -p build/wasm

build/wasm/spscan.o: src/spscan.c include/spscan.h | build/wasm
	$(WASM_CC) $(WASM_CFLAGS) $(SECP_FLAGS) -c $< -o $@

build/wasm/precomputed_%.o: $(SECP)/precomputed_%.c | build/wasm
	$(WASM_CC) $(WASM_CFLAGS) $(SECP_FLAGS) -w -c $< -o $@

build/wasm/libc.o: wasm/libc.c | build/wasm
	$(WASM_CC) $(WASM_CFLAGS) -fno-builtin -c $< -o $@

spscan.wasm: $(WASM_OBJS)
	$(WASM_LD) --no-entry --strip-all -z stack-size=1048576 \
		$(addprefix --export=,$(WASM_EXPORTS)) -o $@ $(WASM_OBJS)

clean:
	rm -f build/*.o build/wasm/*.o build/test_spscan build/libspscan-verify.so libspscan.so libspscan.a spscan.wasm

.PHONY: all check install clean wasm
