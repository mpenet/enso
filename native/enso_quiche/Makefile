# ABOUTME: Builds libenso_quiche, the JNI shim over libquiche, dynamically or statically linked,
# ABOUTME: with optional sanitizer and debug variants.
# enso_quiche JNI shim.
#
# Build modes:
#   make                    # dynamic: -lquiche against $QUICHE_PREFIX/lib (dev)
#   make QUICHE_STATIC=1    # static:  links libquiche.a into libenso_quiche.
#                            # Requires QUICHE_LIB_DIR pointing at a directory
#                            # containing libquiche.a (from `cargo build
#                            # --release --lib --features ffi,pkg-config-meta`
#                            # against cloudflare/quiche 0.29.3).
#   make SANITIZE=1         # AddressSanitizer + UndefinedBehaviorSanitizer
#                            # build for tests (combine with QUICHE_STATIC=1);
#                            # see doc/testing.md for running a JVM against it.
#   make debug              # -O0 -g
#
# QUICHE_STATIC=1 is what the release CI uses so the shipped jar is
# self-contained: users don't need `brew install cloudflare-quiche`.
#
# CFLAGS / LDFLAGS from the environment or the command line only add to
# the build (optimisation level, extra warnings): the language, PIC,
# visibility and hardening flags below are always applied.
#
# Output lands in target/native/<os>-<arch>/ so build.clj can pack it
# into the jar at run-time load-time.

JAVA_HOME ?= $(shell /usr/libexec/java_home 2>/dev/null || echo /usr/lib/jvm/default)
QUICHE_PREFIX ?= $(shell brew --prefix cloudflare-quiche 2>/dev/null || echo /usr/local)
QUICHE_INCLUDE_DIR ?= $(QUICHE_PREFIX)/include
QUICHE_LIB_DIR ?= $(QUICHE_PREFIX)/lib
# Oldest macOS the dylib loads on; libquiche.a must be built with the
# same MACOSX_DEPLOYMENT_TARGET.
MACOSX_DEPLOYMENT_TARGET ?= 11.0

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

# $(call cc-option,FLAG): FLAG when $(CC) accepts it, else nothing, so
# older compilers still build (release builds use compilers that take
# every flag below; see build-linux.sh).
cc-option = $(shell $(CC) -Werror $(1) -c -x c /dev/null -o /dev/null >/dev/null 2>&1 && echo $(1))

ifeq ($(UNAME_S),Darwin)
  OS := darwin
  LIB_EXT := dylib
  JNI_MD_INC := $(JAVA_HOME)/include/darwin
  DYNAMIC_LINK_FLAG := -dynamiclib
  # macOS system frameworks pulled in transitively by libquiche's Rust
  # deps (iana-time-zone → CoreFoundation; rustls/ring → Security;
  # network detection → SystemConfiguration). libSystem covers
  # pthread/dl/m so no explicit -l needed.
  STATIC_SYSLIBS := -framework CoreFoundation -framework Security -framework SystemConfiguration
  # Export only the JNI entry points (see exports.map for the rationale).
  EXPORT_FLAGS := -Wl,-exported_symbol,_Java_*
  # ld64 already emits PIC code with a non-executable stack and data, and
  # read-only __DATA_CONST via chained fixups for 11.0+ targets; pinning
  # the deployment target keeps those defaults and the minimum OS stable.
  PLATFORM_CFLAGS := -mmacosx-version-min=$(MACOSX_DEPLOYMENT_TARGET)
  # The install name is recorded by anything linking against the dylib;
  # keep it relocatable instead of the build directory's absolute path.
  HARDEN_LDFLAGS := -mmacosx-version-min=$(MACOSX_DEPLOYMENT_TARGET) \
    -Wl,-install_name,@rpath/libenso_quiche.dylib
else
  OS := linux
  LIB_EXT := so
  JNI_MD_INC := $(JAVA_HOME)/include/linux
  DYNAMIC_LINK_FLAG := -shared
  # BoringSSL vendored inside libquiche.a pulls in pthread + dl; -lm is
  # cheap and covered by rustc's static musl variants too.
  STATIC_SYSLIBS := -lpthread -ldl -lm
  # Export only the JNI entry points; keep libquiche.a's own (BoringSSL)
  # symbols local.
  EXPORT_FLAGS := -Wl,--version-script=$(CURDIR)/exports.map -Wl,--exclude-libs,ALL
  # Probe every page of large stack frames so a stack overflow can't jump
  # over the guard page.
  PLATFORM_CFLAGS := $(call cc-option,-fstack-clash-protection)
  # Full RELRO: the GOT is read-only once the loader resolved it.
  HARDEN_LDFLAGS := -Wl,-z,relro,-z,now -Wl,-z,noexecstack
  # libquiche.a carries DWARF for all of libquiche and BoringSSL (~30 MB):
  # drop it from the shipped library, keep the symbol table. Sanitizer
  # and debug builds keep it.
  RELEASE_LDFLAGS := -Wl,--strip-debug
endif

ARCH := $(UNAME_M)
ifeq ($(ARCH),x86_64)
  ARCH := amd64
  # Intel CET: indirect-branch tracking and shadow-stack markers.
  ifeq ($(OS),linux)
    ARCH_CFLAGS := $(call cc-option,-fcf-protection)
  endif
endif
ifeq ($(ARCH),aarch64)
  ARCH := arm64
endif
ifeq ($(ARCH),arm64)
  # Pointer authentication on returns and BTI landing pads.
  ARCH_CFLAGS := $(call cc-option,-mbranch-protection=standard)
endif

OUT_DIR := $(CURDIR)/../../target/native/$(OS)-$(ARCH)
OUT := $(OUT_DIR)/libenso_quiche.$(LIB_EXT)

CFLAGS ?= -O2
WARN_CFLAGS := -Wall -Wextra -Wno-unused-parameter -Werror=format-security
# Hardening: stack canaries, checked libc calls (FORTIFY needs -O1+; the
# -U first replaces any level a toolchain defines by default).
FORTIFY_CFLAGS := -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
HARDEN_CFLAGS = -fstack-protector-strong $(FORTIFY_CFLAGS) $(PLATFORM_CFLAGS) $(ARCH_CFLAGS)
# JNIEXPORT marks the entry points visible; everything else stays hidden.
SHIM_CFLAGS = -std=c11 -fPIC -fvisibility=hidden $(WARN_CFLAGS) $(HARDEN_CFLAGS) \
  -I$(JAVA_HOME)/include -I$(JNI_MD_INC) -I$(QUICHE_INCLUDE_DIR)

ifdef SANITIZE
  # ASan replaces the fortified libc wrappers with its own interceptors;
  # every UB report aborts so a test run cannot pass over one.
  FORTIFY_CFLAGS :=
  SANITIZE_FLAGS := -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g
  CFLAGS := -O1
  RELEASE_LDFLAGS :=
endif

ifdef QUICHE_STATIC
  # Static link libquiche.a into the shim so the resulting .dylib/.so
  # has no runtime dep on system libquiche. Standard archive semantics
  # — ld pulls only the objects transitively referenced from our C
  # source, so every quiche_* API the shim calls is resolved. Whole-
  # archive linking (-force_load / --whole-archive) is not used:
  # libquiche.a embeds a full copy of BoringSSL, which ld64 rejects as
  # duplicate symbols.
  SHIM_LDFLAGS = $(DYNAMIC_LINK_FLAG) $(EXPORT_FLAGS) $(HARDEN_LDFLAGS) $(RELEASE_LDFLAGS) \
    $(QUICHE_LIB_DIR)/libquiche.a \
    $(STATIC_SYSLIBS)
else
  # Dev / local dynamic build. Adds an rpath to the local quiche install
  # so `java -jar` works without LD_LIBRARY_PATH gymnastics.
  ifeq ($(UNAME_S),Darwin)
    SHIM_LDFLAGS := $(DYNAMIC_LINK_FLAG) $(EXPORT_FLAGS) $(HARDEN_LDFLAGS) -Wl,-rpath,@loader_path \
      -Wl,-rpath,$(QUICHE_LIB_DIR) -L$(QUICHE_LIB_DIR) -lquiche
  else
    SHIM_LDFLAGS := $(DYNAMIC_LINK_FLAG) $(EXPORT_FLAGS) $(HARDEN_LDFLAGS) -Wl,-rpath,'$$ORIGIN' \
      -Wl,-rpath,$(QUICHE_LIB_DIR) -L$(QUICHE_LIB_DIR) -lquiche
  endif
endif

SRC := enso_quiche.c

.PHONY: all debug clean

all: $(OUT)

$(OUT): $(SRC) Makefile exports.map $(QUICHE_INCLUDE_DIR)/quiche.h
	@mkdir -p $(OUT_DIR)
	$(CC) $(CFLAGS) $(SHIM_CFLAGS) $(SANITIZE_FLAGS) $(SRC) -o $(OUT) $(SANITIZE_FLAGS) $(SHIM_LDFLAGS) $(LDFLAGS)
	@echo "Built $(OUT) ($$(du -h $(OUT) | cut -f1))"

debug: CFLAGS := -O0 -g
debug: FORTIFY_CFLAGS :=
debug: RELEASE_LDFLAGS :=
debug: $(OUT)

clean:
	rm -rf $(OUT_DIR)
