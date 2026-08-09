# enso_quiche JNI shim.
#
# Two build modes:
#   make                    # dynamic: -lquiche against $QUICHE_PREFIX/lib (dev)
#   make QUICHE_STATIC=1    # static:  links libquiche.a into libenso_quiche.
#                            # Requires QUICHE_LIB_DIR pointing at a directory
#                            # containing libquiche.a (from `cargo build
#                            # --release --lib --features ffi,pkg-config-meta`
#                            # against cloudflare/quiche 0.29.3).
#
# QUICHE_STATIC=1 is what the release CI uses so the shipped jar is
# self-contained: users don't need `brew install cloudflare-quiche`.
#
# Output lands in target/native/<os>-<arch>/ so build.clj can pack it
# into the jar at run-time load-time.

JAVA_HOME ?= $(shell /usr/libexec/java_home 2>/dev/null || echo /usr/lib/jvm/default)
QUICHE_PREFIX ?= $(shell brew --prefix cloudflare-quiche 2>/dev/null || echo /usr/local)
QUICHE_INCLUDE_DIR ?= $(QUICHE_PREFIX)/include
QUICHE_LIB_DIR ?= $(QUICHE_PREFIX)/lib

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

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
else
  OS := linux
  LIB_EXT := so
  JNI_MD_INC := $(JAVA_HOME)/include/linux
  DYNAMIC_LINK_FLAG := -shared
  # BoringSSL vendored inside libquiche.a pulls in pthread + dl; -lm is
  # cheap and covered by rustc's static musl variants too.
  STATIC_SYSLIBS := -lpthread -ldl -lm
endif

ARCH := $(UNAME_M)
ifeq ($(ARCH),x86_64)
  ARCH := amd64
endif
ifeq ($(ARCH),aarch64)
  ARCH := arm64
endif

OUT_DIR := $(CURDIR)/../../target/native/$(OS)-$(ARCH)
OUT := $(OUT_DIR)/libenso_quiche.$(LIB_EXT)

CFLAGS ?= -O2 -std=c11 -fPIC -Wall -Wextra -Wno-unused-parameter
CFLAGS += -I$(JAVA_HOME)/include -I$(JNI_MD_INC) -I$(QUICHE_INCLUDE_DIR)

ifdef QUICHE_STATIC
  # Static link libquiche.a into the shim so the resulting .dylib/.so
  # has no runtime dep on system libquiche. Standard archive semantics
  # — ld pulls only the objects transitively referenced from our C
  # source. All quiche_* APIs the shim currently exports get resolved;
  # if we add new bindings later we just recompile. Whole-archive
  # (-force_load / --whole-archive) tripped over ld64 duplicate-symbol
  # errors on modern macOS because libquiche.a already embeds a full
  # copy of BoringSSL.
  LDFLAGS := $(DYNAMIC_LINK_FLAG) \
    $(QUICHE_LIB_DIR)/libquiche.a \
    $(STATIC_SYSLIBS)
else
  # Dev / local dynamic build. Adds an rpath to the local quiche install
  # so `java -jar` works without LD_LIBRARY_PATH gymnastics.
  ifeq ($(UNAME_S),Darwin)
    LDFLAGS := $(DYNAMIC_LINK_FLAG) -Wl,-rpath,@loader_path -Wl,-rpath,$(QUICHE_LIB_DIR) \
      -L$(QUICHE_LIB_DIR) -lquiche
  else
    LDFLAGS := $(DYNAMIC_LINK_FLAG) -Wl,-rpath,$$$$ORIGIN -Wl,-rpath,$(QUICHE_LIB_DIR) \
      -L$(QUICHE_LIB_DIR) -lquiche
  endif
endif

SRC := enso_quiche.c

.PHONY: all debug clean

all: $(OUT)

$(OUT): $(SRC)
	@mkdir -p $(OUT_DIR)
	$(CC) $(CFLAGS) $(SRC) -o $(OUT) $(LDFLAGS)
	@echo "Built $(OUT) ($$(du -h $(OUT) | cut -f1))"

debug: CFLAGS := -O0 -g -std=c11 -fPIC -Wall -Wextra -Wno-unused-parameter -I$(JAVA_HOME)/include -I$(JNI_MD_INC) -I$(QUICHE_INCLUDE_DIR)
debug: $(OUT)

clean:
	rm -rf $(OUT_DIR)
