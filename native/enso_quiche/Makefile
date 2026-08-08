# enso_quiche JNI shim.
#
# Builds libenso_quiche.<so|dylib> against system libquiche + JDK JNI
# headers. Output lands in target/native/<os>-<arch>/ so build.clj can
# pack it into the jar at run-time load-time.
#
# Usage:
#   make            # default = release build for current host
#   make debug      # -O0 -g, keeps ASan-friendly build
#   make clean

JAVA_HOME ?= $(shell /usr/libexec/java_home 2>/dev/null || echo /usr/lib/jvm/default)
QUICHE_PREFIX ?= $(shell brew --prefix cloudflare-quiche 2>/dev/null || echo /usr/local)

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Darwin)
  OS := darwin
  LIB_EXT := dylib
  JNI_MD_INC := $(JAVA_HOME)/include/darwin
  LDFLAGS_EXTRA := -dynamiclib -Wl,-rpath,@loader_path -Wl,-rpath,$(QUICHE_PREFIX)/lib
else
  OS := linux
  LIB_EXT := so
  JNI_MD_INC := $(JAVA_HOME)/include/linux
  LDFLAGS_EXTRA := -shared -Wl,-rpath,$$$$ORIGIN -Wl,-rpath,$(QUICHE_PREFIX)/lib
endif

ARCH := $(UNAME_M)
ifeq ($(ARCH),x86_64)
  ARCH := amd64
endif

# Output directory mirrors target/native/<os>-<arch>/ layout so build.clj
# can locate the artifact per platform.
OUT_DIR := $(CURDIR)/../../target/native/$(OS)-$(ARCH)
OUT := $(OUT_DIR)/libenso_quiche.$(LIB_EXT)

CFLAGS ?= -O2 -std=c11 -fPIC -Wall -Wextra -Wno-unused-parameter
CFLAGS += -I$(JAVA_HOME)/include -I$(JNI_MD_INC) -I$(QUICHE_PREFIX)/include
LDFLAGS := $(LDFLAGS_EXTRA) -L$(QUICHE_PREFIX)/lib -lquiche

SRC := enso_quiche.c

.PHONY: all debug clean

all: $(OUT)

$(OUT): $(SRC)
	@mkdir -p $(OUT_DIR)
	$(CC) $(CFLAGS) $(SRC) -o $(OUT) $(LDFLAGS)
	@echo "Built $(OUT)"

debug: CFLAGS := -O0 -g -std=c11 -fPIC -Wall -Wextra -Wno-unused-parameter -I$(JAVA_HOME)/include -I$(JNI_MD_INC) -I$(QUICHE_PREFIX)/include
debug: $(OUT)

clean:
	rm -rf $(OUT_DIR)
