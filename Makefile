# dpiOS - DPI circumvention for macOS (Apple Silicon)

CC      ?= clang
PREFIX  ?= /usr/local
ARCHS   ?= -arch arm64
MIN_OS  ?= 11.0

CFLAGS  += -std=c11 -O2 -g -Wall -Wextra -Wno-unused-parameter \
           -fno-omit-frame-pointer \
           -mmacosx-version-min=$(MIN_OS) $(ARCHS)
LDFLAGS += -mmacosx-version-min=$(MIN_OS) $(ARCHS)

SRCDIR  := src
BUILDIR := build
BIN     := $(BUILDIR)/dpios

SOURCES := $(wildcard $(SRCDIR)/*.c)
OBJECTS := $(patsubst $(SRCDIR)/%.c,$(BUILDIR)/%.o,$(SOURCES))
DEPS    := $(OBJECTS:.o=.d)

TESTBIN := $(BUILDIR)/test_dpios
# only the host-independent half: parsers, checksums, lists, presets
TESTSRC := tests/test_dpios.c $(SRCDIR)/tls.c $(SRCDIR)/http.c \
           $(SRCDIR)/checksum.c $(SRCDIR)/blacklist.c $(SRCDIR)/config.c \
           $(SRCDIR)/log.c

.PHONY: all clean install uninstall universal check test cross

all: $(BIN)

$(BIN): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^

$(BUILDIR)/%.o: $(SRCDIR)/%.c | $(BUILDIR)
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

$(BUILDIR):
	@mkdir -p $(BUILDIR)

# Intel + Apple Silicon in one binary
universal:
	$(MAKE) clean
	$(MAKE) ARCHS="-arch arm64 -arch x86_64"

clean:
	rm -rf $(BUILDIR)

install: $(BIN)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/bin/dpios
	@echo "installed $(DESTDIR)$(PREFIX)/bin/dpios"
	@echo "run 'sudo dpios --check' to verify this machine, then"
	@echo "'sudo ./scripts/install-service.sh' to start it at boot"

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/dpios

# convenience: build then run the self-test
check: $(BIN)
	sudo $(BIN) --check

test: | $(BUILDIR)
	$(CC) $(CFLAGS) -I$(SRCDIR) -o $(TESTBIN) $(TESTSRC)
	$(TESTBIN)

# build a macOS binary from a Linux host (development aid, see the script)
cross:
	./scripts/crossbuild.sh

-include $(DEPS)
