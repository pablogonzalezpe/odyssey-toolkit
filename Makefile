CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic -Werror -std=c11 -Iinclude
LDFLAGS ?=
LDLIBS ?=

SRC_DIR := src
BIN_DIR := bin
TEST_DIR := tests
SRCS := $(wildcard $(SRC_DIR)/*.c)
LIB_SRCS := $(filter-out $(SRC_DIR)/main.c, $(SRCS))
SMOKE_TESTS := $(sort $(wildcard $(TEST_DIR)/smoke_*.sh))
C_PROBES := $(sort $(wildcard $(TEST_DIR)/_t*_probe.c $(TEST_DIR)/_t*_harness.c))

ifeq ($(OS),Windows_NT)
EXE_EXT := .exe
LDLIBS += -lws2_32
else
EXE_EXT :=
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS := $(shell pkg-config --libs openssl 2>/dev/null)
ifneq ($(strip $(OPENSSL_LIBS)),)
CFLAGS += -DOD_ENABLE_OPENSSL $(OPENSSL_CFLAGS)
LDLIBS += $(OPENSSL_LIBS)
endif
endif

TARGET := $(BIN_DIR)/odyssey$(EXE_EXT)

.PHONY: all clean test test-probes test-smoke

all: $(TARGET)

$(TARGET): $(SRCS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS) $(LDLIBS)

test: $(TARGET) test-probes test-smoke
	@echo "All tests passed."

test-probes: $(TARGET)
	@for src in $(C_PROBES); do \
		name=$$(basename "$$src" .c); \
		echo "[probe] $$name"; \
		$(CC) $(CFLAGS) -o $(BIN_DIR)/$$name $$src $(LIB_SRCS) $(LDFLAGS) $(LDLIBS) || exit 1; \
	done

test-smoke: $(TARGET)
	@for t in $(SMOKE_TESTS); do \
		name=$$(basename "$$t"); \
		echo "[smoke] $$name"; \
		bash "$$t" || exit 1; \
	done

clean:
	rm -rf $(BIN_DIR)
