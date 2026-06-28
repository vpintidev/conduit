# Conduit — build file
#
# Targets:
#   make            build everything into build/
#   make test       build and run the unit tests
#   make example    build the udp_hello example
#   make clean      remove all build artifacts

CC      := cc
CFLAGS  := -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Isrc
BUILD   := build

LIB_SRC := src/conduit.c
LIB_OBJ := $(BUILD)/conduit.o

TEST_BIN    := $(BUILD)/test_conduit
EXAMPLE_BIN := $(BUILD)/udp_hello

.PHONY: all test example clean

all: $(TEST_BIN) $(EXAMPLE_BIN)

# Compile the library object once; the test links against it.
$(LIB_OBJ): $(LIB_SRC) src/conduit.h | $(BUILD)
	$(CC) $(CFLAGS) -c $(LIB_SRC) -o $@

# The test links the test driver against the library object.
$(TEST_BIN): tests/test_conduit.c $(LIB_OBJ) | $(BUILD)
	$(CC) $(CFLAGS) $< $(LIB_OBJ) -o $@

test: $(TEST_BIN)
	./$(TEST_BIN)

# The example is a standalone spike and does not use the library.
$(EXAMPLE_BIN): examples/udp_hello.c | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@

example: $(EXAMPLE_BIN)

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -rf $(BUILD)