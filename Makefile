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
PING_BIN    := $(BUILD)/conduit_ping
HS_BIN      := $(BUILD)/conduit_handshake

.PHONY: all test example ping handshake clean

all: $(TEST_BIN) $(EXAMPLE_BIN) $(PING_BIN) $(HS_BIN)

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

# conduit_ping puts a real Conduit header on the wire; it links the library.
$(PING_BIN): examples/conduit_ping.c $(LIB_OBJ) | $(BUILD)
	$(CC) $(CFLAGS) $< $(LIB_OBJ) -o $@

ping: $(PING_BIN)

# conduit_handshake demonstrates the three-message handshake; links the library.
$(HS_BIN): examples/conduit_handshake.c $(LIB_OBJ) | $(BUILD)
	$(CC) $(CFLAGS) $< $(LIB_OBJ) -o $@

handshake: $(HS_BIN)

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -rf $(BUILD)