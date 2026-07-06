# Conduit — build file
#
# Targets:
#   make            build everything into build/
#   make test       build and run the unit tests
#   make example    build the udp_hello example
#   make clean      remove all build artifacts

CC      ?= cc
CFLAGS  := -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Isrc $(EXTRA_CFLAGS)
BUILD   := build

LIB_SRC := src/conduit.c
LIB_OBJ := $(BUILD)/conduit.o

TEST_BIN    := $(BUILD)/test_conduit
EXAMPLE_BIN := $(BUILD)/udp_hello
PING_BIN    := $(BUILD)/conduit_ping
HS_BIN      := $(BUILD)/conduit_handshake
RTT_BIN     := $(BUILD)/conduit_rtt
RELIABLE_BIN := $(BUILD)/conduit_reliable

.PHONY: all test example ping handshake rtt reliable clean

all: $(TEST_BIN) $(EXAMPLE_BIN) $(PING_BIN) $(HS_BIN) $(RTT_BIN) $(RELIABLE_BIN)

# Compile the library object once; the test links against it.
$(LIB_OBJ): $(LIB_SRC) src/conduit.h | $(BUILD)
	$(CC) $(CFLAGS) -c $(LIB_SRC) -o $@

# The test links the test driver against the library object.
# The test links the test driver against the library object. It depends on the
# headers it includes, so editing a header triggers a rebuild.
$(TEST_BIN): tests/test_conduit.c tests/test.h src/conduit.h $(LIB_OBJ) | $(BUILD)
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

# conduit_rtt keeps a connection alive (heartbeats, RTT, timeout); links the library.
$(RTT_BIN): examples/conduit_rtt.c $(LIB_OBJ) | $(BUILD)
	$(CC) $(CFLAGS) $< $(LIB_OBJ) -o $@

rtt: $(RTT_BIN)

# conduit_reliable demonstrates reliable DATA (sequences, cumulative acks,
# retransmission); links the library.
$(RELIABLE_BIN): examples/conduit_reliable.c $(LIB_OBJ) | $(BUILD)
	$(CC) $(CFLAGS) $< $(LIB_OBJ) -o $@

reliable: $(RELIABLE_BIN)

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -rf $(BUILD)
