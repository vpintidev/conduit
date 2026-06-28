#include "conduit.h"
#include <stdio.h>

static void hexdump(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x ", buf[i]);
    printf("\n");
}

int main(void) {
    /* 1. Build a header in memory. */
    conduit_header out = {
        .connection_id = 0xABCD1234u,
        .type          = CONDUIT_PKT_HEARTBEAT,
        .flags         = 0
    };

    /* 2. Encode it to the wire format and show the raw bytes.
     *    Expect: ab cd 12 34   (connection ID, big-endian)
     *            20            (type = HEARTBEAT)
     *            00 00         (flags) */
    uint8_t buf[CONDUIT_HEADER_SIZE];
    size_t n = conduit_header_encode(&out, buf);
    printf("encoded %zu bytes: ", n);
    hexdump(buf, n);

    /* 3. Decode it back and check the values survived the round trip. */
    conduit_header in;
    conduit_result r = conduit_header_decode(buf, n, &in);
    if (r != CONDUIT_OK) {
        printf("decode FAILED with code %d\n", (int)r);
        return 1;
    }
    printf("decoded: connection_id=0x%08X  type=%s(0x%02X)  flags=0x%04X\n",
           (unsigned)in.connection_id,
           conduit_packet_type_name(in.type), (unsigned)in.type,
           (unsigned)in.flags);

    int ok = (in.connection_id == out.connection_id)
          && (in.type == out.type)
          && (in.flags == out.flags);
    printf("round-trip: %s\n", ok ? "OK" : "MISMATCH");

    /* 4. Feed a truncated (3-byte) buffer and confirm the parser refuses it. */
    conduit_header dummy;
    conduit_result short_r = conduit_header_decode(buf, 3, &dummy);
    printf("decode of 3-byte buffer: %s (expected rejection)\n",
           short_r == CONDUIT_ERR_TOO_SHORT ? "rejected cleanly" : "WRONGLY ACCEPTED");

    return ok ? 0 : 1;
}