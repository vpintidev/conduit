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
    int short_ok = (short_r == CONDUIT_ERR_TOO_SHORT);
    printf("decode of 3-byte buffer: %s (expected rejection)\n",
           short_ok ? "rejected cleanly" : "WRONGLY ACCEPTED");

    /* 5. Handshake round-trips: build each message, then parse it back. */
    printf("\n-- handshake round-trips --\n");
    uint8_t pkt[64];
    conduit_header ph;

    size_t in_len = conduit_build_init(0x11111111u, pkt, sizeof(pkt));
    conduit_header_decode(pkt, in_len, &ph);
    conduit_handshake_init hi;
    conduit_parse_init(pkt, in_len, &hi);
    int init_ok = (ph.type == CONDUIT_PKT_HANDSHAKE_INIT)
               && (ph.connection_id == CONDUIT_CID_UNSPECIFIED)
               && (hi.version == CONDUIT_PROTOCOL_VERSION)
               && (hi.initiator_cid == 0x11111111u);
    printf("INIT    (%zu bytes): initiator_cid=0x%08X version=%u -> %s\n",
           in_len, (unsigned)hi.initiator_cid, (unsigned)hi.version,
           init_ok ? "ok" : "FAIL");

    size_t rs_len = conduit_build_resp(0x11111111u, 0x22222222u, 0xDEADBEEFu, pkt, sizeof(pkt));
    conduit_header_decode(pkt, rs_len, &ph);
    conduit_handshake_resp hr;
    conduit_parse_resp(pkt, rs_len, &hr);
    int resp_ok = (ph.type == CONDUIT_PKT_HANDSHAKE_RESP)
               && (ph.connection_id == 0x11111111u)   /* addressed to initiator */
               && (hr.responder_cid == 0x22222222u)
               && (hr.token == 0xDEADBEEFu);
    printf("RESP    (%zu bytes): responder_cid=0x%08X token=0x%08X -> %s\n",
           rs_len, (unsigned)hr.responder_cid, (unsigned)hr.token,
           resp_ok ? "ok" : "FAIL");

    size_t cf_len = conduit_build_confirm(0x22222222u, 0xDEADBEEFu, pkt, sizeof(pkt));
    conduit_header_decode(pkt, cf_len, &ph);
    conduit_handshake_confirm hc;
    conduit_parse_confirm(pkt, cf_len, &hc);
    int conf_ok = (ph.type == CONDUIT_PKT_HANDSHAKE_CONFIRM)
               && (ph.connection_id == 0x22222222u)   /* addressed to responder */
               && (hc.token == 0xDEADBEEFu);
    printf("CONFIRM (%zu bytes): token=0x%08X -> %s\n",
           cf_len, (unsigned)hc.token, conf_ok ? "ok" : "FAIL");

    conduit_handshake_init htmp;
    int hs_short_ok =
        (conduit_parse_init(pkt, CONDUIT_HEADER_SIZE + 2, &htmp) == CONDUIT_ERR_TOO_SHORT);
    printf("truncated INIT body: %s\n",
           hs_short_ok ? "rejected cleanly" : "WRONGLY ACCEPTED");

    int all_ok = ok && short_ok && init_ok && resp_ok && conf_ok && hs_short_ok;
    printf("\nALL TESTS: %s\n", all_ok ? "PASS" : "FAIL");
    return all_ok ? 0 : 1;
}