// test_conduit.c — Unit tests for the Conduit wire primitives.
//
// Uses the minimal helper in test.h: each TEST(...) names a group, each
// CHECK*(...) asserts without aborting, and test_summary() prints the result and
// returns the exit code (0 = all passed).
//
// Build & run:  make test

#include "conduit.h"
#include "test.h"

int main(void)
{
    uint8_t buf[64];
    conduit_header h;

    /* ---- fixed header ---- */
    TEST("fixed header round-trip");
    conduit_header src = {0xABCD1234u, CONDUIT_PKT_DATA, 0};
    size_t n = conduit_header_encode(&src, buf);
    CHECK_EQ_SIZE(n, CONDUIT_HEADER_SIZE);
    CHECK(conduit_header_decode(buf, n, &h) == CONDUIT_OK);
    CHECK_EQ_U32(h.connection_id, 0xABCD1234u);
    CHECK(h.type == CONDUIT_PKT_DATA);
    CHECK_EQ_U32(h.flags, 0u);

    TEST("reject truncated header");
    CHECK(conduit_header_decode(buf, 3, &h) == CONDUIT_ERR_TOO_SHORT);

    TEST("reject unknown critical flag");
    /* A critical flag bit (high byte) undefined in this revision must be rejected. */
    conduit_header crit = {1u, CONDUIT_PKT_DATA, 0x0100u};
    conduit_header_encode(&crit, buf);
    CHECK(conduit_header_decode(buf, CONDUIT_HEADER_SIZE, &h) == CONDUIT_ERR_UNKNOWN_CRITICAL);

    /* ---- handshake ---- */
    TEST("handshake INIT round-trip");
    size_t in_len = conduit_build_init(0x11111111u, buf, sizeof(buf));
    CHECK_EQ_SIZE(in_len, CONDUIT_INIT_SIZE);
    CHECK(conduit_header_decode(buf, in_len, &h) == CONDUIT_OK);
    CHECK(h.type == CONDUIT_PKT_HANDSHAKE_INIT);
    CHECK_EQ_U32(h.connection_id, CONDUIT_CID_UNSPECIFIED);
    conduit_handshake_init hi;
    CHECK(conduit_parse_init(buf, in_len, &hi) == CONDUIT_OK);
    CHECK_EQ_U32(hi.version, CONDUIT_PROTOCOL_VERSION);
    CHECK_EQ_U32(hi.initiator_cid, 0x11111111u);

    TEST("handshake RESP round-trip");
    size_t rs_len = conduit_build_resp(0x11111111u, 0x22222222u, 0xDEADBEEFu, buf, sizeof(buf));
    CHECK_EQ_SIZE(rs_len, CONDUIT_RESP_SIZE);
    CHECK(conduit_header_decode(buf, rs_len, &h) == CONDUIT_OK);
    CHECK(h.type == CONDUIT_PKT_HANDSHAKE_RESP);
    CHECK_EQ_U32(h.connection_id, 0x11111111u); /* addressed to initiator */
    conduit_handshake_resp hr;
    CHECK(conduit_parse_resp(buf, rs_len, &hr) == CONDUIT_OK);
    CHECK_EQ_U32(hr.responder_cid, 0x22222222u);
    CHECK_EQ_U32(hr.token, 0xDEADBEEFu);

    TEST("handshake CONFIRM round-trip");
    size_t cf_len = conduit_build_confirm(0x22222222u, 0xDEADBEEFu, buf, sizeof(buf));
    CHECK_EQ_SIZE(cf_len, CONDUIT_CONFIRM_SIZE);
    CHECK(conduit_header_decode(buf, cf_len, &h) == CONDUIT_OK);
    CHECK(h.type == CONDUIT_PKT_HANDSHAKE_CONFIRM);
    CHECK_EQ_U32(h.connection_id, 0x22222222u); /* addressed to responder */
    conduit_handshake_confirm hc;
    CHECK(conduit_parse_confirm(buf, cf_len, &hc) == CONDUIT_OK);
    CHECK_EQ_U32(hc.token, 0xDEADBEEFu);

    TEST("reject truncated handshake body");
    conduit_handshake_init hi2;
    CHECK(conduit_parse_init(buf, CONDUIT_HEADER_SIZE + 2, &hi2) == CONDUIT_ERR_TOO_SHORT);

    /* ---- heartbeat ---- */
    TEST("heartbeat round-trip");
    size_t hb_len = conduit_build_heartbeat(0x0000BBBBu, 42u, buf, sizeof(buf));
    CHECK_EQ_SIZE(hb_len, CONDUIT_HEARTBEAT_SIZE);
    CHECK(conduit_header_decode(buf, hb_len, &h) == CONDUIT_OK);
    CHECK(h.type == CONDUIT_PKT_HEARTBEAT);
    CHECK_EQ_U32(h.connection_id, 0x0000BBBBu);
    conduit_heartbeat hb;
    CHECK(conduit_parse_heartbeat(buf, hb_len, &hb) == CONDUIT_OK);
    CHECK_EQ_U32(hb.sequence, 42u);

    TEST("heartbeat ACK round-trip");
    size_t ha_len = conduit_build_heartbeat_ack(0x0000AAAAu, 7u, buf, sizeof(buf));
    CHECK_EQ_SIZE(ha_len, CONDUIT_HEARTBEAT_SIZE);
    CHECK(conduit_header_decode(buf, ha_len, &h) == CONDUIT_OK);
    CHECK(h.type == CONDUIT_PKT_HEARTBEAT_ACK);
    conduit_heartbeat ha;
    CHECK(conduit_parse_heartbeat(buf, ha_len, &ha) == CONDUIT_OK);
    CHECK_EQ_U32(ha.sequence, 7u);

    TEST("reject truncated heartbeat body");
    conduit_heartbeat hb2;
    CHECK(conduit_parse_heartbeat(buf, CONDUIT_HEADER_SIZE + 1, &hb2) == CONDUIT_ERR_TOO_SHORT);

    /* ---- close ---- */
    TEST("close round-trip");
    size_t cl_len = conduit_build_close(0x0000BBBBu, CONDUIT_CLOSE_APPLICATION, buf, sizeof(buf));
    CHECK_EQ_SIZE(cl_len, CONDUIT_CLOSE_SIZE);
    CHECK(conduit_header_decode(buf, cl_len, &h) == CONDUIT_OK);
    CHECK(h.type == CONDUIT_PKT_CLOSE);
    CHECK_EQ_U32(h.connection_id, 0x0000BBBBu);
    conduit_close cl;
    CHECK(conduit_parse_close(buf, cl_len, &cl) == CONDUIT_OK);
    CHECK_EQ_U32(cl.reason, CONDUIT_CLOSE_APPLICATION);

    TEST("close: builder refuses an undersized buffer");
    CHECK_EQ_SIZE(conduit_build_close(1u, CONDUIT_CLOSE_NONE, buf, CONDUIT_CLOSE_SIZE - 1), 0u);

    TEST("reject truncated close body");
    conduit_close cl2;
    CHECK(conduit_parse_close(buf, CONDUIT_HEADER_SIZE, &cl2) == CONDUIT_ERR_TOO_SHORT);

    TEST("close: unknown reason is preserved verbatim");
    /* Reason is diagnostic: an unrecognized value parses fine and is not remapped. */
    size_t cu_len = conduit_build_close(1u, 0xFFu, buf, sizeof(buf));
    conduit_close cl3;
    CHECK(conduit_parse_close(buf, cu_len, &cl3) == CONDUIT_OK);
    CHECK_EQ_U32(cl3.reason, 0xFFu);

    /* ---- liveness / RTT (deterministic, simulated clock) ---- */
    TEST("liveness: heartbeat fires only after the idle interval");
    conduit_conn c;
    conduit_conn_init(&c, 0x0000BBBBu, 1000u /*interval*/, 3u /*timeout*/);
    CHECK_EQ_SIZE(conduit_conn_tick(&c, 0, buf, sizeof(buf)), 0u);   /* not yet */
    CHECK_EQ_SIZE(conduit_conn_tick(&c, 999, buf, sizeof(buf)), 0u); /* not yet */
    size_t hn = conduit_conn_tick(&c, 1000, buf, sizeof(buf));       /* now! */
    CHECK_EQ_SIZE(hn, CONDUIT_HEARTBEAT_SIZE);
    CHECK(conduit_header_decode(buf, hn, &h) == CONDUIT_OK);
    CHECK(h.type == CONDUIT_PKT_HEARTBEAT);
    conduit_heartbeat probe;
    CHECK(conduit_parse_heartbeat(buf, hn, &probe) == CONDUIT_OK);
    CHECK_EQ_U32(probe.sequence, 1u);

    TEST("liveness: matching ack yields RTT and keeps the connection alive");
    conduit_conn_on_ack(&c, probe.sequence, 1200u); /* ack 200 ms later */
    uint32_t rtt = 0;
    CHECK(conduit_conn_rtt_ms(&c, &rtt) == 1);
    CHECK_EQ_U32(rtt, 200u);
    CHECK(conduit_conn_status(&c) == CONDUIT_CONN_ALIVE);

    TEST("liveness: connection declared lost after unacked probes");
    conduit_conn c2;
    conduit_conn_init(&c2, 0x0000BBBBu, 1000u, 3u);
    conduit_conn_tick(&c2, 1000, buf, sizeof(buf)); /* probe 1 */
    conduit_conn_tick(&c2, 2000, buf, sizeof(buf)); /* probe 2 */
    conduit_conn_tick(&c2, 3000, buf, sizeof(buf)); /* probe 3 */
    CHECK(conduit_conn_status(&c2) == CONDUIT_CONN_ALIVE);
    CHECK_EQ_SIZE(conduit_conn_tick(&c2, 4000, buf, sizeof(buf)), 0u); /* #4 -> lost */
    CHECK(conduit_conn_status(&c2) == CONDUIT_CONN_LOST);

    /* ---- termination (CLOSE) ---- */
    TEST("close: ALIVE -> CLOSED and tick becomes inert");
    conduit_conn c3;
    conduit_conn_init(&c3, 0x0000BBBBu, 1000u, 3u);
    CHECK(conduit_conn_status(&c3) == CONDUIT_CONN_ALIVE);
    conduit_conn_close(&c3);
    CHECK(conduit_conn_status(&c3) == CONDUIT_CONN_CLOSED);
    /* Even long past the interval, a CLOSED connection emits nothing and does
     * not transition to LOST. */
    CHECK_EQ_SIZE(conduit_conn_tick(&c3, 100000u, buf, sizeof(buf)), 0u);
    CHECK(conduit_conn_status(&c3) == CONDUIT_CONN_CLOSED);

    TEST("close: a LOST connection stays LOST");
    /* A peer already declared dead cannot be gracefully closed. */
    conduit_conn c4;
    conduit_conn_init(&c4, 0x0000BBBBu, 1000u, 3u);
    conduit_conn_tick(&c4, 1000, buf, sizeof(buf)); /* probe 1 */
    conduit_conn_tick(&c4, 2000, buf, sizeof(buf)); /* probe 2 */
    conduit_conn_tick(&c4, 3000, buf, sizeof(buf)); /* probe 3 */
    conduit_conn_tick(&c4, 4000, buf, sizeof(buf)); /* #4 -> lost */
    CHECK(conduit_conn_status(&c4) == CONDUIT_CONN_LOST);
    conduit_conn_close(&c4);
    CHECK(conduit_conn_status(&c4) == CONDUIT_CONN_LOST);

    /* ---- handshake driver (deterministic, simulated clock) ---- */
    TEST("handshake: full INIT/RESP/CONFIRM drives both sides to ESTABLISHED");
    {
        conduit_handshake_state ini, res;
        conduit_handshake_init_initiator(&ini, 0x0000AAAAu, 1000u, 4000u, 4u);
        conduit_handshake_init_responder(&res, 0x0000BBBBu);

        uint8_t initpkt[64], resppkt[64], confpkt[64];
        conduit_header hh;

        /* initiator's first tick emits INIT immediately */
        size_t ni = conduit_handshake_tick(&ini, 0, initpkt, sizeof(initpkt));
        CHECK_EQ_SIZE(ni, CONDUIT_INIT_SIZE);
        CHECK(conduit_header_decode(initpkt, ni, &hh) == CONDUIT_OK);
        CHECK(hh.type == CONDUIT_PKT_HANDSHAKE_INIT);

        /* responder consumes INIT, emits RESP (token is caller-supplied) */
        size_t nr = conduit_handshake_on_init(&res, initpkt, ni, 0xDEADBEEFu,
                                              resppkt, sizeof(resppkt));
        CHECK_EQ_SIZE(nr, CONDUIT_RESP_SIZE);
        CHECK(conduit_handshake_status(&res) == CONDUIT_HS_RESP_SENT);
        CHECK(conduit_header_decode(resppkt, nr, &hh) == CONDUIT_OK);
        CHECK(hh.type == CONDUIT_PKT_HANDSHAKE_RESP);
        CHECK_EQ_U32(hh.connection_id, 0x0000AAAAu); /* addressed to initiator */

        /* initiator consumes RESP, emits CONFIRM, is ESTABLISHED */
        size_t nc = conduit_handshake_on_resp(&ini, resppkt, nr,
                                              confpkt, sizeof(confpkt));
        CHECK_EQ_SIZE(nc, CONDUIT_CONFIRM_SIZE);
        CHECK(conduit_handshake_status(&ini) == CONDUIT_HS_ESTABLISHED);
        CHECK_EQ_U32(conduit_handshake_peer_cid(&ini), 0x0000BBBBu);
        CHECK(conduit_header_decode(confpkt, nc, &hh) == CONDUIT_OK);
        CHECK(hh.type == CONDUIT_PKT_HANDSHAKE_CONFIRM);
        CHECK_EQ_U32(hh.connection_id, 0x0000BBBBu); /* addressed to responder */

        /* responder consumes CONFIRM, token matches, is ESTABLISHED */
        CHECK(conduit_handshake_on_confirm(&res, confpkt, nc) == 1);
        CHECK(conduit_handshake_status(&res) == CONDUIT_HS_ESTABLISHED);
        CHECK_EQ_U32(conduit_handshake_peer_cid(&res), 0x0000AAAAu);
    }

    TEST("handshake: INIT retransmits on exponential backoff (1s, +2s, +4s capped)");
    {
        conduit_handshake_state ini;
        conduit_handshake_init_initiator(&ini, 0x0000AAAAu, 1000u, 4000u, 4u);
        uint8_t p[64];
        /* Sends at t=0, then when backoff elapses: 1000, 3000, 7000. Between
         * those instants, tick emits nothing. */
        CHECK_EQ_SIZE(conduit_handshake_tick(&ini, 0, p, sizeof(p)), CONDUIT_INIT_SIZE);
        CHECK_EQ_SIZE(conduit_handshake_tick(&ini, 999, p, sizeof(p)), 0u);
        CHECK_EQ_SIZE(conduit_handshake_tick(&ini, 1000, p, sizeof(p)), CONDUIT_INIT_SIZE);
        CHECK_EQ_SIZE(conduit_handshake_tick(&ini, 2999, p, sizeof(p)), 0u);
        CHECK_EQ_SIZE(conduit_handshake_tick(&ini, 3000, p, sizeof(p)), CONDUIT_INIT_SIZE);
        CHECK_EQ_SIZE(conduit_handshake_tick(&ini, 6999, p, sizeof(p)), 0u);
        CHECK_EQ_SIZE(conduit_handshake_tick(&ini, 7000, p, sizeof(p)), CONDUIT_INIT_SIZE);
        CHECK(conduit_handshake_status(&ini) == CONDUIT_HS_INIT_SENT);
    }

    TEST("handshake: initiator FAILS after max unanswered INITs");
    {
        conduit_handshake_state ini;
        conduit_handshake_init_initiator(&ini, 0x0000AAAAu, 1000u, 4000u, 4u);
        uint8_t p[64];
        conduit_handshake_tick(&ini, 0, p, sizeof(p));    /* INIT #1 */
        conduit_handshake_tick(&ini, 1000, p, sizeof(p)); /* INIT #2 */
        conduit_handshake_tick(&ini, 3000, p, sizeof(p)); /* INIT #3 */
        conduit_handshake_tick(&ini, 7000, p, sizeof(p)); /* INIT #4 */
        CHECK(conduit_handshake_status(&ini) == CONDUIT_HS_INIT_SENT);
        /* attempts now == max_attempts: next tick gives up */
        CHECK_EQ_SIZE(conduit_handshake_tick(&ini, 20000, p, sizeof(p)), 0u);
        CHECK(conduit_handshake_status(&ini) == CONDUIT_HS_FAILED);
    }

    TEST("handshake: a repeat INIT re-issues RESP (recovers a lost RESP)");
    {
        conduit_handshake_state res;
        conduit_handshake_init_responder(&res, 0x0000BBBBu);
        uint8_t initpkt[64], resppkt[64];
        size_t ni = conduit_build_init(0x0000AAAAu, initpkt, sizeof(initpkt));

        /* first INIT -> RESP */
        size_t nr1 = conduit_handshake_on_init(&res, initpkt, ni, 0x11111111u,
                                               resppkt, sizeof(resppkt));
        CHECK_EQ_SIZE(nr1, CONDUIT_RESP_SIZE);
        CHECK(conduit_handshake_status(&res) == CONDUIT_HS_RESP_SENT);

        /* the RESP was "lost"; the initiator re-sends INIT. The responder,
         * already in RESP_SENT, must emit a fresh RESP rather than ignore it. */
        size_t nr2 = conduit_handshake_on_init(&res, initpkt, ni, 0x22222222u,
                                               resppkt, sizeof(resppkt));
        CHECK_EQ_SIZE(nr2, CONDUIT_RESP_SIZE);
        CHECK(conduit_handshake_status(&res) == CONDUIT_HS_RESP_SENT);
    }

    TEST("handshake: CONFIRM with the wrong token is rejected");
    {
        conduit_handshake_state res;
        conduit_handshake_init_responder(&res, 0x0000BBBBu);
        uint8_t initpkt[64], resppkt[64], confpkt[64];
        size_t ni = conduit_build_init(0x0000AAAAu, initpkt, sizeof(initpkt));
        conduit_handshake_on_init(&res, initpkt, ni, 0xABCDABCDu,
                                  resppkt, sizeof(resppkt));

        /* CONFIRM echoing the WRONG token must be refused; state stays RESP_SENT. */
        size_t nbad = conduit_build_confirm(0x0000BBBBu, 0x00000000u,
                                            confpkt, sizeof(confpkt));
        CHECK(conduit_handshake_on_confirm(&res, confpkt, nbad) == 0);
        CHECK(conduit_handshake_status(&res) == CONDUIT_HS_RESP_SENT);

        /* the correct token is accepted */
        size_t ngood = conduit_build_confirm(0x0000BBBBu, 0xABCDABCDu,
                                             confpkt, sizeof(confpkt));
        CHECK(conduit_handshake_on_confirm(&res, confpkt, ngood) == 1);
        CHECK(conduit_handshake_status(&res) == CONDUIT_HS_ESTABLISHED);
    }

    return test_summary();
}