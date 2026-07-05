#include "conduit.h"
#include <arpa/inet.h> /* htonl, ntohl, htons, ntohs */
#include <string.h>    /* memcpy */

size_t conduit_header_encode(const conduit_header *h, uint8_t *buf)
{
    /* Lay the fields out at explicit offsets, each in network byte order.
     *   bytes [0..3] connection_id
     *   byte  [4]    type
     *   bytes [5..6] flags
     * We copy field by field (never the struct as a whole) so the result is
     * independent of this machine's padding and endianness. */
    uint32_t cid_be = htonl(h->connection_id);
    uint16_t flg_be = htons(h->flags);

    memcpy(buf + 0, &cid_be, 4);
    buf[4] = h->type;
    memcpy(buf + 5, &flg_be, 2);

    return CONDUIT_HEADER_SIZE;
}

conduit_result conduit_header_decode(const uint8_t *buf, size_t len,
                                     conduit_header *out)
{
    /* 1. Never read a byte we have not proven exists. A datagram shorter than
     *    the fixed header is malformed; reject it before touching its bytes. */
    if (len < CONDUIT_HEADER_SIZE)
    {
        return CONDUIT_ERR_TOO_SHORT;
    }

    /* 2. Read the fields back, converting from network to host byte order. */
    uint32_t cid_be;
    uint16_t flg_be;
    memcpy(&cid_be, buf + 0, 4);
    memcpy(&flg_be, buf + 5, 2);

    out->connection_id = ntohl(cid_be);
    out->type = buf[4];
    out->flags = ntohs(flg_be);

    /* 3. If the sender set a CRITICAL flag bit we do not recognize, we must not
     *    guess at the packet's meaning -- reject it cleanly. We compute the set
     *    critical bits and subtract the ones we know; anything left is unknown.
     *    In circle 1 no critical flags are defined, so `known_critical` is 0. */
    uint16_t critical_set = (uint16_t)(out->flags & CONDUIT_FLAG_CRITICAL_MASK);
    uint16_t known_critical = 0; /* grows as critical flags are defined */
    uint16_t unknown_set = (uint16_t)(critical_set & (uint16_t)~known_critical);
    if (unknown_set != 0)
    {
        return CONDUIT_ERR_UNKNOWN_CRITICAL;
    }

    return CONDUIT_OK;
}

const char *conduit_packet_type_name(uint8_t type)
{
    switch (type)
    {
    case CONDUIT_PKT_HANDSHAKE_INIT:
        return "HANDSHAKE_INIT";
    case CONDUIT_PKT_HANDSHAKE_RESP:
        return "HANDSHAKE_RESP";
    case CONDUIT_PKT_HANDSHAKE_CONFIRM:
        return "HANDSHAKE_CONFIRM";
    case CONDUIT_PKT_DATA:
        return "DATA";
    case CONDUIT_PKT_HEARTBEAT:
        return "HEARTBEAT";
    case CONDUIT_PKT_HEARTBEAT_ACK:
        return "HEARTBEAT_ACK";
    case CONDUIT_PKT_CLOSE:
        return "CLOSE";
    default:
        return "UNKNOWN";
    }
}

/* ============================================================================
 * Handshake builders and parsers
 *
 * A handshake packet is the fixed header (Section 2.2 of the spec) followed by
 * a small body. Builders produce a complete packet; parsers read the body of a
 * packet whose fixed header has already been validated by conduit_header_decode().
 * ========================================================================== */

/* Read/write fixed-width integers in network byte order at a given offset. */
static void put_u32(uint8_t *p, uint32_t v)
{
    uint32_t be = htonl(v);
    memcpy(p, &be, 4);
}
static uint32_t get_u32(const uint8_t *p)
{
    uint32_t be;
    memcpy(&be, p, 4);
    return ntohl(be);
}

size_t conduit_build_init(uint32_t initiator_cid, uint8_t *buf, size_t cap)
{
    if (cap < CONDUIT_INIT_SIZE)
        return 0;
    /* INIT is addressed to a not-yet-known responder: header CID is unspecified. */
    conduit_header h = {CONDUIT_CID_UNSPECIFIED, CONDUIT_PKT_HANDSHAKE_INIT, 0};
    conduit_header_encode(&h, buf);
    buf[CONDUIT_HEADER_SIZE + 0] = CONDUIT_PROTOCOL_VERSION;
    put_u32(buf + CONDUIT_HEADER_SIZE + 1, initiator_cid);
    return CONDUIT_INIT_SIZE;
}

size_t conduit_build_resp(uint32_t initiator_cid, uint32_t responder_cid,
                          uint32_t token, uint8_t *buf, size_t cap)
{
    if (cap < CONDUIT_RESP_SIZE)
        return 0;
    /* RESP is addressed to the initiator, by the ID it chose. */
    conduit_header h = {initiator_cid, CONDUIT_PKT_HANDSHAKE_RESP, 0};
    conduit_header_encode(&h, buf);
    buf[CONDUIT_HEADER_SIZE + 0] = CONDUIT_PROTOCOL_VERSION;
    put_u32(buf + CONDUIT_HEADER_SIZE + 1, responder_cid);
    put_u32(buf + CONDUIT_HEADER_SIZE + 5, token);
    return CONDUIT_RESP_SIZE;
}

size_t conduit_build_confirm(uint32_t responder_cid, uint32_t token,
                             uint8_t *buf, size_t cap)
{
    if (cap < CONDUIT_CONFIRM_SIZE)
        return 0;
    /* CONFIRM is addressed to the responder, by the ID it chose. */
    conduit_header h = {responder_cid, CONDUIT_PKT_HANDSHAKE_CONFIRM, 0};
    conduit_header_encode(&h, buf);
    put_u32(buf + CONDUIT_HEADER_SIZE + 0, token);
    return CONDUIT_CONFIRM_SIZE;
}

conduit_result conduit_parse_init(const uint8_t *buf, size_t len,
                                  conduit_handshake_init *out)
{
    if (len < CONDUIT_INIT_SIZE)
        return CONDUIT_ERR_TOO_SHORT;
    out->version = buf[CONDUIT_HEADER_SIZE + 0];
    out->initiator_cid = get_u32(buf + CONDUIT_HEADER_SIZE + 1);
    return CONDUIT_OK;
}

conduit_result conduit_parse_resp(const uint8_t *buf, size_t len,
                                  conduit_handshake_resp *out)
{
    if (len < CONDUIT_RESP_SIZE)
        return CONDUIT_ERR_TOO_SHORT;
    out->version = buf[CONDUIT_HEADER_SIZE + 0];
    out->responder_cid = get_u32(buf + CONDUIT_HEADER_SIZE + 1);
    out->token = get_u32(buf + CONDUIT_HEADER_SIZE + 5);
    return CONDUIT_OK;
}

conduit_result conduit_parse_confirm(const uint8_t *buf, size_t len,
                                     conduit_handshake_confirm *out)
{
    if (len < CONDUIT_CONFIRM_SIZE)
        return CONDUIT_ERR_TOO_SHORT;
    out->token = get_u32(buf + CONDUIT_HEADER_SIZE + 0);
    return CONDUIT_OK;
}

/* ============================================================================
 * Heartbeat builders and parser
 * ========================================================================== */

/* HEARTBEAT and HEARTBEAT_ACK differ only by packet type, so they share one
 * internal builder. */
static size_t build_heartbeat_typed(uint8_t type, uint32_t dest_cid,
                                    uint32_t sequence, uint8_t *buf, size_t cap)
{
    if (cap < CONDUIT_HEARTBEAT_SIZE)
        return 0;
    conduit_header h = {dest_cid, type, 0};
    conduit_header_encode(&h, buf);
    put_u32(buf + CONDUIT_HEADER_SIZE + 0, sequence);
    return CONDUIT_HEARTBEAT_SIZE;
}

size_t conduit_build_heartbeat(uint32_t dest_cid, uint32_t sequence,
                               uint8_t *buf, size_t cap)
{
    return build_heartbeat_typed(CONDUIT_PKT_HEARTBEAT, dest_cid, sequence, buf, cap);
}

size_t conduit_build_heartbeat_ack(uint32_t dest_cid, uint32_t sequence,
                                   uint8_t *buf, size_t cap)
{
    return build_heartbeat_typed(CONDUIT_PKT_HEARTBEAT_ACK, dest_cid, sequence, buf, cap);
}

conduit_result conduit_parse_heartbeat(const uint8_t *buf, size_t len,
                                       conduit_heartbeat *out)
{
    if (len < CONDUIT_HEARTBEAT_SIZE)
        return CONDUIT_ERR_TOO_SHORT;
    out->sequence = get_u32(buf + CONDUIT_HEADER_SIZE + 0);
    return CONDUIT_OK;
}

/* ============================================================================
 * Close builder and parser
 *
 * CLOSE carries a single Reason octet after the fixed header. It is best-effort:
 * no ack, no retransmission (spec Section 3.3). See conduit.h for the rationale.
 * ========================================================================== */

size_t conduit_build_close(uint32_t dest_cid, uint8_t reason,
                           uint8_t *buf, size_t cap)
{
    if (cap < CONDUIT_CLOSE_SIZE)
        return 0;
    conduit_header h = {dest_cid, CONDUIT_PKT_CLOSE, 0};
    conduit_header_encode(&h, buf);
    buf[CONDUIT_HEADER_SIZE + 0] = reason;
    return CONDUIT_CLOSE_SIZE;
}

conduit_result conduit_parse_close(const uint8_t *buf, size_t len,
                                   conduit_close *out)
{
    if (len < CONDUIT_CLOSE_SIZE)
        return CONDUIT_ERR_TOO_SHORT;
    out->reason = buf[CONDUIT_HEADER_SIZE + 0];
    return CONDUIT_OK;
}

const char *conduit_close_reason_name(uint8_t reason)
{
    switch (reason)
    {
    case CONDUIT_CLOSE_NONE:
        return "NONE";
    case CONDUIT_CLOSE_APPLICATION:
        return "APPLICATION";
    case CONDUIT_CLOSE_SHUTDOWN:
        return "SHUTDOWN";
    case CONDUIT_CLOSE_PROTOCOL_ERROR:
        return "PROTOCOL_ERROR";
    default:
        return "UNKNOWN";
    }
}

/* ============================================================================
 * Connection liveness and RTT
 * ========================================================================== */

void conduit_conn_init(conduit_conn *c, uint32_t peer_cid,
                       uint32_t interval_ms, uint32_t timeout_count)
{
    memset(c, 0, sizeof(*c));
    c->peer_cid = peer_cid;
    c->interval_ms = interval_ms;
    c->timeout_count = timeout_count;
    c->state = CONDUIT_CONN_ALIVE;
    c->next_seq = 1; /* sequence 0 is reserved to mean "none" */
    /* last_send_ms starts at 0, so the first tick sends a heartbeat promptly. */
}

size_t conduit_conn_tick(conduit_conn *c, uint64_t now_ms, uint8_t *out, size_t cap)
{
    if (c->state != CONDUIT_CONN_ALIVE)
        return 0;

    /* Too many probes went unanswered -> the peer is gone. */
    if (c->inflight >= c->timeout_count)
    {
        c->state = CONDUIT_CONN_LOST;
        return 0;
    }

    /* Still within the idle interval -> nothing to do yet. */
    if (now_ms - c->last_send_ms < c->interval_ms)
        return 0;

    /* Idle long enough -> emit a heartbeat and remember it (for RTT / timeout). */
    uint32_t seq = c->next_seq++;
    size_t n = conduit_build_heartbeat(c->peer_cid, seq, out, cap);
    if (n == 0)
        return 0; /* buffer too small; send nothing */
    c->last_send_ms = now_ms;
    c->inflight++;
    c->has_pending = 1;
    c->pending_seq = seq;
    c->pending_since_ms = now_ms;
    return n;
}

void conduit_conn_on_ack(conduit_conn *c, uint32_t acked_seq, uint64_t now_ms)
{
    if (c->state != CONDUIT_CONN_ALIVE)
        return;
    c->inflight = 0; /* a reply proves the peer is alive */
    if (c->has_pending && acked_seq == c->pending_seq)
    {
        c->last_rtt_ms = (uint32_t)(now_ms - c->pending_since_ms);
        c->has_rtt = 1;
        c->has_pending = 0;
    }
}

void conduit_conn_note_recv(conduit_conn *c)
{
    if (c->state == CONDUIT_CONN_ALIVE)
        c->inflight = 0;
}

void conduit_conn_close(conduit_conn *c)
{
    /* A peer already declared LOST cannot be gracefully closed; leave it LOST.
     * From any other state, the connection becomes deliberately CLOSED. Once
     * CLOSED, conduit_conn_tick() is inert and on_ack/note_recv are ignored,
     * because those paths already guard on state == ALIVE. */
    if (c->state == CONDUIT_CONN_ALIVE)
    {
        c->state = CONDUIT_CONN_CLOSED;
        c->has_pending = 0; /* drop any outstanding probe: we're done */
    }
}

conduit_conn_state conduit_conn_status(const conduit_conn *c)
{
    return c->state;
}

int conduit_conn_rtt_ms(const conduit_conn *c, uint32_t *out_rtt_ms)
{
    if (!c->has_rtt)
        return 0;
    *out_rtt_ms = c->last_rtt_ms;
    return 1;
}

/* ============================================================================
 * Handshake driver with retransmission
 *
 * See conduit.h for the full rationale. In short: only the initiator keeps a
 * timer, and only for INIT; the responder is stateless with respect to timers;
 * a lost CONFIRM is repaired by the keep-alive timeout, not retransmitted here.
 * ========================================================================== */

void conduit_handshake_init_initiator(conduit_handshake_state *hs, uint32_t my_cid,
                                      uint32_t initial_backoff_ms,
                                      uint32_t backoff_cap_ms, uint32_t max_attempts)
{
    memset(hs, 0, sizeof(*hs));
    hs->role = CONDUIT_ROLE_INITIATOR;
    hs->state = CONDUIT_HS_INIT_SENT;
    hs->my_cid = my_cid;
    hs->max_attempts = max_attempts;
    hs->backoff_ms = initial_backoff_ms;
    hs->backoff_cap_ms = backoff_cap_ms;
    /* last_init_ms stays 0 and attempts stays 0, so the first tick sends INIT
     * immediately (see the "due now" logic in _tick). */
}

void conduit_handshake_init_responder(conduit_handshake_state *hs, uint32_t my_cid)
{
    memset(hs, 0, sizeof(*hs));
    hs->role = CONDUIT_ROLE_RESPONDER;
    hs->state = CONDUIT_HS_LISTEN;
    hs->my_cid = my_cid;
}

size_t conduit_handshake_tick(conduit_handshake_state *hs, uint64_t now_ms,
                              uint8_t *out, size_t cap)
{
    /* Only the initiator, still waiting for RESP, ever sends from _tick. */
    if (hs->role != CONDUIT_ROLE_INITIATOR || hs->state != CONDUIT_HS_INIT_SENT)
        return 0;

    /* Out of attempts -> the handshake has failed. */
    if (hs->attempts >= hs->max_attempts)
    {
        hs->state = CONDUIT_HS_FAILED;
        return 0;
    }

    /* Is an INIT due? The very first one (attempts == 0) is due immediately;
     * later ones are due once the current backoff has elapsed since the last. */
    if (hs->attempts > 0 && (now_ms - hs->last_init_ms) < hs->backoff_ms)
        return 0;

    size_t n = conduit_build_init(hs->my_cid, out, cap);
    if (n == 0)
        return 0; /* buffer too small; send nothing, don't count the attempt */

    hs->last_init_ms = now_ms;
    hs->attempts++;

    /* Grow the backoff for next time (exponential), capped. Skip the growth on
     * the first send so the first *retransmit* waits the initial interval. */
    if (hs->attempts > 1)
    {
        uint64_t doubled = (uint64_t)hs->backoff_ms * 2u;
        hs->backoff_ms = (doubled > hs->backoff_cap_ms)
                             ? hs->backoff_cap_ms
                             : (uint32_t)doubled;
    }
    return n;
}

size_t conduit_handshake_on_init(conduit_handshake_state *hs,
                                 const uint8_t *buf, size_t len, uint32_t token,
                                 uint8_t *out, size_t cap)
{
    if (hs->role != CONDUIT_ROLE_RESPONDER)
        return 0;
    /* Accept an INIT while listening, and also a repeat INIT after we already
     * sent RESP (its earlier RESP may have been lost): re-issue RESP either way.
     * Once ESTABLISHED we ignore further INITs. */
    if (hs->state != CONDUIT_HS_LISTEN && hs->state != CONDUIT_HS_RESP_SENT)
        return 0;

    conduit_handshake_init hi;
    if (conduit_parse_init(buf, len, &hi) != CONDUIT_OK)
        return 0;

    hs->peer_cid = hi.initiator_cid; /* the initiator's chosen CID (from body) */
    hs->token = token;
    hs->has_token = 1;

    /* RESP is addressed to the initiator, carries our CID and the token. */
    size_t n = conduit_build_resp(hs->peer_cid, hs->my_cid, hs->token, out, cap);
    if (n == 0)
        return 0;
    hs->state = CONDUIT_HS_RESP_SENT;
    return n;
}

size_t conduit_handshake_on_resp(conduit_handshake_state *hs,
                                 const uint8_t *buf, size_t len,
                                 uint8_t *out, size_t cap)
{
    if (hs->role != CONDUIT_ROLE_INITIATOR)
        return 0;
    /* Accept RESP while waiting for it; a duplicate after ESTABLISHED just
     * re-emits CONFIRM (harmless). Ignore in any other state. */
    if (hs->state != CONDUIT_HS_INIT_SENT && hs->state != CONDUIT_HS_ESTABLISHED)
        return 0;

    conduit_handshake_resp hr;
    if (conduit_parse_resp(buf, len, &hr) != CONDUIT_OK)
        return 0;

    hs->peer_cid = hr.responder_cid;
    hs->token = hr.token;
    hs->has_token = 1;

    /* CONFIRM is addressed to the responder and echoes the token. */
    size_t n = conduit_build_confirm(hs->peer_cid, hs->token, out, cap);
    if (n == 0)
        return 0;
    hs->state = CONDUIT_HS_ESTABLISHED;
    return n;
}

int conduit_handshake_on_confirm(conduit_handshake_state *hs,
                                 const uint8_t *buf, size_t len)
{
    if (hs->role != CONDUIT_ROLE_RESPONDER)
        return 0;
    if (hs->state != CONDUIT_HS_RESP_SENT && hs->state != CONDUIT_HS_ESTABLISHED)
        return 0;

    conduit_handshake_confirm hc;
    if (conduit_parse_confirm(buf, len, &hc) != CONDUIT_OK)
        return 0;

    /* The token must match the one we issued in RESP. */
    if (!hs->has_token || hc.token != hs->token)
        return 0;

    hs->state = CONDUIT_HS_ESTABLISHED;
    return 1;
}

conduit_hs_state conduit_handshake_status(const conduit_handshake_state *hs)
{
    return hs->state;
}

uint32_t conduit_handshake_peer_cid(const conduit_handshake_state *hs)
{
    return hs->peer_cid;
}