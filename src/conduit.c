#include "conduit.h"
#include <arpa/inet.h> /* htonl, ntohl, htons, ntohs */
#include <string.h>    /* memcpy */

size_t conduit_header_encode(const conduit_header *h, uint8_t *buf) {
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
                                     conduit_header *out) {
    /* 1. Never read a byte we have not proven exists. A datagram shorter than
     *    the fixed header is malformed; reject it before touching its bytes. */
    if (len < CONDUIT_HEADER_SIZE) {
        return CONDUIT_ERR_TOO_SHORT;
    }

    /* 2. Read the fields back, converting from network to host byte order. */
    uint32_t cid_be;
    uint16_t flg_be;
    memcpy(&cid_be, buf + 0, 4);
    memcpy(&flg_be, buf + 5, 2);

    out->connection_id = ntohl(cid_be);
    out->type          = buf[4];
    out->flags         = ntohs(flg_be);

    /* 3. If the sender set a CRITICAL flag bit we do not recognize, we must not
     *    guess at the packet's meaning -- reject it cleanly. We compute the set
     *    critical bits and subtract the ones we know; anything left is unknown.
     *    In circle 1 no critical flags are defined, so `known_critical` is 0. */
    uint16_t critical_set   = (uint16_t)(out->flags & CONDUIT_FLAG_CRITICAL_MASK);
    uint16_t known_critical = 0; /* grows as critical flags are defined */
    uint16_t unknown_set    = (uint16_t)(critical_set & (uint16_t)~known_critical);
    if (unknown_set != 0) {
        return CONDUIT_ERR_UNKNOWN_CRITICAL;
    }

    return CONDUIT_OK;
}

const char *conduit_packet_type_name(uint8_t type) {
    switch (type) {
        case CONDUIT_PKT_HANDSHAKE_INIT: return "HANDSHAKE_INIT";
        case CONDUIT_PKT_HANDSHAKE_RESP: return "HANDSHAKE_RESP";
        case CONDUIT_PKT_HANDSHAKE_CONFIRM: return "HANDSHAKE_CONFIRM";
        case CONDUIT_PKT_DATA:           return "DATA";
        case CONDUIT_PKT_HEARTBEAT:      return "HEARTBEAT";
        case CONDUIT_PKT_HEARTBEAT_ACK:  return "HEARTBEAT_ACK";
        case CONDUIT_PKT_CLOSE:          return "CLOSE";
        default:                         return "UNKNOWN";
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
static void put_u32(uint8_t *p, uint32_t v) {
    uint32_t be = htonl(v);
    memcpy(p, &be, 4);
}
static uint32_t get_u32(const uint8_t *p) {
    uint32_t be;
    memcpy(&be, p, 4);
    return ntohl(be);
}

size_t conduit_build_init(uint32_t initiator_cid, uint8_t *buf, size_t cap) {
    if (cap < CONDUIT_INIT_SIZE) return 0;
    /* INIT is addressed to a not-yet-known responder: header CID is unspecified. */
    conduit_header h = { CONDUIT_CID_UNSPECIFIED, CONDUIT_PKT_HANDSHAKE_INIT, 0 };
    conduit_header_encode(&h, buf);
    buf[CONDUIT_HEADER_SIZE + 0] = CONDUIT_PROTOCOL_VERSION;
    put_u32(buf + CONDUIT_HEADER_SIZE + 1, initiator_cid);
    return CONDUIT_INIT_SIZE;
}

size_t conduit_build_resp(uint32_t initiator_cid, uint32_t responder_cid,
                          uint32_t token, uint8_t *buf, size_t cap) {
    if (cap < CONDUIT_RESP_SIZE) return 0;
    /* RESP is addressed to the initiator, by the ID it chose. */
    conduit_header h = { initiator_cid, CONDUIT_PKT_HANDSHAKE_RESP, 0 };
    conduit_header_encode(&h, buf);
    buf[CONDUIT_HEADER_SIZE + 0] = CONDUIT_PROTOCOL_VERSION;
    put_u32(buf + CONDUIT_HEADER_SIZE + 1, responder_cid);
    put_u32(buf + CONDUIT_HEADER_SIZE + 5, token);
    return CONDUIT_RESP_SIZE;
}

size_t conduit_build_confirm(uint32_t responder_cid, uint32_t token,
                             uint8_t *buf, size_t cap) {
    if (cap < CONDUIT_CONFIRM_SIZE) return 0;
    /* CONFIRM is addressed to the responder, by the ID it chose. */
    conduit_header h = { responder_cid, CONDUIT_PKT_HANDSHAKE_CONFIRM, 0 };
    conduit_header_encode(&h, buf);
    put_u32(buf + CONDUIT_HEADER_SIZE + 0, token);
    return CONDUIT_CONFIRM_SIZE;
}

conduit_result conduit_parse_init(const uint8_t *buf, size_t len,
                                  conduit_handshake_init *out) {
    if (len < CONDUIT_INIT_SIZE) return CONDUIT_ERR_TOO_SHORT;
    out->version       = buf[CONDUIT_HEADER_SIZE + 0];
    out->initiator_cid = get_u32(buf + CONDUIT_HEADER_SIZE + 1);
    return CONDUIT_OK;
}

conduit_result conduit_parse_resp(const uint8_t *buf, size_t len,
                                  conduit_handshake_resp *out) {
    if (len < CONDUIT_RESP_SIZE) return CONDUIT_ERR_TOO_SHORT;
    out->version       = buf[CONDUIT_HEADER_SIZE + 0];
    out->responder_cid = get_u32(buf + CONDUIT_HEADER_SIZE + 1);
    out->token         = get_u32(buf + CONDUIT_HEADER_SIZE + 5);
    return CONDUIT_OK;
}

conduit_result conduit_parse_confirm(const uint8_t *buf, size_t len,
                                     conduit_handshake_confirm *out) {
    if (len < CONDUIT_CONFIRM_SIZE) return CONDUIT_ERR_TOO_SHORT;
    out->token = get_u32(buf + CONDUIT_HEADER_SIZE + 0);
    return CONDUIT_OK;
}

/* ============================================================================
 * Heartbeat builders and parser
 * ========================================================================== */

/* HEARTBEAT and HEARTBEAT_ACK differ only by packet type, so they share one
 * internal builder. */
static size_t build_heartbeat_typed(uint8_t type, uint32_t dest_cid,
                                     uint32_t sequence, uint8_t *buf, size_t cap) {
    if (cap < CONDUIT_HEARTBEAT_SIZE) return 0;
    conduit_header h = { dest_cid, type, 0 };
    conduit_header_encode(&h, buf);
    put_u32(buf + CONDUIT_HEADER_SIZE + 0, sequence);
    return CONDUIT_HEARTBEAT_SIZE;
}

size_t conduit_build_heartbeat(uint32_t dest_cid, uint32_t sequence,
                               uint8_t *buf, size_t cap) {
    return build_heartbeat_typed(CONDUIT_PKT_HEARTBEAT, dest_cid, sequence, buf, cap);
}

size_t conduit_build_heartbeat_ack(uint32_t dest_cid, uint32_t sequence,
                                   uint8_t *buf, size_t cap) {
    return build_heartbeat_typed(CONDUIT_PKT_HEARTBEAT_ACK, dest_cid, sequence, buf, cap);
}

conduit_result conduit_parse_heartbeat(const uint8_t *buf, size_t len,
                                       conduit_heartbeat *out) {
    if (len < CONDUIT_HEARTBEAT_SIZE) return CONDUIT_ERR_TOO_SHORT;
    out->sequence = get_u32(buf + CONDUIT_HEADER_SIZE + 0);
    return CONDUIT_OK;
}