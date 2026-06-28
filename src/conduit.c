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
        case CONDUIT_PKT_DATA:           return "DATA";
        case CONDUIT_PKT_HEARTBEAT:      return "HEARTBEAT";
        case CONDUIT_PKT_HEARTBEAT_ACK:  return "HEARTBEAT_ACK";
        case CONDUIT_PKT_CLOSE:          return "CLOSE";
        default:                         return "UNKNOWN";
    }
}