#ifndef CONDUIT_H
#define CONDUIT_H

#include <stdint.h>
#include <stddef.h>

/* ============================================================================
 * Conduit fixed packet header
 *
 * Every Conduit packet begins with a fixed 7-octet header:
 *     connection ID (4) + type (1) + flags (2) = 7
 * Optional sections (reliability, messaging) follow it in later circles; they
 * are not part of this header.
 * ========================================================================== */

#define CONDUIT_HEADER_SIZE 7

/* ---- Packet types (the 'type' field) -------------------------------------
 * The detailed exchange semantics of each type are defined in later sections
 * of the specification; here we only fix their on-the-wire values so they are
 * stable from the start. */
typedef enum {
    CONDUIT_PKT_HANDSHAKE_INIT    = 0x01, /* initiator -> responder: announce    */
    CONDUIT_PKT_HANDSHAKE_RESP    = 0x02, /* responder -> initiator: CID + token  */
    CONDUIT_PKT_HANDSHAKE_CONFIRM = 0x03, /* initiator -> responder: echo token   */
    CONDUIT_PKT_DATA              = 0x10, /* application payload                  */
    CONDUIT_PKT_HEARTBEAT         = 0x20, /* liveness probe (also drives RTT)     */
    CONDUIT_PKT_HEARTBEAT_ACK     = 0x21, /* reply to a heartbeat                 */
    CONDUIT_PKT_CLOSE             = 0x30  /* best-effort connection close         */
} conduit_packet_type;

/* ---- Flags (the 16-bit 'flags' field) ------------------------------------
 * The field is split into two classes *by position*. This fixes, once and for
 * all, how a receiver MUST treat a flag bit it does not understand:
 *   - bits 8..15 (high byte): CRITICAL  -> unknown bit set => REJECT the packet
 *   - bits 0..7  (low byte):  IGNORABLE -> unknown bit set => IGNORE that bit
 *
 * No flag bits are defined in circle 1 (the field is always 0). The masks below
 * let the decoder enforce the rule already; named bits will be added later
 * without ever moving these class boundaries. */
#define CONDUIT_FLAG_CRITICAL_MASK  0xFF00u
#define CONDUIT_FLAG_IGNORABLE_MASK 0x00FFu

/* ---- In-memory representation of the fixed header ------------------------
 * IMPORTANT: this struct is the *in-memory* view, NOT the wire layout. Never
 * send a struct over the network directly: padding and byte order differ
 * between machines. Use conduit_header_encode() / conduit_header_decode(). */
typedef struct {
    uint32_t connection_id; /* destination's connection ID (the demux key) */
    uint8_t  type;          /* one of conduit_packet_type                  */
    uint16_t flags;         /* see CONDUIT_FLAG_* above                     */
} conduit_header;

/* ---- Result codes for decoding ------------------------------------------- */
typedef enum {
    CONDUIT_OK = 0,
    CONDUIT_ERR_TOO_SHORT,        /* buffer smaller than the fixed header   */
    CONDUIT_ERR_UNKNOWN_CRITICAL  /* an unknown CRITICAL flag bit was set   */
} conduit_result;

/* ---- Encode / decode ----------------------------------------------------- */

/* Write `h` into `buf` in Conduit wire format (network byte order).
 * `buf` MUST have room for at least CONDUIT_HEADER_SIZE bytes.
 * Returns the number of bytes written (always CONDUIT_HEADER_SIZE). */
size_t conduit_header_encode(const conduit_header *h, uint8_t *buf);

/* Parse a fixed header from `buf` (length `len`) into `out`.
 * Validates the length and the critical flags before trusting any field.
 * Returns CONDUIT_OK on success, or an error code otherwise. */
conduit_result conduit_header_decode(const uint8_t *buf, size_t len,
                                     conduit_header *out);

/* Human-readable name of a packet type (for logging / debugging). */
const char *conduit_packet_type_name(uint8_t type);

/* ============================================================================
 * Connection establishment (handshake)
 *
 * Conduit uses a three-message handshake:
 *
 *   1. INIT     (initiator -> responder)  announce; carry version + chosen CID
 *   2. RESP     (responder -> initiator)  reply; carry version + chosen CID + token
 *   3. CONFIRM  (initiator -> responder)  echo the token back
 *
 * Each endpoint assigns the Connection ID by which it wishes to be addressed.
 * The token lets the responder confirm the initiator can actually receive at
 * its claimed address (return routability). In circle 1 the token is a plain,
 * non-cryptographic value: it proves round-trip only, NOT authenticity. A
 * keyed/stateless token (real anti-spoofing) is deferred to a later circle; the
 * field and the extra round-trip are in place so that hardening needs no wire
 * change.
 * ========================================================================== */

/* Protocol version carried in the handshake. A receiver that sees a version it
 * does not support rejects the connection (no negotiation in circle 1). */
#define CONDUIT_PROTOCOL_VERSION 1

/* Connection ID 0 means "unspecified" (used by INIT, before the responder's ID
 * is known). An endpoint MUST NOT assign 0 as its own ID. */
#define CONDUIT_CID_UNSPECIFIED 0u

/* Total packet sizes for each handshake message (fixed header + body). */
#define CONDUIT_INIT_SIZE    (CONDUIT_HEADER_SIZE + 5) /* +version(1)+cid(4)         */
#define CONDUIT_RESP_SIZE    (CONDUIT_HEADER_SIZE + 9) /* +version(1)+cid(4)+token(4)*/
#define CONDUIT_CONFIRM_SIZE (CONDUIT_HEADER_SIZE + 4) /* +token(4)                  */

/* Parsed handshake bodies. */
typedef struct { uint8_t  version; uint32_t initiator_cid; } conduit_handshake_init;
typedef struct { uint8_t  version; uint32_t responder_cid; uint32_t token; } conduit_handshake_resp;
typedef struct { uint32_t token; } conduit_handshake_confirm;

/* Builders: write a complete handshake packet into `buf` (capacity `cap`).
 * Return the number of bytes written, or 0 if `cap` is too small. */
size_t conduit_build_init(uint32_t initiator_cid, uint8_t *buf, size_t cap);
size_t conduit_build_resp(uint32_t initiator_cid, uint32_t responder_cid,
                          uint32_t token, uint8_t *buf, size_t cap);
size_t conduit_build_confirm(uint32_t responder_cid, uint32_t token,
                             uint8_t *buf, size_t cap);

/* Parsers: read a handshake body from a packet already validated by
 * conduit_header_decode(). They check the length and fill `out`. */
conduit_result conduit_parse_init(const uint8_t *buf, size_t len,
                                  conduit_handshake_init *out);
conduit_result conduit_parse_resp(const uint8_t *buf, size_t len,
                                  conduit_handshake_resp *out);
conduit_result conduit_parse_confirm(const uint8_t *buf, size_t len,
                                     conduit_handshake_confirm *out);

#endif /* CONDUIT_H */