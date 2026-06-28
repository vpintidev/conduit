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
    CONDUIT_PKT_HANDSHAKE_INIT = 0x01, /* initiator -> responder: open request  */
    CONDUIT_PKT_HANDSHAKE_RESP = 0x02, /* responder -> initiator: accept + token */
    CONDUIT_PKT_DATA           = 0x10, /* application payload                    */
    CONDUIT_PKT_HEARTBEAT      = 0x20, /* liveness probe (also drives RTT)       */
    CONDUIT_PKT_HEARTBEAT_ACK  = 0x21, /* reply to a heartbeat                   */
    CONDUIT_PKT_CLOSE          = 0x30  /* best-effort connection close           */
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

#endif /* CONDUIT_H */