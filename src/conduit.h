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
typedef enum
{
    CONDUIT_PKT_HANDSHAKE_INIT = 0x01,    /* initiator -> responder: announce    */
    CONDUIT_PKT_HANDSHAKE_RESP = 0x02,    /* responder -> initiator: CID + token  */
    CONDUIT_PKT_HANDSHAKE_CONFIRM = 0x03, /* initiator -> responder: echo token   */
    CONDUIT_PKT_DATA = 0x10,              /* application payload                  */
    CONDUIT_PKT_HEARTBEAT = 0x20,         /* liveness probe (also drives RTT)     */
    CONDUIT_PKT_HEARTBEAT_ACK = 0x21,     /* reply to a heartbeat                 */
    CONDUIT_PKT_CLOSE = 0x30              /* best-effort connection close         */
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
#define CONDUIT_FLAG_CRITICAL_MASK 0xFF00u
#define CONDUIT_FLAG_IGNORABLE_MASK 0x00FFu

/* ---- In-memory representation of the fixed header ------------------------
 * IMPORTANT: this struct is the *in-memory* view, NOT the wire layout. Never
 * send a struct over the network directly: padding and byte order differ
 * between machines. Use conduit_header_encode() / conduit_header_decode(). */
typedef struct
{
    uint32_t connection_id; /* destination's connection ID (the demux key) */
    uint8_t type;           /* one of conduit_packet_type                  */
    uint16_t flags;         /* see CONDUIT_FLAG_* above                     */
} conduit_header;

/* ---- Result codes for decoding ------------------------------------------- */
typedef enum
{
    CONDUIT_OK = 0,
    CONDUIT_ERR_TOO_SHORT,       /* buffer smaller than the fixed header   */
    CONDUIT_ERR_UNKNOWN_CRITICAL /* an unknown CRITICAL flag bit was set   */
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
#define CONDUIT_INIT_SIZE (CONDUIT_HEADER_SIZE + 5)    /* +version(1)+cid(4)         */
#define CONDUIT_RESP_SIZE (CONDUIT_HEADER_SIZE + 9)    /* +version(1)+cid(4)+token(4)*/
#define CONDUIT_CONFIRM_SIZE (CONDUIT_HEADER_SIZE + 4) /* +token(4)                  */

/* Parsed handshake bodies. */
typedef struct
{
    uint8_t version;
    uint32_t initiator_cid;
} conduit_handshake_init;
typedef struct
{
    uint8_t version;
    uint32_t responder_cid;
    uint32_t token;
} conduit_handshake_resp;
typedef struct
{
    uint32_t token;
} conduit_handshake_confirm;

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

/* ============================================================================
 * Keep-alive (heartbeat) and RTT
 *
 * Once a connection is established, an endpoint probes liveness and measures
 * round-trip time with HEARTBEAT / HEARTBEAT_ACK. Both carry a 4-byte Sequence.
 * The prober chooses a fresh Sequence and records the send time; the peer echoes
 * the same Sequence in a HEARTBEAT_ACK without keeping any state; when the ack
 * returns, the prober computes RTT = now - send_time on its own clock. The
 * Sequence is an opaque label only -- no clock value crosses the wire.
 * ========================================================================== */

/* HEARTBEAT and HEARTBEAT_ACK have identical bodies and sizes. */
#define CONDUIT_HEARTBEAT_SIZE (CONDUIT_HEADER_SIZE + 4) /* + sequence(4) */

/* Parsed heartbeat body (used for both HEARTBEAT and HEARTBEAT_ACK). */
typedef struct
{
    uint32_t sequence;
} conduit_heartbeat;

/* Builders: write a complete packet addressed to `dest_cid` into `buf`
 * (capacity `cap`). Return bytes written, or 0 if `cap` is too small. */
size_t conduit_build_heartbeat(uint32_t dest_cid, uint32_t sequence,
                               uint8_t *buf, size_t cap);
size_t conduit_build_heartbeat_ack(uint32_t dest_cid, uint32_t sequence,
                                   uint8_t *buf, size_t cap);

/* Parser: read the Sequence from a HEARTBEAT or HEARTBEAT_ACK whose fixed header
 * has already been validated by conduit_header_decode(). */
conduit_result conduit_parse_heartbeat(const uint8_t *buf, size_t len,
                                       conduit_heartbeat *out);

/* ============================================================================
 * Connection termination (CLOSE)
 *
 * CLOSE is a single, best-effort packet: the fixed header followed by a 1-octet
 * Reason code. It is NOT acknowledged and NOT retransmitted (Section 3.3). The
 * sender marks the connection closed and stops; the receiver does the same on
 * arrival. If the CLOSE is lost, the peer still tears the connection down via
 * the heartbeat liveness timeout (Section 3.2) -- this is "local truth"
 * (Section 1.4): each endpoint decides locally, and the two sides may release
 * the connection at slightly different times.
 *
 * The Reason is diagnostic only: a receiver MUST NOT change its teardown
 * behavior based on the value (a close is a close), but SHOULD surface it for
 * logging. An unrecognized Reason value MUST be treated as CONDUIT_CLOSE_NONE.
 * ========================================================================== */

/* CLOSE reason codes (the 1-octet body). Values are stable from the start;
 * the list may grow without a wire change. */
typedef enum
{
    CONDUIT_CLOSE_NONE = 0x00,        /* unspecified / graceful, no detail       */
    CONDUIT_CLOSE_APPLICATION = 0x01, /* the application asked to close          */
    CONDUIT_CLOSE_SHUTDOWN = 0x02,    /* endpoint is shutting down / going away  */
    CONDUIT_CLOSE_PROTOCOL_ERROR = 0x03 /* peer violated the protocol            */
} conduit_close_reason;

/* CLOSE is the fixed header plus a 1-octet Reason. */
#define CONDUIT_CLOSE_SIZE (CONDUIT_HEADER_SIZE + 1) /* + reason(1) */

/* Parsed CLOSE body. */
typedef struct
{
    uint8_t reason; /* one of conduit_close_reason (see note above) */
} conduit_close;

/* Builder: write a complete CLOSE addressed to `dest_cid` into `buf`
 * (capacity `cap`). Returns bytes written, or 0 if `cap` is too small. */
size_t conduit_build_close(uint32_t dest_cid, uint8_t reason,
                           uint8_t *buf, size_t cap);

/* Parser: read the Reason from a CLOSE whose fixed header has already been
 * validated by conduit_header_decode(). */
conduit_result conduit_parse_close(const uint8_t *buf, size_t len,
                                   conduit_close *out);

/* Human-readable name of a CLOSE reason (for logging / debugging). */
const char *conduit_close_reason_name(uint8_t reason);

/* ============================================================================
 * Connection liveness and RTT (established connections)
 *
 * Minimal, time-injected state for keeping an established connection alive and
 * measuring RTT. It is NOT yet the full connection object / state machine; it
 * manages only heartbeat scheduling, RTT, and liveness-failure detection.
 *
 * Time is supplied by the caller as a monotonic millisecond count and is never
 * read inside these functions, so the logic is fully deterministic and can be
 * unit-tested with a simulated clock.
 * ========================================================================== */

typedef enum
{
    CONDUIT_CONN_ALIVE = 0,
    CONDUIT_CONN_LOST = 1,  /* peer stopped answering: detected via timeout   */
    CONDUIT_CONN_CLOSED = 2 /* torn down deliberately (we sent/received CLOSE) */
} conduit_conn_state;

typedef struct
{
    uint32_t peer_cid;      /* destination CID for packets we send        */
    uint32_t interval_ms;   /* idle time before a heartbeat is sent       */
    uint32_t timeout_count; /* unacked probes that declare the peer lost  */

    conduit_conn_state state;
    uint32_t next_seq;     /* sequence for the next heartbeat            */
    uint64_t last_send_ms; /* when we last sent a heartbeat              */
    uint32_t inflight;     /* heartbeats sent since the last sign of life*/

    int has_pending;           /* is a probe outstanding (for RTT)?          */
    uint32_t pending_seq;      /* its sequence                               */
    uint64_t pending_since_ms; /* when it was sent                           */

    int has_rtt;
    uint32_t last_rtt_ms; /* most recent measured RTT                   */
} conduit_conn;

/* Initialize liveness state for an established connection. */
void conduit_conn_init(conduit_conn *c, uint32_t peer_cid,
                       uint32_t interval_ms, uint32_t timeout_count);

/* Advance time to `now_ms`. If idle for `interval_ms`, write a HEARTBEAT into
 * `out` (capacity `cap`) and return its length; otherwise return 0. May move the
 * connection to CONDUIT_CONN_LOST after too many unacked probes. */
size_t conduit_conn_tick(conduit_conn *c, uint64_t now_ms, uint8_t *out, size_t cap);

/* Record a HEARTBEAT_ACK for `acked_seq` at `now_ms`: clears the unacked count
 * and, if it matches the outstanding probe, updates the measured RTT. Ignored if
 * the connection is already lost. */
void conduit_conn_on_ack(conduit_conn *c, uint32_t acked_seq, uint64_t now_ms);

/* Record that some packet from the peer arrived (any packet is a sign of life). */
void conduit_conn_note_recv(conduit_conn *c);

/* Mark the connection as deliberately closed. After this the connection is
 * inert: conduit_conn_tick() emits nothing and never transitions to LOST, and
 * acks/receives are ignored. Call this both when we originate a CLOSE and when
 * we receive one from the peer. A connection already LOST stays LOST (a dead
 * peer cannot be gracefully closed); otherwise it becomes CLOSED. */
void conduit_conn_close(conduit_conn *c);

/* Current liveness state. */
conduit_conn_state conduit_conn_status(const conduit_conn *c);

/* If an RTT has been measured, store it in `*out_rtt_ms` and return 1; else 0. */
int conduit_conn_rtt_ms(const conduit_conn *c, uint32_t *out_rtt_ms);

#endif /* CONDUIT_H */
