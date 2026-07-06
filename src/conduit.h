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
    CONDUIT_PKT_DATA_ACK = 0x11,          /* acknowledge reliable DATA (cumulative)*/
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

/* ============================================================================
 * Handshake driver with retransmission
 *
 * The handshake (Section 3.1) runs over connectionless UDP and cannot lean on
 * the (not-yet-established) reliability layer, so it must be robust to loss on
 * its own. This driver adds that robustness on top of the stateless builders and
 * parsers above. Like conduit_conn, it is time-injected: the caller supplies a
 * monotonic millisecond clock via _tick(), the driver never reads the clock
 * itself, and the whole thing is unit-testable with a simulated clock.
 *
 * Only ONE retransmission timer exists in the whole handshake, on the INITIATOR,
 * and only for INIT:
 *
 *   - The initiator sends INIT and waits for RESP. If RESP does not arrive
 *     before the current backoff elapses, it re-sends INIT (exponential backoff,
 *     capped, up to a maximum number of attempts, after which the handshake
 *     FAILS). On RESP it sends CONFIRM once and is ESTABLISHED.
 *
 *   - Re-sending INIT also recovers a lost RESP: a responder that sees a repeat
 *     INIT simply issues a fresh RESP. The responder therefore keeps NO timer.
 *
 *   - A lost CONFIRM is NOT retransmitted. The initiator considers itself
 *     ESTABLISHED once CONFIRM is sent and moves on to heartbeats. If that
 *     CONFIRM was lost, the responder never reaches ESTABLISHED, ignores the
 *     initiator's later traffic, and the initiator's own keep-alive timeout
 *     (Section 3.2) eventually declares the half-open connection dead so it can
 *     restart. This is "local truth" (Section 1.4): the liveness mechanism we
 *     already have repairs the half-open state -- no extra machinery here.
 *
 * The responder is deliberately stateless with respect to timers: it reacts to
 * INIT by emitting RESP and validates the echoed token in CONFIRM. It uses this
 * driver only to track the logical phase (LISTEN -> ESTABLISHED), not to
 * schedule retransmissions.
 * ========================================================================== */

/* Which side of the handshake this driver plays. */
typedef enum
{
    CONDUIT_ROLE_INITIATOR = 0,
    CONDUIT_ROLE_RESPONDER = 1
} conduit_role;

/* Handshake phase. FAILED is terminal (initiator gave up after too many INITs). */
typedef enum
{
    CONDUIT_HS_INIT_SENT = 0,  /* initiator: INIT sent, awaiting RESP        */
    CONDUIT_HS_LISTEN = 1,      /* responder: awaiting INIT                   */
    CONDUIT_HS_RESP_SENT = 2,   /* responder: RESP sent, awaiting CONFIRM     */
    CONDUIT_HS_ESTABLISHED = 3, /* handshake complete                         */
    CONDUIT_HS_FAILED = 4       /* initiator: too many INIT attempts, gave up */
} conduit_hs_state;

typedef struct
{
    conduit_role role;
    conduit_hs_state state;

    uint32_t my_cid;   /* the CID this endpoint chose for itself       */
    uint32_t peer_cid; /* the peer's CID (learned during the exchange) */
    uint32_t token;    /* address-validation token for this handshake  */
    int has_token;     /* whether `token` is populated yet             */

    /* --- INIT retransmission (initiator only) --- */
    uint32_t attempts;      /* INITs sent so far                       */
    uint32_t max_attempts;  /* give up (FAILED) after this many        */
    uint32_t backoff_ms;    /* current wait before the next INIT       */
    uint32_t backoff_cap_ms;/* backoff never grows past this           */
    uint64_t last_init_ms;  /* when the most recent INIT was sent      */
} conduit_handshake_state;

/* Initialize as the INITIATOR. `my_cid` is the CID this endpoint claims (MUST
 * NOT be 0). The retransmission policy is injected: `initial_backoff_ms` is the
 * first wait before re-sending INIT, doubling each attempt up to `backoff_cap_ms`,
 * and the handshake FAILS after `max_attempts` INITs go unanswered. */
void conduit_handshake_init_initiator(conduit_handshake_state *hs, uint32_t my_cid,
                                      uint32_t initial_backoff_ms,
                                      uint32_t backoff_cap_ms, uint32_t max_attempts);

/* Initialize as the RESPONDER. `my_cid` is the CID this endpoint will assign to
 * itself in RESP (MUST NOT be 0). The responder keeps no retransmission timer. */
void conduit_handshake_init_responder(conduit_handshake_state *hs, uint32_t my_cid);

/* Advance the initiator's clock to `now_ms`. Emits an INIT into `out` (capacity
 * `cap`) and returns its length when one is due: immediately on the first tick,
 * then again whenever the backoff elapses with no RESP. Returns 0 if nothing is
 * due this tick, if the handshake is no longer INIT_SENT, or if the buffer is
 * too small. May transition to CONDUIT_HS_FAILED once max_attempts is reached.
 * Has no effect for a responder (returns 0). */
size_t conduit_handshake_tick(conduit_handshake_state *hs, uint64_t now_ms,
                              uint8_t *out, size_t cap);

/* RESPONDER: handle a received INIT (already header-validated as HANDSHAKE_INIT).
 * Records the initiator's CID and the caller-supplied `token`, emits a RESP into
 * `out`, and moves to RESP_SENT. `token` is generated by the caller (this module
 * does not depend on any RNG). Returns the RESP length, or 0 on parse failure /
 * undersized buffer. Safe to call again on a repeat INIT: it re-issues RESP. */
size_t conduit_handshake_on_init(conduit_handshake_state *hs,
                                 const uint8_t *buf, size_t len, uint32_t token,
                                 uint8_t *out, size_t cap);

/* INITIATOR: handle a received RESP (already header-validated as HANDSHAKE_RESP).
 * Records the responder's CID and token, emits a CONFIRM into `out`, and moves to
 * ESTABLISHED. Returns the CONFIRM length, or 0 on parse failure / undersized
 * buffer. A duplicate RESP after ESTABLISHED re-emits CONFIRM (harmless). */
size_t conduit_handshake_on_resp(conduit_handshake_state *hs,
                                 const uint8_t *buf, size_t len,
                                 uint8_t *out, size_t cap);

/* RESPONDER: handle a received CONFIRM (already header-validated as
 * HANDSHAKE_CONFIRM). Verifies the echoed token matches the one issued in RESP;
 * on match moves to ESTABLISHED and returns 1. Returns 0 on parse failure or
 * token mismatch (the caller SHOULD drop the packet and stay in RESP_SENT). */
int conduit_handshake_on_confirm(conduit_handshake_state *hs,
                                 const uint8_t *buf, size_t len);

/* Current handshake phase. */
conduit_hs_state conduit_handshake_status(const conduit_handshake_state *hs);

/* Once ESTABLISHED, the peer's chosen CID (the destination for packets we send).
 * Returns 0 (CONDUIT_CID_UNSPECIFIED) before the peer CID is known. */
uint32_t conduit_handshake_peer_cid(const conduit_handshake_state *hs);

/* ============================================================================
 * Reliability: DATA / DATA_ACK wire format (Section 4)
 *
 * A reliable DATA packet is the fixed header, a 4-byte Sequence Number, then the
 * application payload. A DATA_ACK is the fixed header and a 4-byte cumulative
 * Acknowledgement Number. Sequence 0 is reserved (means "none"); the first DATA
 * uses sequence 1. See conduit.h Section 4 of the spec for the full model.
 * ========================================================================== */

/* Overhead a reliable DATA packet adds before the payload (header + sequence). */
#define CONDUIT_DATA_HEADER_SIZE (CONDUIT_HEADER_SIZE + 4) /* + sequence(4) */
/* A DATA_ACK is the fixed header plus a 4-byte cumulative ack number. */
#define CONDUIT_DATA_ACK_SIZE (CONDUIT_HEADER_SIZE + 4)    /* + ack(4) */

/* Sequence 0 is reserved to mean "no sequence"; real DATA starts at 1. */
#define CONDUIT_SEQ_NONE 0u

/* Parsed views. conduit_data.payload points into the caller's buffer (no copy);
 * it is valid only as long as that buffer is. */
typedef struct
{
    uint32_t sequence;
    const uint8_t *payload;
    size_t payload_len;
} conduit_data;
typedef struct
{
    uint32_t ack; /* cumulative: highest in-sequence sequence received */
} conduit_data_ack;

/* Build a reliable DATA packet addressed to `dest_cid`: header + `sequence` +
 * the `payload_len` bytes at `payload` (payload MAY be empty). Returns the total
 * bytes written, or 0 if `cap` is too small. */
size_t conduit_build_data(uint32_t dest_cid, uint32_t sequence,
                          const uint8_t *payload, size_t payload_len,
                          uint8_t *buf, size_t cap);

/* Build a DATA_ACK addressed to `dest_cid` carrying cumulative `ack`. Returns
 * bytes written, or 0 if `cap` is too small. */
size_t conduit_build_data_ack(uint32_t dest_cid, uint32_t ack,
                              uint8_t *buf, size_t cap);

/* Parse a DATA body (header already validated by conduit_header_decode). Fills
 * `out` with the sequence and a pointer to the payload inside `buf`. */
conduit_result conduit_parse_data(const uint8_t *buf, size_t len,
                                  conduit_data *out);

/* Parse a DATA_ACK body (header already validated). */
conduit_result conduit_parse_data_ack(const uint8_t *buf, size_t len,
                                      conduit_data_ack *out);

/* ============================================================================
 * Reliability: receiver (Section 4.2, 4.4)
 *
 * Tracks which reliable DATA sequences have arrived so it can (a) tell the
 * sender the cumulative acknowledgement number and (b) discard duplicates. It
 * keeps a cumulative point -- every sequence at or below it has been received --
 * plus a fixed bitmap of sequences received just above it. As the cumulative
 * point advances, the window slides forward. This revision does NOT reorder: the
 * caller delivers each new payload to the application immediately.
 * ========================================================================== */

/* Width of the duplicate-detection window above the cumulative point. */
#define CONDUIT_RECV_WINDOW 64

typedef enum
{
    CONDUIT_RECV_NEW = 0,      /* first time we've seen this sequence     */
    CONDUIT_RECV_DUPLICATE = 1,/* already received (or at/below cumulative)*/
    CONDUIT_RECV_INVALID = 2   /* sequence 0, or too far ahead of window  */
} conduit_recv_result;

typedef struct
{
    uint32_t cumulative;             /* all sequences <= this were received */
    uint64_t bitmap;                 /* bit i set => (cumulative + 1 + i) seen */
} conduit_rx;

/* Initialize a receiver with nothing yet received (cumulative = 0). */
void conduit_rx_init(conduit_rx *rx);

/* Record reception of `sequence`. Returns:
 *   CONDUIT_RECV_NEW       -> caller SHOULD deliver this payload to the app
 *   CONDUIT_RECV_DUPLICATE -> caller MUST drop the payload (but SHOULD still ack)
 *   CONDUIT_RECV_INVALID   -> sequence 0, or so far ahead it falls outside the
 *                             window; caller MUST drop it
 * In all non-INVALID cases the cumulative acknowledgement is updated. */
conduit_recv_result conduit_rx_on_data(conduit_rx *rx, uint32_t sequence);

/* The cumulative acknowledgement number to put in a DATA_ACK. */
uint32_t conduit_rx_ack(const conduit_rx *rx);

/* ============================================================================
 * Reliability: sender (Section 4.3, 4.5)
 *
 * Sends reliable DATA with pipelining up to a fixed window, retransmits packets
 * whose cumulative ACK has not arrived within an adaptively-computed RTO, and
 * measures RTT from the data path itself to drive that RTO. Time is injected via
 * _tick()/_on_ack(); the sender never reads the clock, so it is unit-testable
 * with a simulated clock, like conduit_conn and conduit_handshake_state.
 *
 * RTO: a smoothed RTT and RTT-variation estimate (Jacobson/Karels) updated from
 * each RTT sample, with RTO = srtt + 4*rttvar clamped to a minimum, and an
 * initial RTO before the first sample. Per Karn's algorithm, no RTT sample is
 * taken from a packet that was retransmitted; retransmissions still back off
 * (doubling RTO, capped).
 * ========================================================================== */

/* Send window and per-packet payload cap. The window MUST NOT exceed the
 * receiver's CONDUIT_RECV_WINDOW so an in-window packet is always trackable. */
#define CONDUIT_SEND_WINDOW 32
#define CONDUIT_MAX_PAYLOAD 1200 /* bytes of app data per reliable DATA packet */

/* One outstanding (unacknowledged) reliable DATA packet. */
typedef struct
{
    int in_use;
    uint32_t sequence;
    uint8_t payload[CONDUIT_MAX_PAYLOAD];
    size_t payload_len;
    uint64_t last_send_ms;   /* when it was most recently (re)sent          */
    uint64_t rexmit_at_ms;   /* when to retransmit if still unacked         */
    uint32_t transmits;      /* how many times sent (>1 => no RTT sample)   */
    uint32_t rto_ms;         /* per-packet RTO in force (grows on backoff)  */
} conduit_tx_slot;

typedef struct
{
    uint32_t peer_cid;    /* destination CID for packets we send            */
    uint32_t next_seq;    /* sequence for the next new DATA (starts at 1)   */
    uint32_t base_ack;    /* highest cumulative ACK received so far         */

    /* RTO estimator (all in ms; srtt/rttvar are fixed-point-free, plain ms). */
    int have_srtt;        /* whether a first sample has been taken          */
    uint32_t srtt_ms;     /* smoothed RTT                                   */
    uint32_t rttvar_ms;   /* RTT variation                                  */
    uint32_t rto_base_ms; /* current base RTO from the estimator            */
    uint32_t rto_min_ms;  /* lower clamp on RTO                             */
    uint32_t rto_max_ms;  /* cap on a single packet's backed-off RTO        */

    conduit_tx_slot slots[CONDUIT_SEND_WINDOW];
    uint32_t outstanding; /* number of slots in use                         */
} conduit_tx;

/* Initialize a sender. `peer_cid` is the destination CID. `initial_rto_ms` is
 * the RTO used before any RTT sample; `rto_min_ms` clamps the estimate from
 * below; `rto_max_ms` caps a single packet's backed-off RTO. */
void conduit_tx_init(conduit_tx *tx, uint32_t peer_cid,
                     uint32_t initial_rto_ms, uint32_t rto_min_ms,
                     uint32_t rto_max_ms);

/* True if a new reliable DATA may be queued (window not full). */
int conduit_tx_can_send(const conduit_tx *tx);

/* Queue and build a new reliable DATA carrying `payload` (`payload_len` bytes,
 * <= CONDUIT_MAX_PAYLOAD). Writes the packet into `out` and returns its length,
 * assigning the next sequence and recording it for possible retransmission.
 * Returns 0 if the window is full, the payload is too large, or `cap` is too
 * small. `now_ms` is the send time (starts the RTO clock for this packet). */
size_t conduit_tx_send(conduit_tx *tx, const uint8_t *payload, size_t payload_len,
                       uint64_t now_ms, uint8_t *out, size_t cap);

/* Advance time to `now_ms`. If any outstanding packet is due for retransmission,
 * write it into `out`, back off its RTO, and return its length; otherwise return
 * 0. Call repeatedly until it returns 0 to flush all due retransmissions. */
size_t conduit_tx_tick(conduit_tx *tx, uint64_t now_ms, uint8_t *out, size_t cap);

/* Record a received cumulative ACK at `now_ms`. Releases every outstanding
 * packet with sequence <= `ack`, and updates the RTO estimator from any of them
 * that were sent exactly once (Karn's algorithm). */
void conduit_tx_on_ack(conduit_tx *tx, uint32_t ack, uint64_t now_ms);

/* Number of unacknowledged packets currently outstanding. */
uint32_t conduit_tx_outstanding(const conduit_tx *tx);

/* Current RTO the estimator would use for a first transmission (for tests /
 * observability). Before any sample, this is the initial RTO. */
uint32_t conduit_tx_rto_ms(const conduit_tx *tx);

#endif /* CONDUIT_H */
