# The Conduit Protocol

**A Modular, Layered Communication Protocol over UDP**

- Draft: `draft-conduit-01`
- Status: Work in Progress — independent specification
- Date: 2026-07-06

## Abstract

Conduit is a connection-oriented communication protocol layered on top of UDP.
It provides logical connections, per-channel delivery guarantees, and round-trip
latency measurement, while allowing applications to pay — in both wire overhead
and processing cost — only for the guarantees they actually use. Conduit targets
distributed systems operating over controlled networks (private clusters, backend
fabrics, game servers, telemetry pipelines). It is not a replacement for TCP,
QUIC, or HTTP, is not intended for the public Internet or web browsers, and does
not interoperate with any existing protocol.

This document specifies the Conduit wire format and the rules governing the
exchange of Conduit packets between endpoints. It is written incrementally,
alongside a reference implementation; sections describing not-yet-implemented
features are explicitly marked as such.

## Status of This Memo

This is not an IETF document and has not been reviewed or approved by any
standards body. RFC numbers are assigned by the RFC Editor; an independent
specification does not receive one. This document therefore adopts the
Internet-Draft naming convention — a draft name and a two-digit revision
(`draft-conduit-01`) — purely as a familiar, professional format. The revision
number is incremented as the specification evolves.

## Conventions and Terminology

### Requirement Keywords

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119.

### Definitions

- **Endpoint** — A participant in the protocol: a single instance of a Conduit
  implementation bound to a UDP socket, able to initiate or accept connections.
- **Initiator** — The endpoint that begins a connection by sending the first
  handshake packet.
- **Responder** — The endpoint that listens for and accepts incoming connections.
- **Connection** — A logical, stateful association between two endpoints,
  established over the stateless UDP substrate. A connection has a defined
  lifecycle: establishment, active exchange, and termination.
- **Connection ID** — An identifier that distinguishes a connection independently
  of the underlying IP address and UDP port. Each endpoint assigns the Connection
  ID by which it wishes to be addressed.
- **Packet** — The unit of data on the wire: a single UDP datagram carrying a
  Conduit header and an optional payload.
- **Channel** — A logical, independent stream within a connection, each with its
  own delivery guarantees (reliable/unreliable, ordered/unordered). Loss on one
  channel MUST NOT block delivery on another.
- **Message** — A complete application-level unit submitted to or delivered by
  Conduit, of arbitrary size. A message MAY be fragmented across multiple packets
  for transmission and reassembled at the receiver.
- **MTU** — Maximum Transmission Unit: the largest datagram that can traverse the
  path without IP-level fragmentation.

## 1. Introduction

### 1.1. Purpose

A gap exists between raw UDP and complete transport stacks such as TCP and QUIC.
TCP imposes total ordering and full reliability even where neither is required,
introducing head-of-line blocking that harms latency-sensitive workloads. QUIC
addresses many of TCP's limitations but is large, coupled to TLS and HTTP/3, and
oriented toward the public web. Raw UDP, by contrast, offers no connections, no
reliability, and no congestion control.

Conduit occupies this gap for the case where a single party controls both
endpoints and wishes to choose, per channel and per message, which guarantees to
pay for. Its central thesis is that reliability, ordering, compression, and
encryption are independent, composable options rather than a monolithic bundle,
and that an application pays — in wire overhead and processing cost — only for
what it uses.

### 1.2. Scope

Conduit is designed for distributed systems operating over controlled networks,
including microservice fabrics, high-performance backends, real-time dashboards,
game servers, telemetry pipelines, and clusters. It assumes that endpoints are
mutually reachable and that the operator controls both sides of every connection.

### 1.3. Non-Goals

Conduit explicitly does NOT aim to:

- replace TCP, QUIC, or HTTP;
- operate inside web browsers;
- interoperate with any existing protocol — Conduit endpoints communicate only
  with other Conduit endpoints;
- perform NAT traversal or hole punching (v1 assumes reachable endpoints);
- support multipath delivery;
- provide audited, standards-grade security. The OPTIONAL cryptographic layer is
  best-effort and is not a substitute for TLS.

### 1.4. Design Principles

- **Layered and independently usable.** Conduit is organized into layers
  (transport, reliability, messaging) that MAY be used in isolation. A lower
  layer MUST NOT depend on a higher one.
- **Fixed mechanisms, injected policies.** Retransmission, framing, and
  demultiplexing are fixed mechanisms; congestion control, serialization,
  compression, and encryption are replaceable policies.
- **Pay for what you use.** A disabled feature MUST NOT impose wire overhead or
  runtime cost.
- **Local truth.** Over a stateless substrate, connection state is maintained
  locally by each endpoint and synchronized through explicit exchanges; a timeout
  is the ultimate authority on liveness.

## 2. Packet Format

### 2.1. Wire Conventions

- All multi-octet integer fields are encoded in **network byte order**
  (big-endian).
- All fields defined in this revision are **fixed-width**. Variable-width
  encoding MAY be introduced in a later revision for specific fields.
- A receiver MUST verify that a received datagram is at least
  `CONDUIT_HEADER_SIZE` (7) octets long before interpreting any field. A
  datagram shorter than the fixed header MUST be discarded.

### 2.2. Fixed Header

Every Conduit packet begins with a fixed 7-octet header:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Connection ID                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |             Flags             |  Payload ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Connection ID (32 bits).** The Connection ID of the _destination_ endpoint:
the identifier the receiving endpoint assigned to itself during the handshake
(Section 3). On receipt, an endpoint uses this field to demultiplex the packet
to the correct connection. The Connection ID MUST be carried in cleartext even
when the OPTIONAL cryptographic layer is in use, because it is required to
select the decryption context before any payload can be decrypted.

**Type (8 bits).** Identifies the packet's purpose. Defined values:

| Value  | Name                | Direction             | Purpose                        |
| ------ | ------------------- | --------------------- | ------------------------------ |
| `0x01` | `HANDSHAKE_INIT`    | initiator → responder | Begin connection establishment |
| `0x02` | `HANDSHAKE_RESP`    | responder → initiator | Accept; carry CID and token    |
| `0x03` | `HANDSHAKE_CONFIRM` | initiator → responder | Echo token; finish handshake   |
| `0x10` | `DATA`              | either                | Application payload            |
| `0x11` | `DATA_ACK`          | either                | Acknowledge reliable DATA      |
| `0x20` | `HEARTBEAT`         | either                | Liveness probe; drives RTT     |
| `0x21` | `HEARTBEAT_ACK`     | either                | Reply to a heartbeat           |
| `0x30` | `CLOSE`             | either                | Best-effort connection close   |

A receiver that does not recognize the Type value MUST discard the packet. The
detailed exchange semantics of each type are specified in Sections 3 through 5.

**Flags (16 bits).** A bit field, with bits numbered 0 (least significant)
through 15 (most significant). The field is partitioned into two classes by
position, which determines how a receiver MUST treat an unrecognized flag bit:

- **Bits 8–15 — Critical class.** If a receiver encounters a bit set in this
  range that it does not recognize, it MUST discard the packet. A critical flag
  may change the interpretation of the packet, so a receiver that cannot
  interpret it MUST NOT proceed.
- **Bits 0–7 — Ignorable class.** A receiver MUST ignore any bit set in this
  range that it does not recognize, and MUST process the remainder of the packet
  normally. An ignorable flag is purely additive.

This revision defines no flag bits. A sender conforming to this revision MUST
set the Flags field to zero. (Subsequent revisions assign individual bits — for
example, to signal the presence of the optional sections in Section 2.3 — within
the class boundaries fixed above.)

### 2.3. Optional Sections

Following the fixed header, a packet MAY carry additional sections whose presence
is indicated by Flags bits defined in later revisions. When no such bits are set,
the body (if any) immediately follows the fixed header. The reliability metadata
of Section 4 (the `DATA` Sequence Number) is carried directly in the packet body
of the relevant types rather than as a flag-signalled optional section; the
flag-signalled optional-section mechanism is reserved for additive extensions
such as selective acknowledgement (Section 4.2) and the messaging metadata of
Section 5, which are specified where they are introduced.

## 3. Connection Lifecycle

### 3.1. Handshake

A connection is established with a three-message handshake. Because UDP is
connectionless and these packets cannot rely on the (not-yet-established)
reliability layer, the handshake is defined to be robust to loss on its own.
Loss handling (retransmission with timeout) is specified in a later revision.

```
 Initiator                                   Responder
     |                                            |
     |----------------- INIT -------------------->|   version + CID_I
     |                                            |
     |<---------------- RESP ---------------------|   version + CID_R + token
     |                                            |
     |---------------- CONFIRM ------------------>|   echo token
     |                                            |
 ESTABLISHED                                  ESTABLISHED
```

**Connection ID assignment.** Each endpoint assigns the Connection ID by which
it wishes to be addressed and communicates it during the handshake: the
initiator in INIT, the responder in RESP. Thereafter a packet carries the
_destination's_ Connection ID in its header. The value 0 is reserved to mean
"unspecified" and MUST NOT be assigned by an endpoint; it appears only in the
INIT header, where the responder's ID is not yet known.

**Address-validation token.** The token in RESP lets the responder confirm that
the initiator can receive datagrams at its claimed source address (return
routability): the initiator MUST echo the token in CONFIRM, and the responder
MUST reject a CONFIRM whose token does not match the one it issued. In this
revision the token is a non-cryptographic value and provides round-trip
confirmation only; it does NOT authenticate the peer or defend against an
attacker able to observe traffic. A keyed, stateless token providing
anti-spoofing is deferred to a later revision; the message flow and the token
field are specified now so that the hardening requires no wire change.

**Version.** INIT and RESP each carry the sender's protocol version. A receiver
that does not support the offered version MUST reject the connection. This
revision performs no version negotiation.

#### 3.1.1. Message bodies

Each handshake packet is the fixed header (Section 2.2) followed by the body
below. All integer fields are in network byte order.

INIT (type `0x01`), header Connection ID = 0 (unspecified):

| Field         | Octets | Description                           |
| ------------- | ------ | ------------------------------------- |
| Version       | 1      | Initiator's protocol version          |
| Initiator CID | 4      | Connection ID chosen by the initiator |

RESP (type `0x02`), header Connection ID = Initiator CID:

| Field         | Octets | Description                           |
| ------------- | ------ | ------------------------------------- |
| Version       | 1      | Responder's protocol version          |
| Responder CID | 4      | Connection ID chosen by the responder |
| Token         | 4      | Address-validation token              |

CONFIRM (type `0x03`), header Connection ID = Responder CID:

| Field | Octets | Description                      |
| ----- | ------ | -------------------------------- |
| Token | 4      | The token from RESP, echoed back |

#### 3.1.2. Loss handling

The handshake carries no reliability metadata of its own, so robustness to loss
is a property of the exchange rather than the wire format. The strategy below is
RECOMMENDED; the specific timing parameters are an implementation concern and do
not affect interoperability, since a peer cannot observe another endpoint's
timers — only the packets they cause.

A single retransmission timer suffices, on the initiator, and only for INIT:

- **Lost INIT.** The initiator retransmits INIT if no RESP arrives within a
  timeout. Retransmissions SHOULD use exponential backoff (a doubling delay up
  to a cap) to avoid adding load to an already-congested path, and the initiator
  SHOULD abandon the handshake after a bounded number of attempts.

- **Lost RESP.** The responder does NOT keep a retransmission timer. A lost RESP
  is recovered by the initiator's own INIT retransmission: a responder that
  receives a repeat INIT simply issues a fresh RESP. Because the responder holds
  no per-handshake timer, it is not forced to retain state for every INIT it has
  ever seen — relevant to its exposure to spoofed or flooding traffic.

- **Lost CONFIRM.** CONFIRM is NOT retransmitted. The initiator considers the
  connection established once it has sent CONFIRM. If that CONFIRM is lost, the
  responder never reaches the established state and ignores the initiator's
  subsequent traffic; the initiator's keep-alive mechanism (Section 3.2) then
  observes the unanswered connection and tears it down, after which it MAY
  restart the handshake. Repairing the half-open state is thus delegated to the
  liveness timeout ("local truth", Section 1.4) rather than to a dedicated
  timer, keeping the responder free of handshake-completion state.

A responder MUST treat handshake packets idempotently to the extent the above
requires: a repeat INIT re-issues RESP, and a duplicate CONFIRM whose token
matches is harmless.

### 3.2. Keep-Alive and RTT Measurement

Once a connection is established, each endpoint detects whether its peer is still
reachable and measures the connection's round-trip time using a heartbeat
exchange.

HEARTBEAT and HEARTBEAT_ACK packets each consist of the fixed header (Section
2.2) followed by a 4-octet body. All integer fields are in network byte order.

HEARTBEAT (type `0x20`), header Connection ID = destination CID:

| Field    | Octets | Description                               |
| -------- | ------ | ----------------------------------------- |
| Sequence | 4      | Monotonically increasing probe identifier |

HEARTBEAT_ACK (type `0x21`), header Connection ID = destination CID:

| Field    | Octets | Description                                   |
| -------- | ------ | --------------------------------------------- |
| Sequence | 4      | The Sequence value from the HEARTBEAT, echoed |

**Procedure.** An endpoint sending a HEARTBEAT chooses a Sequence value greater
than any it has previously used on the connection and records the local time of
transmission. On receiving a HEARTBEAT, an endpoint MUST reply with a
HEARTBEAT_ACK echoing the same Sequence value; it retains no state to do so. On
receiving a HEARTBEAT_ACK, the original sender matches the echoed Sequence to its
recorded transmission time and computes the round-trip time as
`now - transmission_time`.

**RTT is measured entirely on the sender's own clock.** The Sequence value is an
opaque label used only to match an acknowledgement to its probe; no timestamp or
clock value crosses the network, and the two endpoints' clocks need not be
synchronized.

**Idle-only.** Heartbeats are sent only when the connection is otherwise idle:
any packet sent on the connection resets the heartbeat timer, and a HEARTBEAT is
emitted only after the timer elapses with no other traffic. Application data and
acknowledgements therefore serve as implicit liveness signals.

**Liveness failure.** If repeated heartbeats elicit no acknowledgement within an
implementation-defined bound, the endpoint declares the connection lost. This is
a local decision (see "local truth", Section 1.4); the two endpoints may detect
loss at different times. The specific timing parameters (heartbeat interval,
failure threshold) and the mechanism that drives them are implementation concerns
and are not part of the wire format.

### 3.3. Termination

A connection is torn down with a single CLOSE packet. Termination is
best-effort: CLOSE is neither acknowledged nor retransmitted. An endpoint that
sends CLOSE considers the connection closed immediately; an endpoint that
receives CLOSE does the same. Because delivery is not guaranteed, a lost CLOSE
does not strand the peer: the peer still detects the vanished connection through
the keep-alive liveness timeout (Section 3.2). Termination is thus a matter of
"local truth" (Section 1.4) — each endpoint releases the connection on its own,
and the two sides MAY do so at different times.

CLOSE consists of the fixed header (Section 2.2) followed by a 1-octet Reason.

CLOSE (type `0x30`), header Connection ID = destination CID:

| Field  | Octets | Description                       |
| ------ | ------ | --------------------------------- |
| Reason | 1      | Diagnostic reason for the closure |

Defined Reason values:

| Value  | Name             | Meaning                                    |
| ------ | ---------------- | ------------------------------------------ |
| `0x00` | `NONE`           | Unspecified or graceful; no detail given   |
| `0x01` | `APPLICATION`    | The application requested the close        |
| `0x02` | `SHUTDOWN`       | The endpoint is shutting down / going away |
| `0x03` | `PROTOCOL_ERROR` | The peer violated the protocol             |

**Reason is diagnostic only.** The Reason exists for logging and observability.
A receiver MUST NOT vary its teardown behavior based on the value — a CLOSE
always terminates the connection. A receiver that does not recognize a Reason
value MUST treat it as `NONE` and MUST still tear the connection down. Reason
values MAY be added in later revisions without a wire change.

**No half-close.** This revision defines a single, symmetric teardown: CLOSE
ends the connection in both directions at once. There is no independent
shutdown of one direction, and there is no defined packet to send on a
connection after its CLOSE. Any packet received for a connection that has
already been closed locally MUST be discarded.

## 4. Reliability Model

This section defines OPTIONAL reliable delivery for `DATA` packets: a sender
retransmits until its data is acknowledged, and a receiver discards duplicates.
Reliability is a property of the sender/receiver state machines described here,
layered on the fixed header (Section 2.2); it adds one packet type (`DATA_ACK`)
and a Sequence Number to `DATA`.

This revision provides reliability **without ordering**. A receiver delivers each
`DATA` payload to the application as soon as it arrives, regardless of Sequence
Number order; it never buffers out-of-order packets to reorder them. Ordered
delivery is a separate, composable guarantee specified in Section 5. An
application that needs in-order data uses that guarantee; an application that
does not (for example, one exchanging independent records) avoids the
head-of-line blocking that ordering would impose.

### 4.1. Sequence Numbers

Each reliable `DATA` packet carries a 32-bit Sequence Number in its body,
immediately following the fixed header:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Connection ID                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |             Flags             |               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
|                       Sequence Number                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Payload ...                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

`DATA` (type `0x10`), header Connection ID = destination CID:

| Field           | Octets   | Description                               |
| --------------- | -------- | ----------------------------------------- |
| Sequence Number | 4        | Per-sender, per-connection sequence label |
| Payload         | variable | Application data (MAY be empty)           |

Sequence Numbers are assigned by the sender, one per reliable `DATA` packet, and
increase by one for each new packet (not for each retransmission — a retransmit
reuses the original number). The first reliable `DATA` on a connection uses
Sequence Number 1; the value 0 is reserved and MUST NOT be assigned to a `DATA`
packet. Sequence Numbers are per-direction: the two endpoints number their own
`DATA` independently.

Sequence Number wraparound (a connection sending more than 2³²−1 reliable
packets) is not addressed in this revision; an implementation MAY treat it as a
connection-fatal condition.

### 4.2. Acknowledgements

A receiver of reliable `DATA` reports progress with a `DATA_ACK` packet:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Connection ID                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |             Flags             |               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
|                    Acknowledgement Number                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

`DATA_ACK` (type `0x11`), header Connection ID = destination CID:

| Field                  | Octets | Description                                  |
| ---------------------- | ------ | -------------------------------------------- |
| Acknowledgement Number | 4      | Highest Sequence Number received with no gap |

The Acknowledgement Number is **cumulative**: it is the highest Sequence Number N
such that every reliable `DATA` packet from 1 through N has been received. It
acknowledges all of them at once. An Acknowledgement Number of 0 means no
in-sequence `DATA` has been received yet.

Because the acknowledgement is cumulative, a gap stalls it: if a receiver has
seen 1, 2, 3, 5, 6 but not 4, it can only acknowledge 3, even though 5 and 6
arrived. The sender therefore learns that 4 is missing (the acknowledgement does
not advance past 3) but is not told that 5 and 6 are safe, and MAY retransmit
them needlessly. This is the known cost of cumulative acknowledgement under loss.

> **Planned refinement (selective acknowledgement).** A later revision will add
> selective acknowledgement (SACK): the ability to report received ranges beyond
> the cumulative point (e.g. "cumulative 3, plus 5–6"), so the sender retransmits
> only the true gap. SACK is designed as an additive extension of the cumulative
> scheme here — carried in an optional section signalled by a Flags bit
> (Section 2.3) — and does not change the meaning of the Acknowledgement Number
> field defined above. The cumulative field remains the baseline a receiver
> always provides.

A receiver SHOULD send a `DATA_ACK` promptly on receiving `DATA`. It MAY
acknowledge less than once per packet (for instance, one `DATA_ACK` per batch of
received packets), since the cumulative number already summarizes all progress;
an implementation MUST NOT rely on a one-to-one correspondence between `DATA` and
`DATA_ACK`.

### 4.3. Retransmission and the Retransmission Timeout (RTO)

A reliable sender retains each unacknowledged `DATA` packet and the time it was
sent. If the Acknowledgement Number has not advanced to cover a packet within
the current RTO, the sender retransmits that packet (reusing its Sequence
Number). Repeated retransmissions of the same packet SHOULD back off (a doubling
RTO, up to a cap) to avoid adding load to a lossy or congested path, mirroring
the handshake's loss handling (Section 3.1.2).

The RTO is derived adaptively from measured round-trip time, following the
standard smoothed-estimate approach (Jacobson/Karels): the sender maintains a
smoothed RTT and an RTT variation estimate, updates both from each RTT sample,
and sets the RTO to the smoothed RTT plus a multiple of the variation, clamped to
a minimum. Before any sample is available, the sender uses a conservative initial
RTO.

**RTT samples come from the data path itself.** When a `DATA_ACK` advances the
Acknowledgement Number to cover a packet that was sent exactly once, the sender
has a fresh RTT sample: the elapsed time between sending that packet and
receiving the acknowledgement. This makes reliability self-contained — it
measures RTT from its own traffic and does not depend on the keep-alive heartbeat
(Section 3.2), which by design is silent while data flows.

**Karn's algorithm — do not sample retransmitted packets.** If a packet was
retransmitted, an arriving acknowledgement is ambiguous: it cannot be attributed
to the original transmission or a retransmission, so the elapsed time is not a
valid RTT sample. A sender MUST NOT take an RTT sample from a packet that has
been retransmitted. It takes samples only from packets acknowledged on their
first transmission. (The backoff above still applies to the retransmitted packet
regardless.)

### 4.4. Duplicate Detection

Retransmission can cause a receiver to see the same Sequence Number more than
once; reordering in the network can also deliver a packet whose number is below
the cumulative point. A receiver MUST detect and discard such duplicates,
delivering each Sequence Number's payload to the application at most once.

A receiver tracks received Sequence Numbers with a sliding window: the cumulative
Acknowledgement Number (all numbers at or below it have been received and
delivered) plus a fixed-width bitmap recording which numbers just above it have
been received. On receiving a reliable `DATA` packet with Sequence Number S:

- If S is at or below the cumulative point, or its bit is already set in the
  bitmap, it is a duplicate: the receiver discards the payload but SHOULD still
  send a `DATA_ACK` (the sender's copy of the acknowledgement may have been lost).
- Otherwise S is new: the receiver delivers the payload, records S (sets its bit,
  or advances the cumulative point), and lets the window slide forward as the
  cumulative point advances.

A `DATA` packet whose Sequence Number is so far beyond the cumulative point that
it falls outside the bitmap window MAY be discarded; the sender's window
(Section 4.5) is bounded to keep this from happening in normal operation.

### 4.5. Send Window

A reliable sender MAY have multiple unacknowledged `DATA` packets outstanding at
once (pipelining), up to a fixed send-window limit. When the number of
unacknowledged packets reaches the limit, the sender MUST wait for the
Acknowledgement Number to advance before sending new `DATA`; retransmissions of
already-sent packets are not constrained by the limit.

In this revision the send window is a fixed, configured value: it is a mechanism
for pipelining, not yet a congestion-control signal. Dynamic adjustment of the
window in response to loss and delay (congestion control) is deferred to a later
circle. The sender's window MUST NOT exceed the receiver's duplicate-detection
window (Section 4.4), so that a packet within the sender's window always falls
within the receiver's tracking range.

## 5. Channels and Messages

_To be specified:_ per-channel guarantees, framing, fragmentation, and reassembly.

## 6. Versioning and Extensibility

_To be specified:_ protocol-version negotiation, the critical/ignorable flag
partition, and the second-order extension mechanism.

## 7. Security Considerations

_To be specified._ Note: in the absence of the OPTIONAL cryptographic layer,
Conduit provides no protection against spoofing, replay, or tampering, and MUST
NOT be relied upon for confidentiality or authenticity. Even without
cryptography, an implementation MUST remain robust against malformed, truncated,
or duplicated packets: such input MUST be discarded cleanly and MUST NOT be
trusted.

## Appendix A. Revision History

- `draft-conduit-00` — Initial draft. Document structure; introduction, scope,
  non-goals, design principles, and terminology. Section 2 (Packet Format)
  defines the fixed header (Connection ID, Type, Flags), the wire conventions,
  and the critical/ignorable flag partition. Section 3.1 defines the
  three-message handshake (INIT / RESP / CONFIRM), connection-ID assignment, the
  address-validation token, and version handling; packet type `0x03`
  (HANDSHAKE_CONFIRM) added. Section 3.1.2 documents the RECOMMENDED handshake
  loss-handling strategy: a single INIT-retransmission timer on the initiator
  with exponential backoff, recovery of a lost RESP via repeat INIT, and reliance
  on the keep-alive timeout for a lost CONFIRM. Section 3.2 defines the HEARTBEAT
  / HEARTBEAT_ACK packet bodies (a 4-octet Sequence), the echo-based RTT
  correlation measured on the sender's own clock, the idle-only rule, and local
  liveness-failure detection. Section 3.3 defines connection termination: the
  best-effort CLOSE packet (type `0x30`) with a 1-octet diagnostic Reason,
  symmetric teardown with no half-close, and reliance on the keep-alive timeout
  when a CLOSE is lost. Remaining lifecycle and wire-format sections are
  placeholders pending implementation.
- `draft-conduit-01` — Section 4 (Reliability Model) defines OPTIONAL reliable,
  unordered delivery for `DATA`: a 4-octet Sequence Number in the `DATA` body
  (Section 4.1); a cumulative `DATA_ACK` packet, type `0x11` (Section 4.2), with
  selective acknowledgement noted as a planned additive refinement; adaptive
  retransmission with a Jacobson/Karels RTO sampled from the data path itself and
  Karn's algorithm for retransmitted packets (Section 4.3); sliding-window
  duplicate detection (Section 4.4); and a fixed pipelining send window, with
  dynamic congestion control deferred (Section 4.5). Packet type `0x11`
  (`DATA_ACK`) added to Section 2.2. Ordered delivery remains a separate
  guarantee pending in Section 5.
