# The Conduit Protocol

**A Modular, Layered Communication Protocol over UDP**

- Draft: `draft-conduit-00`
- Status: Work in Progress — independent specification
- Date: 2026-06-28

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
(`draft-conduit-00`) — purely as a familiar, professional format. The revision
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

Following the fixed header, a packet MAY carry additional sections — reliability
metadata (Section 4) and messaging metadata (Section 5) — whose presence is
indicated by Flags bits defined in later revisions. When no such bits are set,
the payload (if any) immediately follows the fixed header. These sections are
not yet specified.

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

### 3.2. Keep-Alive and RTT Measurement

_To be specified._

### 3.3. Termination

_To be specified._

## 4. Reliability Model

_To be specified:_ sequence numbers, acknowledgements, retransmission, duplicate
detection, and ordering.

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
  (HANDSHAKE_CONFIRM) added. Remaining lifecycle and wire-format sections are
  placeholders pending implementation.
