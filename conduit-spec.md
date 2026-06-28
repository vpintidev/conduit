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

*To be specified.* The next revision defines the fixed Conduit header —
Connection ID, packet type, and a flags field — together with the OPTIONAL,
flag-gated sections carrying reliability and messaging metadata.

## 3. Connection Lifecycle

*To be specified:* handshake (with address-validation token), keep-alive,
round-trip-time measurement, and termination.

## 4. Reliability Model

*To be specified:* sequence numbers, acknowledgements, retransmission, duplicate
detection, and ordering.

## 5. Channels and Messages

*To be specified:* per-channel guarantees, framing, fragmentation, and reassembly.

## 6. Versioning and Extensibility

*To be specified:* protocol-version negotiation, the critical/ignorable flag
partition, and the second-order extension mechanism.

## 7. Security Considerations

*To be specified.* Note: in the absence of the OPTIONAL cryptographic layer,
Conduit provides no protection against spoofing, replay, or tampering, and MUST
NOT be relied upon for confidentiality or authenticity. Even without
cryptography, an implementation MUST remain robust against malformed, truncated,
or duplicated packets: such input MUST be discarded cleanly and MUST NOT be
trusted.

## Appendix A. Revision History

- `draft-conduit-00` — Initial draft. Document structure; introduction, scope,
  non-goals, design principles, and terminology. Wire-format sections are
  placeholders pending implementation.
