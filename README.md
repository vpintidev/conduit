[![CI](https://github.com/vpintidev/conduit/actions/workflows/ci.yml/badge.svg)](https://github.com/vpintidev/conduit/actions/workflows/ci.yml)

# Conduit

A modular, layered communication protocol over UDP.

Conduit provides logical connections, per-channel delivery guarantees, and
round-trip latency measurement on top of UDP, letting an application pay — in
wire overhead and processing — only for the guarantees it actually uses. It is
built for distributed systems on controlled networks (private clusters, backend
fabrics, game servers, telemetry pipelines), not as a replacement for TCP, QUIC,
or HTTP.

> **Status:** Early work in progress, developed as a learning project. The wire
> format and reference implementation are built and documented incrementally.
> See the roadmap below for what exists today.

## Why

Between raw UDP and full stacks such as TCP and QUIC there is a gap. TCP forces
total ordering and full reliability even when neither is wanted, adding
head-of-line blocking that hurts latency. QUIC is powerful but large and coupled
to TLS and HTTP/3. Raw UDP offers nothing — no connections, no reliability, no
congestion control. Conduit fills that gap for the case where one party controls
both ends and wants to choose, per channel and per message, which guarantees to
pay for.

## Roadmap

Conduit is built in three concentric circles, each complete and usable on its
own:

- **Circle 1 — Core (in progress).** Logical connections over UDP, a fixed
  packet header, handshake, heartbeat / keep-alive, and round-trip-time
  measurement.
- **Circle 2 — Composable guarantees.** Acknowledgements and retransmission,
  ordering, multiple channels with per-channel guarantees, fragmentation and
  reassembly.
- **Circle 3 — Advanced extensions.** Congestion control, flow control,
  optional compression, optional encryption, and an RPC layer.

What works today: the fixed packet header (encode / decode with validation).

## Project layout

```
conduit/
├── docs/
│   └── conduit-spec.md   # the wire-format specification (RFC-style)
├── src/
│   ├── conduit.h         # public types and prototypes
│   └── conduit.c         # implementation
├── tests/
│   └── test_conduit.c    # unit tests / round-trip checks
└── examples/
    └── udp_hello.c       # a minimal UDP send/receive spike
```

## Building

Requires a C11 compiler and a POSIX environment (developed on Linux / Ubuntu).

```sh
make           # build everything into build/
make test      # build and run the tests
make example   # build the udp_hello example
make clean     # remove build artifacts
```

## Documentation

The protocol is specified in [`docs/conduit-spec.md`](docs/conduit-spec.md),
written in the style of an IETF Internet-Draft and updated alongside the code.

## Non-goals

Conduit does not aim to replace TCP, QUIC, or HTTP, run inside web browsers,
interoperate with other protocols, perform NAT traversal, or provide
standards-grade security. See the specification for detail.

## License

Released under the MIT License. See [`LICENSE`](LICENSE).
