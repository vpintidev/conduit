# Conduit

[![CI](https://github.com/vpintidev/conduit/actions/workflows/ci.yml/badge.svg)](https://github.com/vpintidev/conduit/actions/workflows/ci.yml)

A modular, layered communication protocol over UDP.

Conduit provides logical connections, per-channel delivery guarantees, and
round-trip latency measurement on top of UDP, letting an application pay — in
wire overhead and processing — only for the guarantees it actually uses. It is
built for distributed systems on controlled networks (private clusters, backend
fabrics, game servers, telemetry pipelines), not as a replacement for TCP, QUIC,
or HTTP.

> **Status:** Work in progress, developed as a learning project. The core of
> Circle 1 works today: two peers establish a logical connection over UDP, keep
> it alive, measure round-trip time, and detect when the peer goes away. The wire
> format and reference implementation are built and documented incrementally.

## Why

Between raw UDP and full stacks such as TCP and QUIC there is a gap. TCP forces
total ordering and full reliability even when neither is wanted, adding
head-of-line blocking that hurts latency. QUIC is powerful but large and coupled
to TLS and HTTP/3. Raw UDP offers nothing — no connections, no reliability, no
congestion control. Conduit fills that gap for the case where one party controls
both ends and wants to choose, per channel and per message, which guarantees to
pay for.

## Roadmap

Conduit is built in three concentric circles, each complete and usable on its own.

**Circle 1 — Core** (nearly complete)

- [x] Logical connections over UDP with connection IDs
- [x] Fixed packet header (encode / decode with validation)
- [x] Three-message handshake (INIT / RESP / CONFIRM) with address-validation token
- [x] Keep-alive heartbeats and round-trip-time (RTT) measurement
- [x] Dead-peer detection via unacknowledged probes
- [ ] Explicit connection close (CLOSE)
- [ ] Handshake retransmission on packet loss

**Circle 2 — Composable guarantees** (planned)

Acknowledgements and retransmission, ordering, multiple channels with
per-channel guarantees, fragmentation and reassembly.

**Circle 3 — Advanced extensions** (planned)

Congestion control, flow control, optional compression, optional encryption,
and an RPC layer.

## Project layout

```
conduit/
├── docs/
│   ├── conduit-spec.md      # the wire-format specification (RFC-style)
│   └── TESTING.md           # testing strategy and tooling
├── src/
│   ├── conduit.h            # public API: packet, handshake, liveness
│   └── conduit.c            # implementation
├── tests/
│   ├── test.h               # minimal, zero-dependency test helper
│   └── test_conduit.c       # unit tests
├── examples/
│   ├── udp_hello.c          # minimal UDP send/receive spike
│   ├── conduit_ping.c       # build a real header and send it over UDP
│   ├── conduit_handshake.c  # the three-message handshake between two peers
│   └── conduit_rtt.c        # keep-alive, RTT, and dead-peer detection
└── .github/workflows/
    └── ci.yml               # build & test on gcc and clang, plus sanitizers
```

## Building

Requires a C11 compiler and a POSIX environment (developed on Linux / Ubuntu).

```sh
make            # build everything into build/
make test       # build and run the unit tests
make clean      # remove build artifacts

# examples
make ping       # header-over-UDP demo
make handshake  # three-message handshake demo
make rtt        # keep-alive / RTT / timeout demo
make example    # the raw udp_hello spike
```

## Examples

Each example is a small standalone program under `examples/`.

- **udp_hello** — the simplest "hello over the network": one UDP socket sends
  bytes, another receives them. Not part of the library; a warm-up.
- **conduit_ping** — builds a real Conduit header, sends it in a UDP datagram,
  and parses it back on the other side.
- **conduit_handshake** — run a responder and an initiator and watch the
  INIT → RESP → CONFIRM exchange establish a connection.
- **conduit_rtt** — run two peers (`a` and `b`); they keep each other alive with
  heartbeats and measure RTT. Kill one and the other reports the connection lost.

To watch any of these on the wire (loopback):

```sh
sudo tcpdump -i lo -X udp port 9000
```

## Testing

Unit tests use a tiny, zero-dependency helper (`tests/test.h`) with coloured
`[OK]` / `[KO]` output on a terminal and plain output when piped or in CI:

```sh
make test
```

Because the connection logic takes the current time as a parameter instead of
reading the clock itself, time-dependent behaviour (heartbeat scheduling, RTT,
timeouts) is tested deterministically with a simulated clock — no sockets, no
waiting. Continuous integration builds and tests on both gcc and clang and runs
an AddressSanitizer + UndefinedBehaviorSanitizer job on every push. See
[`docs/TESTING.md`](docs/TESTING.md) for the full strategy.

## Documentation

The protocol is specified in [`docs/conduit-spec.md`](docs/conduit-spec.md),
written in the style of an IETF Internet-Draft and updated alongside the code.

## Non-goals

Conduit does not aim to replace TCP, QUIC, or HTTP, run inside web browsers,
interoperate with other protocols, perform NAT traversal, or provide
standards-grade security. See the specification for detail.

## License

Released under the MIT License. See [`LICENSE`](LICENSE).