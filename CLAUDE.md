# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Conduit is a connection-oriented communication protocol layered on top of UDP, plus its reference implementation in C. The project is early: the specification ([docs/conduit-spec.md](docs/conduit-spec.md)) is `draft-conduit-00`. Specified and implemented so far: Section 2 (Packet Format) — the fixed 7-octet header (Connection ID, Type, Flags) with the critical/ignorable flag partition — and Section 3.1 (the three-message INIT/RESP/CONFIRM handshake, with connection-ID assignment and an address-validation token). Sections 3.2–3.3 (keep-alive, RTT, termination) and 4–5 (reliability, channels) are still placeholders.

The spec and the implementation evolve together. [docs/conduit-spec.md](docs/conduit-spec.md) is the source of truth — read it before writing protocol code, and update it in the same change when wire format or protocol behavior changes. Sections describing not-yet-implemented features are explicitly marked "*To be specified*"; keep that marking accurate.

## Layout

```
docs/conduit-spec.md       # the specification (the "RFC") — source of truth
src/conduit.h              # public API
src/conduit.c              # reference implementation (header + handshake codec)
tests/test_conduit.c       # dependency-free test harness
examples/udp_hello.c       # throwaway POSIX UDP spike — NOT part of the framework
examples/conduit_ping.c    # sends/receives a real Conduit header over UDP
examples/conduit_handshake.c # demonstrates the INIT/RESP/CONFIRM handshake
```

Programs with a `main()` (anything that exercises the protocol over a socket) live in `examples/`, not `src/` — only library code belongs in `src/`. The Makefile links each example against the library object.

## Build & run

The [Makefile](Makefile) drives everything; artifacts go to `build/` (git-ignored). Requires a C11 compiler and a POSIX environment.

```sh
make           # build the library object, tests, and all examples into build/
make test      # build and run the test suite
make example   # build the udp_hello spike
make ping      # build the conduit_ping example
make handshake # build the conduit_handshake example
make clean     # remove build/
```

The test harness is a single `main()` in [tests/test_conduit.c](tests/test_conduit.c) that builds each case, prints a line, and ANDs per-case booleans into a final pass/fail; it returns non-zero on any failure, so `make test` drops into CI as-is. Add a case by following the same pattern and folding its boolean into `all_ok`.

Run the handshake demo end-to-end (loopback, no loss assumed):

```sh
make handshake
./build/conduit_handshake responder 9100            # terminal 1
./build/conduit_handshake initiator 127.0.0.1 9100  # terminal 2
```

## Design principles that constrain the code

These come from spec §1.4 and should govern implementation decisions:

- **Layered, independently usable.** Transport, reliability, and messaging are separate layers. A lower layer MUST NOT depend on a higher one, and each layer MAY be used in isolation.
- **Fixed mechanisms, injected policies.** Retransmission, framing, and demultiplexing are fixed and built in. Congestion control, serialization, compression, and encryption are replaceable policies — design them as injectable, not hard-coded.
- **Pay for what you use.** A disabled feature MUST impose neither wire overhead nor runtime cost. Flag-gate optional header sections; don't reserve space for features that are off.
- **Local truth.** Connection state lives locally in each endpoint over the stateless UDP substrate, synchronized by explicit exchanges; a timeout is the final authority on liveness.

## Robustness requirement (spec §7)

Even without the optional crypto layer, any implementation MUST handle malformed, truncated, or duplicated packets by discarding them cleanly, and MUST NOT trust such input. Treat all received bytes as hostile until validated. Note in [examples/udp_hello.c](examples/udp_hello.c) that `recvfrom` also yields the source address — that source address is what the transport layer will use to demultiplex packets to connections.

## Scope reminders

Conduit targets controlled networks where one operator owns both endpoints. It does **not** interoperate with any existing protocol, does no NAT traversal or multipath, and is not for browsers or the public Internet. Don't add features that only make sense for those non-goals.
