# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Conduit is a connection-oriented communication protocol layered on top of UDP, plus its reference implementation in C. The project is early: the specification ([docs/conduit-spec.md](docs/conduit-spec.md)) is `draft-conduit-00`. Section 2 (Packet Format) is fully specified — the fixed 7-octet header (Connection ID, Type, Flags) with the critical/ignorable flag partition — and is implemented in [src/](src/). Sections 3–5 (lifecycle, reliability, channels) are still placeholders.

The spec and the implementation evolve together. [docs/conduit-spec.md](docs/conduit-spec.md) is the source of truth — read it before writing protocol code, and update it in the same change when wire format or protocol behavior changes. Sections describing not-yet-implemented features are explicitly marked "*To be specified*"; keep that marking accurate.

## Layout

```
docs/conduit-spec.md     # the specification (the "RFC") — source of truth
src/conduit.h            # public API
src/conduit.c            # reference implementation
tests/test_conduit.c     # dependency-free test harness
examples/udp_hello.c     # throwaway POSIX UDP spike — NOT part of the framework
```

## Build & run

The [Makefile](Makefile) drives everything; artifacts go to `build/` (git-ignored). Requires a C11 compiler and a POSIX environment.

```sh
make           # build the library object and tests into build/
make test      # build and run the test suite
make example   # build the udp_hello example into build/
make clean     # remove build/
```

The tests use a tiny in-file `CHECK()` macro rather than a framework — add new tests as plain functions called from `main()`. The harness returns non-zero on any failure, so `make test` drops into CI as-is.

The example spike is standalone and is **not** linked into the library:

```sh
make example
./build/udp_hello recv 9000                       # terminal 1: receiver
./build/udp_hello send 127.0.0.1 9000 "hello"     # terminal 2: sender
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
