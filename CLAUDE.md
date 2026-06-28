# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Conduit is a connection-oriented communication protocol layered on top of UDP, plus its reference implementation in C. The project is at its very beginning: the specification ([conduit-spec.md](conduit-spec.md)) is `draft-conduit-00` with most wire-format sections still placeholders, and the only code so far is a throwaway socket spike ([udp_hello.c](udp_hello.c)).

The spec and the implementation evolve together. [conduit-spec.md](conduit-spec.md) is the source of truth — read it before writing protocol code, and update it in the same change when wire format or protocol behavior changes. Sections describing not-yet-implemented features are explicitly marked "*To be specified*"; keep that marking accurate.

## Build & run

There is no build system yet. The spike compiles directly:

```
gcc -Wall -Wextra -o udp_hello udp_hello.c
./udp_hello recv 9000                       # terminal 1: receiver
./udp_hello send 127.0.0.1 9000 "hello"     # terminal 2: sender
```

Note: [udp_hello.c](udp_hello.c) is **not** part of the framework — it exists only to exercise the POSIX UDP API and should not be built upon directly. New framework code will need its own build setup.

## Design principles that constrain the code

These come from spec §1.4 and should govern implementation decisions:

- **Layered, independently usable.** Transport, reliability, and messaging are separate layers. A lower layer MUST NOT depend on a higher one, and each layer MAY be used in isolation.
- **Fixed mechanisms, injected policies.** Retransmission, framing, and demultiplexing are fixed and built in. Congestion control, serialization, compression, and encryption are replaceable policies — design them as injectable, not hard-coded.
- **Pay for what you use.** A disabled feature MUST impose neither wire overhead nor runtime cost. Flag-gate optional header sections; don't reserve space for features that are off.
- **Local truth.** Connection state lives locally in each endpoint over the stateless UDP substrate, synchronized by explicit exchanges; a timeout is the final authority on liveness.

## Robustness requirement (spec §7)

Even without the optional crypto layer, any implementation MUST handle malformed, truncated, or duplicated packets by discarding them cleanly, and MUST NOT trust such input. Treat all received bytes as hostile until validated. Note in [udp_hello.c](udp_hello.c) that `recvfrom` also yields the source address — that source address is what the transport layer will use to demultiplex packets to connections.

## Scope reminders

Conduit targets controlled networks where one operator owns both endpoints. It does **not** interoperate with any existing protocol, does no NAT traversal or multipath, and is not for browsers or the public Internet. Don't add features that only make sense for those non-goals.
