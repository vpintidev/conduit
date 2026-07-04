# Testing Conduit

How Conduit is tested, and why. This strategy was arrived at bottom-up — driven
by concrete needs as the code was built — rather than imposed up front.

## Philosophy

Conduit favours a small amount of high-value testing infrastructure over a heavy
framework:

- **Zero dependencies.** Tests build with the same `cc` as the library. A
  library that asks its users for no dependencies should not need one to test
  itself; several production C projects (SQLite, the Linux kernel) take the same
  approach with home-grown harnesses.
- **Deterministic.** Time-dependent behaviour is tested with a simulated clock,
  never by sleeping. Tests run in microseconds and do not flake on timing.
- **Layered.** Pure wire primitives and connection logic are covered by unit
  tests; whole-system behaviour is exercised by the runnable examples.

## Running the tests

```sh
make test
```

Output is one line per test — a green `[OK]` or red `[KO]` — with failure detail
(file, line, expected vs actual) shown beneath any failing test. Colour is
emitted only when standard output is an interactive terminal and the `NO_COLOR`
environment variable is unset, so CI logs and redirected output stay free of
escape codes.

## The test helper

`tests/test.h` is a small header providing:

- `TEST(name)` — begin a named test.
- `CHECK(cond)` — assert a condition.
- `CHECK_EQ_U32(got, want)` / `CHECK_EQ_SIZE(got, want)` — assert equality,
  reporting the expected and actual values on failure.
- `test_summary()` — print totals and return the process exit code (0 = pass).

Unlike `assert`, a failing check does **not** abort: every test runs, so a single
invocation reports all failures. (`assert` remains appropriate for catching
"impossible" conditions inside production code — not for tests, and it is
disabled under `NDEBUG`.)

## Deterministic time

The connection liveness logic (`conduit_conn_tick`, `conduit_conn_on_ack`, …)
receives the current time as a parameter and never reads the system clock. This
makes heartbeat scheduling, RTT measurement, and timeout detection fully testable
without sockets or real delays: a test calls `tick` with increasing timestamps
and asserts the outcome. A three-second timeout, for instance, is verified by
advancing the simulated clock in one-second steps — the test itself takes
microseconds.

Testability is the main reason the design passes time explicitly.

## Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request:

- **build & test** on both **gcc** and **clang**. A compiler matrix catches
  compiler-specific issues and standard-conformance gaps.
- **sanitizers** — a separate job builds with **AddressSanitizer** and
  **UndefinedBehaviorSanitizer** and runs the tests, catching memory errors and
  undefined behaviour that ordinary tests miss. This matters especially for a
  network library that parses untrusted input.

The Makefile exposes an `EXTRA_CFLAGS` hook so CI can inject sanitizer flags
without changing the build:

```sh
make test EXTRA_CFLAGS="-fsanitize=address,undefined -g"
```

## Coverage

- **Covered by unit tests:** packet-header encode/decode and validation,
  malformed-input rejection, handshake message round-trips, heartbeat round-trips,
  and the liveness logic (heartbeat timing, RTT, timeout).
- **Covered informally by examples:** end-to-end behaviour over real UDP sockets
  (`conduit_handshake`, `conduit_rtt`).

## Roadmap

As the protocol grows, planned additions include:

- **Fuzzing** the packet parser (libFuzzer / AFL) — the natural next step for a
  parser of untrusted network input, most valuable once the parser handles the
  optional sections introduced in Circle 2.
- **Code coverage** measurement (gcov / lcov) to surface untested branches.
- **End-to-end tests** driving two instances under simulated packet loss, once
  loss handling (retransmission) exists.