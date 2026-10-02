# This fork

sail's fork of [quinn-rs/quinn](https://github.com/quinn-rs/quinn). The
`sail` branch tracks upstream's `0.11.x` release line, which is the
version sail uses. sail takes only `quinn-proto` from it, through
`[patch.crates-io]`; `quinn` and `quinn-udp` come from crates.io.

Upstream is merged into `sail`, never rebased onto it, and the branch is
never force-pushed: sail pins revisions of it. Moving to a new upstream
minor line (0.12) is a merge of that line, done when sail moves its
`quinn` dependency.

## Patches

- **ClientHello scattering** (`quinn-proto`): the client's first Initial
  packets are decryptable by anyone, and a ClientHello at offset 0 in one
  CRYPTO frame gives its SNI to any middlebox. As Chrome's chaos
  protection and quic-go do, the client splits the hello at random points
  (always inside the server name and the ECH extension type), sends the
  pieces in shuffled order with PING and PADDING frames between them, and
  retransmits lost pieces as ordinary CRYPTO data. Servers are
  unaffected. It is on by default;
  `TransportConfig::scramble_client_hello(false)` turns it off.

- **BBR's window is bounded in Startup** (`quinn-proto`), from upstream
  pull request #2798 (by poka-IT, not yet merged; same licence as quinn).
  Startup grew the window while `cwnd_gain < target_window`, a gain
  compared with a byte count, so on a connection that stays app-limited
  the window followed the bytes acked without bound (over 300 MB was seen
  on one TUIC connection), and a sender could flood a bottleneck.
  It now grows while `cwnd < target_window`; the bandwidth filter takes
  app-limited samples only when they raise it, and no zero-rate ones.
  A stopgap: the bandwidth sampling itself still reads low, which a
  BBRv3 port (upstream #2481) is to replace.

- **BBR's minimum RTT expires** (`quinn-proto`). BBR took the
  connection's lifetime minimum RTT (`RttEstimator::min`), which never
  rises, and ProbeRtt could not refresh it. On a long-lived connection,
  which a Hysteria2 client keeps for all its traffic, one low sample
  (an undelayed path, a few packets that a reordering link let through
  early) sized the window for good: when the path's RTT later rose, the
  window stayed at a few packets and throughput collapsed for the rest
  of the connection's life (0.5 Mbit/s on a 50 Mbit/s, 150 ms path, with
  min_rtt still 42 us). As quiche keeps it, the minimum is now the
  lowest of the latest RTT samples (`RttEstimator::latest`, added) over
  a 10 s window: it expires 10 s after it was set, the next ACKs' sample
  replaces it and starts ProbeRtt, and leaving ProbeRtt stamps it anew.
  Upstream `main` still uses `rtt.min()`; the BBRv3 port (upstream
  #2481), which has a windowed min-RTT filter, is to replace this.

## When it could go away

When upstream quinn scatters the client's first CRYPTO data itself (no
such change is in upstream `main` or `0.11.x` today). sail would then set
upstream's option and drop the `[patch.crates-io]` entry.
