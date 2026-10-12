# This fork

sail's fork of [quinn-rs/quinn](https://github.com/quinn-rs/quinn). The
`sail` branch tracks upstream's `0.11.x` release line, which is the
version sail uses. sail takes `quinn-proto` and `quinn` from it, at one
revision, through `[patch.crates-io]`; `quinn-udp`, which `quinn` depends
on by path, then comes from here too, unpatched. Besides the patches
below, the crates are the `0.11.x` line's tip, which can be a few
upstream fixes ahead of the latest release on crates.io.

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

- **Up to 16 segments per send** (`quinn`). A connection handed the
  socket at most 10 datagrams per segmented send (`MAX_TRANSMIT_SEGMENTS`),
  a number upstream chose to keep `poll_transmit`'s buffer small. More
  per send costs the sender less CPU, but past 16 the upload on a long
  path got slower. A Hysteria2 client uploading to sing-box on Linux,
  medians of 6 rounds on loopback and at 50 ms RTT and of 8 at 150 ms
  (netem, no rate limit), 1 GiB a round; 10 was run twice in every job:

  | segments | loopback Mbit/s | CPU s/GiB | 150 ms Mbit/s | CPU s/GiB | 50 ms Mbit/s | CPU s/GiB |
  |---|---|---|---|---|---|---|
  | 10 | 3545, 3487 | 2.90 | 441, 454 | 1.86 | 1151, 1129 | 1.96 |
  | 16 | 3707 | 2.58 | 443 | 1.60 | 1118 | 1.69 |
  | 20 | 3800 | 2.54 | 427 | 1.60 | 1114 | 1.64 |
  | 32 | 3747 | 2.45 | 431 | 1.43 | 1108 | 1.50 |

  The two runs of 10 differ by 2.8% at 150 ms and 2.0% at 50 ms; against
  their pooled medians (449 and 1135), 16 is 1.3% and 1.5% lower, inside
  that, and 20 and 32 are 4-5% lower at 150 ms. Downloads did not change
  at any count. 64, Linux's own limit, fails: a segmented send is one
  UDP datagram to the kernel, and 64 segments of 1452 bytes do not fit
  one. The count is the least of 16, what the socket can segment, and
  what fits a datagram at the current MTU, (65535 - 8 - 40) / MTU: 7 at
  a 9000-byte MTU.
  The cost is memory: a connection keeps its send buffer once it has
  sent a batch, about 17 segments (25 KB at 1452) where it was 11
  (16 KB). Upstream `main` still has 10.

## When it could go away

When upstream quinn scatters the client's first CRYPTO data itself (no
such change is in upstream `main` or `0.11.x` today). sail would then set
upstream's option and drop the `quinn-proto` entry in `[patch.crates-io]`;
the BBR patches go with the BBRv3 port, and the `quinn` entry when
upstream raises its segment count or makes it configurable.
