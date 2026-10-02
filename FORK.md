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

- **BBR is BBRv3** (`quinn-proto`), from upstream pull request #2481
  (by Tipuch, draft-ietf-ccwg-bbr-06; open, not merged into `main` or
  `0.11.x`), with what it builds on: upstream `main`'s spurious-loss
  detection (531ca90e, by Fabien Savy). It replaces quinn's BBRv1, whose
  bandwidth estimate read low and whose pacing rate never reached the
  pacer. It brings:
  - finer controller events: each packet sent, acknowledged and lost by
    packet number space, the window-limited and application-limited
    signals, spurious losses, and the peer's ACK frequency. The
    `Controller` trait's `on_ack`, `on_end_acks` and
    `on_congestion_event` take the packet number and space;
  - a pacer that sends at the controller's `pacing_rate` (bytes/s, was
    bits/s) when it reports one, and a GSO batch bounded by its
    `send_quantum`. Controllers without a rate (Cubic, NewReno) keep
    0.11.x's window-derived pacing unchanged; upstream `main`'s 10 ms
    burst cap and `max_outgoing_bytes_per_second` are not taken, so the
    rate path bounds a burst as 0.11.x does (2 ms of traffic, 10 to 256
    datagrams);
  - BBR's response to classic ECN, from moq-dev/noq pull request #12
    (by Luke Curley; noq is MIT OR Apache-2.0, as quinn): CE stops
    Startup, ends a bandwidth probe, or cuts the short-term model, once
    per recovery episode, instead of being handled as a zero-byte loss.

  Adapted to 0.11.x: let-chains are rewritten for edition 2021; Cubic
  keeps no undo state for spurious losses, so its behaviour is
  unchanged; `Bbr` and `BbrConfig` remain as names for `Bbr3` and
  `Bbr3Config`. BBRv3's own logic supersedes this fork's two earlier BBR
  patches, which went with BBRv1: the Startup window bound (from
  upstream #2798) and the expiring minimum RTT (BBRv3's min-RTT filter
  and ProbeRTT refresh it every 10 s and 5 s). The fork's tests that a
  minimum RTT follows a path whose RTT steps up, and that per-ACK
  samples estimate the link's rate, now test BBRv3.

## When it could go away

When upstream quinn scatters the client's first CRYPTO data itself (no
such change is in upstream `main` or `0.11.x` today) and ships BBRv3
in the line sail uses. sail would then set upstream's option and drop
the `[patch.crates-io]` entry.
