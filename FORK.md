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

## When it could go away

When upstream quinn scatters the client's first CRYPTO data itself (no
such change is in upstream `main` or `0.11.x` today). sail would then set
upstream's option and drop the `[patch.crates-io]` entry.
