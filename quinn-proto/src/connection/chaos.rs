//! ClientHello scattering ("chaos protection")
//!
//! The client's Initial packets are protected with keys derived from public values, so any
//! on-path observer can decrypt them. Simple middleboxes then read the SNI from a ClientHello that
//! sits contiguously in one CRYPTO frame at offset 0. Like Chrome's `QuicChaosProtector` and
//! quic-go's ClientHello scrambling, the client instead splits the ClientHello at random points,
//! always inside the server name (and ECH extension, if any), sends the pieces out of order, and
//! interleaves PING and PADDING frames between them. Receivers reassemble CRYPTO frames by offset,
//! so this is transparent to conforming servers.

use bytes::Bytes;
use rand::{Rng, RngExt};

use crate::frame;

/// TLS handshake message type of a ClientHello
const CLIENT_HELLO: u8 = 1;
/// TLS extension type of server_name
const EXT_SERVER_NAME: u16 = 0;
/// TLS extension type of encrypted_client_hello
const EXT_ECH: u16 = 0xfe0d;

/// Extra frames to write in front of one of the scattered CRYPTO frames
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Filler {
    /// Number of PING frames
    pub(super) pings: u8,
    /// Whether to write a run of PADDING frames, sized when the packet is built
    pub(super) padding: bool,
}

/// Where the interesting parts of a ClientHello are
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct HelloLayout {
    /// Offset and length of the server name in the server_name extension
    pub(super) sni: Option<(usize, usize)>,
    /// Offset of the encrypted_client_hello extension type
    pub(super) ech: Option<usize>,
}

/// Find the server name and ECH extension in a complete TLS ClientHello handshake message
///
/// Returns `None` if `hello` isn't exactly one well-formed ClientHello message.
pub(super) fn parse_client_hello(hello: &[u8]) -> Option<HelloLayout> {
    let mut r = Reader { buf: hello, pos: 0 };
    if r.u8()? != CLIENT_HELLO {
        return None;
    }
    let len = r.u24()?;
    if 4 + len != hello.len() {
        return None;
    }
    r.skip(2 + 32)?; // legacy_version, random
    let n = r.u8()? as usize;
    r.skip(n)?; // legacy_session_id
    let n = r.u16()? as usize;
    r.skip(n)?; // cipher_suites
    let n = r.u8()? as usize;
    r.skip(n)?; // legacy_compression_methods
    let ext_len = r.u16()? as usize;
    let end = r.pos.checked_add(ext_len)?;
    if end != hello.len() {
        return None;
    }
    let mut layout = HelloLayout::default();
    while r.pos < end {
        let ty_pos = r.pos;
        let ty = r.u16()?;
        let len = r.u16()? as usize;
        let body = r.pos;
        r.skip(len)?;
        match ty {
            EXT_SERVER_NAME => {
                // server_name_list length, name_type, host_name length
                let mut e = Reader {
                    buf: &hello[..body + len],
                    pos: body,
                };
                e.skip(2)?;
                if e.u8()? != 0 {
                    continue;
                }
                let n = e.u16()? as usize;
                let start = e.pos;
                e.skip(n)?;
                if n > 0 {
                    layout.sni = Some((start, n));
                }
            }
            EXT_ECH => layout.ech = Some(ty_pos),
            _ => {}
        }
    }
    Some(layout)
}

/// Split a ClientHello into shuffled CRYPTO frames and matching fillers
///
/// Returns `None` if `hello` isn't a single ClientHello message; the caller then sends it
/// unmodified. The frames cover `offset..offset + hello.len()` exactly once, the first frame
/// never starts at `offset`, and no frame contains the whole server name.
pub(super) fn scatter(
    offset: u64,
    hello: &Bytes,
    rng: &mut impl Rng,
) -> Option<(Vec<frame::Crypto>, Vec<Filler>)> {
    let layout = parse_client_hello(hello)?;
    let len = hello.len();

    let mut cuts = Vec::new();
    if let Some((start, n)) = layout.sni {
        // Cut inside the host name, so no frame carries all of it
        cuts.push(if n >= 2 {
            start + rng.random_range(1..n)
        } else {
            start
        });
    }
    if let Some(pos) = layout.ech {
        // Cut the ECH extension type in half, as quic-go does
        cuts.push(pos + 1);
    }
    // And a few more random cuts, so the frame boundaries don't point at the SNI
    for _ in 0..rng.random_range(3..=6) {
        cuts.push(rng.random_range(1..len));
    }
    cuts.retain(|&c| c > 0 && c < len);
    cuts.sort_unstable();
    cuts.dedup();

    let mut frames = Vec::with_capacity(cuts.len() + 1);
    let mut prev = 0;
    for cut in cuts.into_iter().chain(Some(len)) {
        frames.push(frame::Crypto {
            offset: offset + prev as u64,
            data: hello.slice(prev..cut),
        });
        prev = cut;
    }
    if frames.len() < 2 {
        return None;
    }

    // Fisher-Yates, then make sure the start of the hello isn't sent first
    for i in (1..frames.len()).rev() {
        let j = rng.random_range(0..=i);
        frames.swap(i, j);
    }
    if frames[0].offset == offset {
        let j = rng.random_range(1..frames.len());
        frames.swap(0, j);
    }

    let mut fillers = (0..frames.len())
        .map(|_| Filler {
            pings: rng.random_range(0..=2),
            padding: rng.random_ratio(1, 2),
        })
        .collect::<Vec<_>>();
    // At least one PING and one PADDING run somewhere before the last frame
    let i = rng.random_range(0..frames.len());
    fillers[i].pings = fillers[i].pings.max(1);
    let i = rng.random_range(1..frames.len());
    fillers[i].padding = true;

    Some((frames, fillers))
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn skip(&mut self, n: usize) -> Option<()> {
        let end = self.pos.checked_add(n)?;
        if end > self.buf.len() {
            return None;
        }
        self.pos = end;
        Some(())
    }

    fn u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from(self.u8()?) << 8 | u16::from(self.u8()?))
    }

    fn u24(&mut self) -> Option<usize> {
        Some(usize::from(self.u8()?) << 16 | usize::from(self.u16()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    /// A minimal ClientHello with a server_name and an ECH extension
    fn hello(sni: &[u8]) -> Vec<u8> {
        let mut exts = Vec::new();
        // supported_versions
        exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
        // server_name
        let n = sni.len() as u16;
        exts.extend_from_slice(&0u16.to_be_bytes());
        exts.extend_from_slice(&(n + 5).to_be_bytes());
        exts.extend_from_slice(&(n + 3).to_be_bytes());
        exts.push(0);
        exts.extend_from_slice(&n.to_be_bytes());
        exts.extend_from_slice(sni);
        // encrypted_client_hello
        exts.extend_from_slice(&[0xfe, 0x0d, 0x00, 0x04, 1, 2, 3, 4]);

        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7; 32]);
        body.push(0); // session id
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut msg = vec![CLIENT_HELLO];
        msg.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        msg.extend_from_slice(&body);
        msg
    }

    #[test]
    fn parse() {
        let h = hello(b"example.com");
        let layout = parse_client_hello(&h).unwrap();
        let (start, n) = layout.sni.unwrap();
        assert_eq!(&h[start..start + n], b"example.com");
        let ech = layout.ech.unwrap();
        assert_eq!(&h[ech..ech + 2], &[0xfe, 0x0d]);

        assert_eq!(parse_client_hello(&h[..h.len() - 1]), None);
        let mut long = h.clone();
        long.push(0);
        assert_eq!(parse_client_hello(&long), None);
        assert_eq!(parse_client_hello(&[2, 0, 0, 0]), None);
    }

    #[test]
    fn scatter_covers_and_hides_sni() {
        let h = Bytes::from(hello(b"www.example.com"));
        let (sni_start, sni_len) = parse_client_hello(&h).unwrap().sni.unwrap();
        for seed in 0..200u64 {
            let mut rng = StdRng::seed_from_u64(seed);
            let (frames, fillers) = scatter(0, &h, &mut rng).unwrap();
            assert_eq!(frames.len(), fillers.len());
            assert!(frames.len() >= 3);
            assert_ne!(frames[0].offset, 0);
            assert!(fillers.iter().any(|f| f.pings > 0));
            assert!(fillers.iter().any(|f| f.padding));

            let mut sorted = frames.clone();
            sorted.sort_by_key(|f| f.offset);
            let mut out = Vec::new();
            for f in &sorted {
                assert_eq!(f.offset, out.len() as u64);
                assert!(!f.data.is_empty());
                let (s, e) = (f.offset as usize, f.offset as usize + f.data.len());
                assert!(
                    !(s <= sni_start && sni_start + sni_len <= e),
                    "SNI in one frame"
                );
                out.extend_from_slice(&f.data);
            }
            assert_eq!(out, &h[..]);
        }
    }

    #[test]
    fn scatter_rejects_non_hello() {
        let mut rng = StdRng::seed_from_u64(1);
        assert!(scatter(0, &Bytes::from_static(&[1, 2, 3]), &mut rng).is_none());
    }
}
