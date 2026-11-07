//! Parses TLS and DTLS ClientHello messages. Every field comes from whoever made the capture,
//! so reads are bounds-checked and a message that does not add up is refused as a whole.

/// The longest ClientHello accepted, record framing included. Post-quantum key shares make real
/// ones several kilobytes; this leaves room for those and bounds what one flow can make us hold.
pub const MAX_HELLO: usize = 1 << 18;

const CONTENT_HANDSHAKE: u8 = 22;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;

const EXT_SNI: u16 = 0x0000;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ClientHello {
    pub version: u16,
    /// In the order sent, GREASE included: the fingerprint decides what to leave out.
    pub ciphers: Vec<u16>,
    pub extensions: Vec<u16>,
    pub supported_versions: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    /// The first host name in the SNI extension, as sent. It is not necessarily UTF-8 or printable.
    pub server_name: Option<Vec<u8>>,
    pub alpn_first: Option<Vec<u8>>,
}

struct Cursor<'a> {
    data: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.data.len() {
            return None;
        }
        let (head, rest) = self.data.split_at(n);
        self.data = rest;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    /// A block prefixed with its length in `width` bytes.
    fn block(&mut self, width: usize) -> Option<Cursor<'a>> {
        let len = self
            .take(width)?
            .iter()
            .fold(0usize, |n, b| n << 8 | usize::from(*b));
        Some(Cursor {
            data: self.take(len)?,
        })
    }

    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

fn u16_list(mut c: Cursor<'_>) -> Option<Vec<u16>> {
    let mut out = Vec::with_capacity(c.data.len() / 2);
    while !c.is_empty() {
        out.push(c.u16()?);
    }
    Some(out)
}

/// Parses the body of a ClientHello handshake message: the part after its header.
pub fn parse_client_hello(body: &[u8], dtls: bool) -> Option<ClientHello> {
    let mut c = Cursor { data: body };
    let mut hello = ClientHello {
        version: c.u16()?,
        ..Default::default()
    };
    c.take(32)?;
    c.block(1)?; // session id
    if dtls {
        c.block(1)?; // cookie
    }
    hello.ciphers = u16_list(c.block(2)?)?;
    c.block(1)?; // compression methods
    if c.is_empty() {
        return Some(hello); // old clients send no extensions at all
    }
    let mut extensions = c.block(2)?;
    while !extensions.is_empty() {
        let kind = extensions.u16()?;
        let data = extensions.block(2)?;
        hello.extensions.push(kind);
        // A broken extension still exists and still counts, so its contents are read if they
        // can be and left out if they cannot.
        match kind {
            EXT_SNI => hello.server_name = server_name(data),
            EXT_SIGNATURE_ALGORITHMS => {
                hello.signature_algorithms = list_block(data, 2).unwrap_or_default();
            }
            EXT_ALPN => hello.alpn_first = alpn_first(data),
            EXT_SUPPORTED_VERSIONS => {
                hello.supported_versions = list_block(data, 1).unwrap_or_default()
            }
            _ => {}
        }
    }
    Some(hello)
}

fn list_block(mut c: Cursor<'_>, width: usize) -> Option<Vec<u16>> {
    u16_list(c.block(width)?)
}

fn server_name(mut c: Cursor<'_>) -> Option<Vec<u8>> {
    let mut names = c.block(2)?;
    while !names.is_empty() {
        let kind = names.u8()?;
        let name = names.block(2)?;
        if kind == 0 {
            return Some(name.data.to_vec());
        }
    }
    None
}

fn alpn_first(mut c: Cursor<'_>) -> Option<Vec<u8>> {
    let mut list = c.block(2)?;
    Some(list.block(1)?.data.to_vec())
}

/// The outcome of looking at the start of a client's TCP stream.
#[derive(Debug, PartialEq, Eq)]
pub enum Stream {
    /// So far this could be a ClientHello; it needs more bytes.
    NeedMore,
    /// This is not a ClientHello, or is one that does not add up.
    NotHello,
    Hello(ClientHello),
}

/// Whether a stream could start with a ClientHello, judging by as little as its first bytes.
pub fn starts_like_hello(data: &[u8]) -> bool {
    let expect = [CONTENT_HANDSHAKE, 3];
    let n = data.len().min(2);
    if data[..n] != expect[..n] {
        return false;
    }
    if let Some(version) = data.get(2) {
        if *version > 4 {
            return false;
        }
    }
    data.get(5).map_or(true, |t| *t == HANDSHAKE_CLIENT_HELLO)
}

/// Reads a ClientHello from the start of a TCP stream. The message can span records, and records
/// can span packets, so this walks the records gathering handshake bytes until there are enough.
pub fn parse_tcp_stream(stream: &[u8]) -> Stream {
    if !starts_like_hello(stream) {
        return Stream::NotHello;
    }
    let mut handshake = Vec::new();
    let mut rest = stream;
    loop {
        if handshake.len() >= 4 {
            let len = usize::from(handshake[1]) << 16
                | usize::from(handshake[2]) << 8
                | usize::from(handshake[3]);
            if len > MAX_HELLO {
                return Stream::NotHello;
            }
            if handshake.len() >= 4 + len {
                return match parse_client_hello(&handshake[4..4 + len], false) {
                    Some(hello) => Stream::Hello(hello),
                    None => Stream::NotHello,
                };
            }
        }
        if rest.len() < 5 {
            return Stream::NeedMore;
        }
        if rest[0] != CONTENT_HANDSHAKE || rest[1] != 3 {
            return Stream::NotHello;
        }
        let len = usize::from(rest[3]) << 8 | usize::from(rest[4]);
        if len == 0 {
            return Stream::NotHello;
        }
        let available = len.min(rest.len() - 5);
        handshake.extend_from_slice(&rest[5..5 + available]);
        if available < len {
            return Stream::NeedMore;
        }
        rest = &rest[5 + len..];
    }
}

/// One fragment of a DTLS ClientHello from a datagram.
#[derive(Debug, PartialEq, Eq)]
pub struct DtlsFragment<'a> {
    pub message_seq: u16,
    pub total: usize,
    pub offset: usize,
    pub data: &'a [u8],
}

/// The ClientHello fragments in a UDP datagram, which can hold several DTLS records.
pub fn dtls_fragments(mut datagram: &[u8]) -> Vec<DtlsFragment<'_>> {
    let mut out = Vec::new();
    while datagram.len() >= 13 {
        if datagram[0] != CONTENT_HANDSHAKE || datagram[1] != 0xfe {
            break;
        }
        let len = usize::from(datagram[11]) << 8 | usize::from(datagram[12]);
        let Some(mut record) = datagram.get(13..13 + len) else {
            break;
        };
        datagram = &datagram[13 + len..];
        while record.len() >= 12 {
            let be24 =
                |b: &[u8]| usize::from(b[0]) << 16 | usize::from(b[1]) << 8 | usize::from(b[2]);
            let total = be24(&record[1..]);
            let offset = be24(&record[6..]);
            let frag_len = be24(&record[9..]);
            let Some(data) = record.get(12..12 + frag_len) else {
                break;
            };
            if record[0] == HANDSHAKE_CLIENT_HELLO {
                out.push(DtlsFragment {
                    message_seq: u16::from_be_bytes([record[4], record[5]]),
                    total,
                    offset,
                    data,
                });
            }
            record = &record[12 + frag_len..];
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hello body with these extensions, each given as (type, contents).
    fn body(version: u16, dtls: bool, ciphers: &[u16], exts: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut b = version.to_be_bytes().to_vec();
        b.extend_from_slice(&[7; 32]);
        b.extend_from_slice(&[2, 9, 9]); // session id
        if dtls {
            b.extend_from_slice(&[1, 5]); // cookie
        }
        b.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
        for c in ciphers {
            b.extend_from_slice(&c.to_be_bytes());
        }
        b.extend_from_slice(&[1, 0]); // compression
        let mut e = Vec::new();
        for (kind, data) in exts {
            e.extend_from_slice(&kind.to_be_bytes());
            e.extend_from_slice(&(data.len() as u16).to_be_bytes());
            e.extend_from_slice(data);
        }
        b.extend_from_slice(&(e.len() as u16).to_be_bytes());
        b.extend(e);
        b
    }

    fn message(body: &[u8]) -> Vec<u8> {
        let mut m = vec![1, 0, (body.len() >> 8) as u8, body.len() as u8];
        m.extend_from_slice(body);
        m
    }

    fn record(payload: &[u8]) -> Vec<u8> {
        let mut r = vec![22, 3, 1];
        r.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        r.extend_from_slice(payload);
        r
    }

    fn sni(name: &[u8]) -> Vec<u8> {
        let mut v = ((name.len() + 3) as u16).to_be_bytes().to_vec();
        v.push(0);
        v.extend_from_slice(&(name.len() as u16).to_be_bytes());
        v.extend_from_slice(name);
        v
    }

    fn sample() -> Vec<u8> {
        body(
            0x0303,
            false,
            &[0x1301, 0xc02b],
            &[
                (0, sni(b"example.org")),
                (0x10, vec![0, 6, 2, b'h', b'2', 1, b'x', 0]),
                (0x0d, vec![0, 4, 4, 3, 8, 4]),
                (0x2b, vec![4, 3, 4, 3, 3]),
                (0x1a1a, vec![]),
            ],
        )
    }

    #[test]
    fn reads_every_field() {
        let h = parse_client_hello(&sample(), false).unwrap();
        assert_eq!(h.version, 0x0303);
        assert_eq!(h.ciphers, [0x1301, 0xc02b]);
        assert_eq!(h.extensions, [0, 0x10, 0x0d, 0x2b, 0x1a1a]);
        assert_eq!(h.server_name.as_deref(), Some(&b"example.org"[..]));
        assert_eq!(h.alpn_first.as_deref(), Some(&b"h2"[..]));
        assert_eq!(h.signature_algorithms, [0x0403, 0x0804]);
        assert_eq!(h.supported_versions, [0x0304, 0x0303]);
    }

    #[test]
    fn the_dtls_cookie_is_skipped_only_for_dtls() {
        let d = body(0xfefd, true, &[0x1301], &[]);
        assert_eq!(parse_client_hello(&d, true).unwrap().ciphers, [0x1301]);
        assert_ne!(
            parse_client_hello(&d, false).map(|h| h.ciphers),
            Some(vec![0x1301])
        );
    }

    #[test]
    fn a_hello_without_extensions_is_fine() {
        let mut b = 0x0301u16.to_be_bytes().to_vec();
        b.extend_from_slice(&[0; 32]);
        b.extend_from_slice(&[0, 0, 2, 0, 5, 1, 0]);
        let h = parse_client_hello(&b, false).unwrap();
        assert_eq!((h.ciphers.as_slice(), h.extensions.len()), (&[5u16][..], 0));
    }

    #[test]
    fn broken_extension_contents_still_count_as_extensions() {
        let b = body(
            0x0303,
            false,
            &[1],
            &[
                (0, vec![0, 9]),
                (0x10, vec![0]),
                (0x0d, vec![0, 3, 1, 2, 3]),
                (0x2b, vec![9]),
            ],
        );
        let h = parse_client_hello(&b, false).unwrap();
        assert_eq!(h.extensions, [0, 0x10, 0x0d, 0x2b]);
        assert_eq!((h.server_name, h.alpn_first), (None, None));
        assert!(h.signature_algorithms.is_empty() && h.supported_versions.is_empty());
    }

    #[test]
    fn sni_takes_the_first_host_name_entry() {
        // An unknown name type first, then the host name.
        let mut list = vec![1, 0, 1, b'z', 0, 0, 1, b'a', 0, 0, 1, b'b'];
        let mut v = (list.len() as u16).to_be_bytes().to_vec();
        v.append(&mut list);
        let h = parse_client_hello(&body(0x0303, false, &[1], &[(0, v)]), false).unwrap();
        assert_eq!(h.server_name.as_deref(), Some(&b"a"[..]));
        let none = vec![0, 4, 1, 0, 1, b'z'];
        assert_eq!(
            parse_client_hello(&body(0x0303, false, &[1], &[(0, none)]), false)
                .unwrap()
                .server_name,
            None
        );
    }

    #[test]
    fn every_truncation_of_a_hello_is_refused_or_short_of_extensions() {
        let b = sample();
        for n in 0..b.len() {
            if let Some(h) = parse_client_hello(&b[..n], false) {
                assert!(h.extensions.is_empty(), "{n}");
                assert_eq!(
                    n,
                    2 + 32 + 3 + 2 + 4 + 2,
                    "only the point just before the extensions block"
                );
            }
        }
        assert!(parse_client_hello(&body(0x0303, false, &[], &[]), false).is_some());
        let mut odd = sample();
        odd[38] = 3; // an odd cipher list length
        assert!(parse_client_hello(&odd, false).is_none());
    }

    #[test]
    fn a_stream_is_gathered_across_records_and_packets() {
        let m = message(&sample());
        let whole = record(&m);
        assert!(matches!(parse_tcp_stream(&whole), Stream::Hello(_)));
        for n in 1..whole.len() {
            assert_eq!(parse_tcp_stream(&whole[..n]), Stream::NeedMore, "{n}");
        }
        let (a, b) = m.split_at(20);
        let split = [record(a), record(b)].concat();
        for n in 1..split.len() {
            assert_eq!(parse_tcp_stream(&split[..n]), Stream::NeedMore, "{n}");
        }
        let Stream::Hello(h) = parse_tcp_stream(&split) else {
            panic!()
        };
        assert_eq!(h.ciphers, [0x1301, 0xc02b]);
        // The header itself split across records.
        let (a, b) = m.split_at(2);
        assert!(matches!(
            parse_tcp_stream(&[record(a), record(b)].concat()),
            Stream::Hello(_)
        ));
        // Bytes after the hello do not matter.
        let mut more = whole.clone();
        more.extend_from_slice(b"\x17\x03\x03\x00\x01x");
        assert!(matches!(parse_tcp_stream(&more), Stream::Hello(_)));
    }

    #[test]
    fn other_streams_are_given_up_on_at_once() {
        for s in [
            &b"GET / HTTP/1.1\r\n"[..],
            b"S",
            b"\x16\x02",
            b"\x16\x03\x05",
            b"\x17\x03\x03\x00\x05hello",
            b"\x16\x03\x03\x00\x05\x02\x00\x00\x01\x00", // a ServerHello
            b"\x16\x03\x03\x00\x00",                     // an empty record
            b"\x16\x03\x03\x40\x00\x02",                 // a partial ServerHello record
        ] {
            assert_eq!(parse_tcp_stream(s), Stream::NotHello, "{s:?}");
        }
        // A handshake that promises more than the limit.
        assert_eq!(
            parse_tcp_stream(&record(&[1, 0xff, 0xff, 0xff])),
            Stream::NotHello
        );
        // A record of another kind before the hello is complete.
        let part = record(&[1, 0, 0, 200, 3]);
        assert_eq!(
            parse_tcp_stream(&[part, b"\x17\x03\x03\x00\x01x".to_vec()].concat()),
            Stream::NotHello
        );
        // A hello whose contents do not add up.
        assert_eq!(
            parse_tcp_stream(&record(&[1, 0, 0, 2, 3, 3])),
            Stream::NotHello
        );
    }

    #[test]
    fn dtls_fragments_across_records_in_a_datagram() {
        let dtls = |seq: u16, total: usize, off: usize, data: &[u8]| {
            let mut h = vec![1, (total >> 16) as u8, (total >> 8) as u8, total as u8];
            h.extend_from_slice(&seq.to_be_bytes());
            h.extend_from_slice(&[(off >> 16) as u8, (off >> 8) as u8, off as u8]);
            h.extend_from_slice(&[
                (data.len() >> 16) as u8,
                (data.len() >> 8) as u8,
                data.len() as u8,
            ]);
            h.extend_from_slice(data);
            let mut r = vec![22, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 1];
            r.extend_from_slice(&(h.len() as u16).to_be_bytes());
            r.extend(h);
            r
        };
        let d = [dtls(2, 9, 0, b"abcd"), dtls(2, 9, 4, b"efghi")].concat();
        let f = dtls_fragments(&d);
        assert_eq!(f.len(), 2);
        assert_eq!(
            f[1],
            DtlsFragment {
                message_seq: 2,
                total: 9,
                offset: 4,
                data: b"efghi"
            }
        );
        assert!(
            dtls_fragments(&d[..d.len() - 1]).len() == 1,
            "the cut record is dropped"
        );
        assert!(dtls_fragments(b"\x16\x03\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00").is_empty());
        // Another handshake type in the record is passed over.
        let mut server = dtls(0, 2, 0, b"xy");
        server[13] = 2;
        assert!(dtls_fragments(&server).is_empty());
    }
}
