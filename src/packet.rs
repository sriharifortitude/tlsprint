//! Takes a captured frame apart as far as its TCP or UDP payload.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
/// Stacked VLAN tags and IPv6 extension headers beyond this are not followed.
const MAX_HEADERS: usize = 8;

#[derive(Debug, PartialEq, Eq)]
pub enum Transport<'a> {
    Tcp {
        seq: u32,
        syn: bool,
        ack: bool,
        rst: bool,
        payload: &'a [u8],
    },
    Udp {
        payload: &'a [u8],
    },
}

#[derive(Debug, PartialEq, Eq)]
pub struct Packet<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub transport: Transport<'a>,
}

/// Why a frame yields no packet, for those worth counting.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Skip {
    /// Not TCP or UDP over IP, or a link type this does not read.
    Other,
    /// Part of a fragmented IP packet: fragments are not reassembled.
    Fragment,
    /// The headers do not fit in what was captured, or make no sense.
    Malformed,
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

/// Parses a frame with the given pcap link type.
pub fn parse(linktype: u32, frame: &[u8]) -> Result<Packet<'_>, Skip> {
    match linktype {
        // Null: the address family in the capturing host's byte order, so either is possible.
        0 => {
            let head = frame.get(..4).ok_or(Skip::Malformed)?;
            let family = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
            let family = if family > 0xffff {
                family.swap_bytes()
            } else {
                family
            };
            by_family(family, &frame[4..])
        }
        // Loopback: always big-endian.
        108 => {
            let head = frame.get(..4).ok_or(Skip::Malformed)?;
            by_family(
                u32::from_be_bytes([head[0], head[1], head[2], head[3]]),
                &frame[4..],
            )
        }
        1 => ethernet(frame),
        // Raw IP, under its three numbers.
        101 | 12 | 14 => by_version(frame),
        228 => ipv4(frame),
        229 => ipv6(frame),
        // Linux cooked capture, versions 1 and 2.
        113 => {
            let head = frame.get(..16).ok_or(Skip::Malformed)?;
            by_ethertype(be16(&head[14..]), &frame[16..])
        }
        276 => {
            let head = frame.get(..20).ok_or(Skip::Malformed)?;
            by_ethertype(be16(head), &frame[20..])
        }
        _ => Err(Skip::Other),
    }
}

fn by_family(family: u32, rest: &[u8]) -> Result<Packet<'_>, Skip> {
    match family {
        2 => ipv4(rest),
        // AF_INET6 differs between systems: BSD and Linux, Darwin, FreeBSD.
        10 | 24 | 28 | 30 => ipv6(rest),
        _ => Err(Skip::Other),
    }
}

fn by_version(rest: &[u8]) -> Result<Packet<'_>, Skip> {
    match rest.first().map(|b| b >> 4) {
        Some(4) => ipv4(rest),
        Some(6) => ipv6(rest),
        Some(_) => Err(Skip::Other),
        None => Err(Skip::Malformed),
    }
}

fn by_ethertype(kind: u16, rest: &[u8]) -> Result<Packet<'_>, Skip> {
    match kind {
        ETHERTYPE_IPV4 => ipv4(rest),
        ETHERTYPE_IPV6 => ipv6(rest),
        _ => Err(Skip::Other),
    }
}

fn ethernet(frame: &[u8]) -> Result<Packet<'_>, Skip> {
    let head = frame.get(..14).ok_or(Skip::Malformed)?;
    let mut kind = be16(&head[12..]);
    let mut rest = &frame[14..];
    for _ in 0..MAX_HEADERS {
        if !matches!(kind, 0x8100 | 0x88a8 | 0x9100) {
            break;
        }
        let tag = rest.get(..4).ok_or(Skip::Malformed)?;
        kind = be16(&tag[2..]);
        rest = &rest[4..];
    }
    by_ethertype(kind, rest)
}

fn ipv4(data: &[u8]) -> Result<Packet<'_>, Skip> {
    let head = data.get(..20).ok_or(Skip::Malformed)?;
    if head[0] >> 4 != 4 {
        return Err(Skip::Malformed);
    }
    let header = usize::from(head[0] & 0x0f) * 4;
    let total = usize::from(be16(&head[2..]));
    if header < 20 || total < header || data.len() < header {
        return Err(Skip::Malformed);
    }
    let flags = be16(&head[6..]);
    if flags & 0x3fff != 0 {
        return Err(Skip::Fragment);
    }
    // Ethernet pads short frames, so the IP length decides where the packet ends. A capture cut
    // short by a snap length ends sooner.
    let body = &data[header..total.min(data.len())];
    let src = IpAddr::V4(Ipv4Addr::new(head[12], head[13], head[14], head[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(head[16], head[17], head[18], head[19]));
    transport(head[9], src, dst, body)
}

fn ipv6(data: &[u8]) -> Result<Packet<'_>, Skip> {
    let head = data.get(..40).ok_or(Skip::Malformed)?;
    if head[0] >> 4 != 6 {
        return Err(Skip::Malformed);
    }
    let payload = usize::from(be16(&head[4..]));
    let mut body = &data[40..(40 + payload).min(data.len())];
    let mut next = head[6];
    let addr = |b: &[u8]| {
        let mut a = [0u8; 16];
        a.copy_from_slice(b);
        IpAddr::V6(Ipv6Addr::from(a))
    };
    let (src, dst) = (addr(&head[8..24]), addr(&head[24..40]));
    for _ in 0..MAX_HEADERS {
        match next {
            // Hop-by-hop, routing and destination options share a layout.
            0 | 43 | 60 => {
                let ext = body.get(..2).ok_or(Skip::Malformed)?;
                let len = (usize::from(ext[1]) + 1) * 8;
                next = ext[0];
                body = body.get(len..).ok_or(Skip::Malformed)?;
            }
            44 => return Err(Skip::Fragment),
            _ => return transport(next, src, dst, body),
        }
    }
    Err(Skip::Other)
}

fn transport(proto: u8, src: IpAddr, dst: IpAddr, body: &[u8]) -> Result<Packet<'_>, Skip> {
    match proto {
        PROTO_TCP => {
            let head = body.get(..20).ok_or(Skip::Malformed)?;
            let offset = usize::from(head[12] >> 4) * 4;
            if offset < 20 {
                return Err(Skip::Malformed);
            }
            let payload = body.get(offset..).ok_or(Skip::Malformed)?;
            Ok(Packet {
                src,
                dst,
                src_port: be16(head),
                dst_port: be16(&head[2..]),
                transport: Transport::Tcp {
                    seq: u32::from_be_bytes([head[4], head[5], head[6], head[7]]),
                    syn: head[13] & 0x02 != 0,
                    ack: head[13] & 0x10 != 0,
                    rst: head[13] & 0x04 != 0,
                    payload,
                },
            })
        }
        PROTO_UDP => {
            let head = body.get(..8).ok_or(Skip::Malformed)?;
            let len = usize::from(be16(&head[4..]));
            if len < 8 {
                return Err(Skip::Malformed);
            }
            Ok(Packet {
                src,
                dst,
                src_port: be16(head),
                dst_port: be16(&head[2..]),
                transport: Transport::Udp {
                    payload: &body[8..len.min(body.len())],
                },
            })
        }
        _ => Err(Skip::Other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp(payload: &[u8]) -> Vec<u8> {
        let mut t = vec![
            0x12, 0x34, 0x01, 0xbb, 0, 0, 0, 9, 0, 0, 0, 0, 0x60, 0x12, 0, 0, 0, 0, 0, 0,
        ];
        t.extend_from_slice(&[1, 1, 1, 1]); // four bytes of options
        t.extend_from_slice(payload);
        t
    }

    fn udp(payload: &[u8]) -> Vec<u8> {
        let mut u = vec![0x12, 0x34, 0x01, 0xbb];
        u.extend_from_slice(&((payload.len() + 8) as u16).to_be_bytes());
        u.extend_from_slice(&[0, 0]);
        u.extend_from_slice(payload);
        u
    }

    fn v4(proto: u8, body: &[u8]) -> Vec<u8> {
        let mut h = vec![0x45, 0];
        h.extend_from_slice(&((body.len() + 20) as u16).to_be_bytes());
        h.extend_from_slice(&[
            0, 0, 0x40, 0, 64, proto, 0, 0, 192, 0, 2, 1, 198, 51, 100, 7,
        ]);
        h.extend_from_slice(body);
        h
    }

    fn v6(next: u8, body: &[u8]) -> Vec<u8> {
        let mut h = vec![0x60, 0, 0, 0];
        h.extend_from_slice(&(body.len() as u16).to_be_bytes());
        h.extend_from_slice(&[next, 64]);
        h.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        h.extend_from_slice(&[0; 11]);
        h.push(1);
        h.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        h.extend_from_slice(&[0; 11]);
        h.push(2);
        h.extend_from_slice(body);
        h
    }

    fn eth(kind: u16, body: &[u8]) -> Vec<u8> {
        let mut e = vec![0; 12];
        e.extend_from_slice(&kind.to_be_bytes());
        e.extend_from_slice(body);
        e
    }

    fn payload_of<'a>(p: &'a Packet<'a>) -> &'a [u8] {
        match p.transport {
            Transport::Tcp { payload, .. } | Transport::Udp { payload } => payload,
        }
    }

    #[test]
    fn tcp_over_ipv4_over_ethernet() {
        let frame = eth(0x0800, &v4(6, &tcp(b"hello")));
        let p = parse(1, &frame).unwrap();
        assert_eq!(p.src.to_string(), "192.0.2.1");
        assert_eq!(p.dst.to_string(), "198.51.100.7");
        assert_eq!((p.src_port, p.dst_port), (0x1234, 443));
        assert_eq!(
            p.transport,
            Transport::Tcp {
                seq: 9,
                syn: true,
                ack: true,
                rst: false,
                payload: b"hello"
            }
        );
    }

    #[test]
    fn udp_over_ipv6_through_extension_headers() {
        // Hop-by-hop (8 bytes), then destination options (16 bytes), then UDP.
        let mut body = vec![60, 0, 0, 0, 0, 0, 0, 0];
        body.extend_from_slice(&[17, 1]);
        body.extend_from_slice(&[0; 14]);
        body.extend(udp(b"quic"));
        let frame = eth(0x86dd, &v6(0, &body));
        let p = parse(1, &frame).unwrap();
        assert_eq!(p.dst.to_string(), "2001:db8::2");
        assert_eq!(p.transport, Transport::Udp { payload: b"quic" });
    }

    #[test]
    fn every_link_type_reaches_the_payload() {
        let ip = v4(17, &udp(b"x"));
        let ip6 = v6(17, &udp(b"x"));
        let mut cases: Vec<(u32, Vec<u8>)> = vec![
            (1, eth(0x0800, &ip)),
            (101, ip.clone()),
            (12, ip6.clone()),
            (14, ip.clone()),
            (228, ip.clone()),
            (229, ip6.clone()),
            (0, [2u32.to_le_bytes().to_vec(), ip.clone()].concat()),
            (0, [2u32.to_be_bytes().to_vec(), ip.clone()].concat()),
            (0, [30u32.to_le_bytes().to_vec(), ip6.clone()].concat()),
            (0, [28u32.to_le_bytes().to_vec(), ip6.clone()].concat()),
            (0, [24u32.to_be_bytes().to_vec(), ip6.clone()].concat()),
            (0, [10u32.to_le_bytes().to_vec(), ip6.clone()].concat()),
            (108, [2u32.to_be_bytes().to_vec(), ip.clone()].concat()),
            (108, [30u32.to_be_bytes().to_vec(), ip6.clone()].concat()),
        ];
        let mut sll = vec![0; 14];
        sll.extend_from_slice(&0x0800u16.to_be_bytes());
        cases.push((113, [sll, ip.clone()].concat()));
        let mut sll2 = 0x86ddu16.to_be_bytes().to_vec();
        sll2.extend_from_slice(&[0; 18]);
        cases.push((276, [sll2, ip6].concat()));
        for (link, frame) in cases {
            let p = parse(link, &frame).unwrap_or_else(|e| panic!("link {link}: {e:?}"));
            assert_eq!(payload_of(&p), b"x", "link {link}");
        }
    }

    #[test]
    fn stacked_vlan_tags() {
        let mut inner = vec![0, 1];
        inner.extend_from_slice(&0x8100u16.to_be_bytes());
        inner.extend_from_slice(&[0, 2, 0x08, 0x00]);
        inner.extend(v4(6, &tcp(b"v")));
        let frame = eth(0x88a8, &inner);
        assert_eq!(payload_of(&parse(1, &frame).unwrap()), b"v");
        let mut one = vec![0, 1, 0x08, 0x00];
        one.extend(v4(6, &tcp(b"w")));
        assert_eq!(payload_of(&parse(1, &eth(0x9100, &one)).unwrap()), b"w");
        // Tags without end are not followed for ever.
        let mut endless = Vec::new();
        for _ in 0..20 {
            endless.extend_from_slice(&[0, 1, 0x81, 0x00]);
        }
        assert_eq!(parse(1, &eth(0x8100, &endless)), Err(Skip::Other));
    }

    #[test]
    fn ethernet_padding_is_not_payload_and_a_snap_length_is_not_an_error() {
        let mut frame = eth(0x0800, &v4(6, &tcp(b"ab")));
        frame.extend_from_slice(&[0; 6]);
        assert_eq!(payload_of(&parse(1, &frame).unwrap()), b"ab");
        let mut udp_frame = eth(0x0800, &v4(17, &udp(b"ab")));
        udp_frame.extend_from_slice(&[0; 6]);
        assert_eq!(payload_of(&parse(1, &udp_frame).unwrap()), b"ab");
        let long = eth(0x0800, &v4(6, &tcp(b"abcdefgh")));
        assert_eq!(
            payload_of(&parse(1, &long[..long.len() - 4]).unwrap()),
            b"abcd"
        );
        let long = eth(0x0800, &v4(17, &udp(b"abcdefgh")));
        assert_eq!(
            payload_of(&parse(1, &long[..long.len() - 4]).unwrap()),
            b"abcd"
        );
    }

    #[test]
    fn length_fields_end_the_payload_before_the_frame_does() {
        // Trailing bytes after an IPv6 packet are not TCP payload.
        let mut frame = eth(0x86dd, &v6(6, &tcp(b"ab")));
        frame.extend_from_slice(&[0; 6]);
        assert_eq!(payload_of(&parse(1, &frame).unwrap()), b"ab");
        // A UDP length shorter than what IP says is there decides.
        let mut datagram = udp(b"abcd");
        datagram[4..6].copy_from_slice(&10u16.to_be_bytes());
        assert_eq!(payload_of(&parse(101, &v4(17, &datagram)).unwrap()), b"ab");
    }

    #[test]
    fn fragments_are_reported() {
        let mut more = v4(6, &tcp(b"a"));
        more[6] = 0x20; // more fragments
        assert_eq!(parse(101, &more), Err(Skip::Fragment));
        let mut later = v4(6, &tcp(b"a"));
        later[6] = 0;
        later[7] = 8; // a fragment offset
        assert_eq!(parse(101, &later), Err(Skip::Fragment));
        // Don't-fragment alone is not a fragment.
        let mut df = v4(6, &tcp(b"a"));
        df[6] = 0x40;
        assert!(parse(101, &df).is_ok());
        assert_eq!(parse(229, &v6(44, &[0; 16])), Err(Skip::Fragment));
    }

    #[test]
    fn nonsense_headers_are_malformed_not_panics() {
        let good = eth(0x0800, &v4(6, &tcp(b"abc")));
        for n in 0..good.len() - 3 {
            let r = parse(1, &good[..n]);
            assert!(r.is_err() || n >= 14 + 20 + 24, "{n}: {r:?}");
        }
        let good6 = v6(17, &udp(b"abc"));
        for n in 0..40 + 8 {
            assert_eq!(parse(229, &good6[..n]), Err(Skip::Malformed), "{n}");
        }
        let mut short_ihl = v4(6, &tcp(b"a"));
        short_ihl[0] = 0x44;
        assert_eq!(parse(101, &short_ihl), Err(Skip::Malformed));
        let mut wrong_version = v4(6, &tcp(b"a"));
        wrong_version[0] = 0x65;
        assert_eq!(parse(228, &wrong_version), Err(Skip::Malformed));
        assert_eq!(
            parse(229, &v4(6, &tcp(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))),
            Err(Skip::Malformed)
        );
        let mut small_total = v4(6, &tcp(b"a"));
        small_total[2..4].copy_from_slice(&10u16.to_be_bytes());
        assert_eq!(parse(101, &small_total), Err(Skip::Malformed));
        let mut small_offset = tcp(b"a");
        small_offset[12] = 0x40;
        assert_eq!(parse(101, &v4(6, &small_offset)), Err(Skip::Malformed));
        let mut big_offset = tcp(b"a");
        big_offset[12] = 0xf0;
        assert_eq!(parse(101, &v4(6, &big_offset)), Err(Skip::Malformed));
        let mut small_udp = udp(b"a");
        small_udp[4..6].copy_from_slice(&3u16.to_be_bytes());
        assert_eq!(parse(101, &v4(17, &small_udp)), Err(Skip::Malformed));
        assert_eq!(
            parse(229, &v6(0, &[17, 200, 0, 0, 0, 0, 0, 0])),
            Err(Skip::Malformed)
        );
    }

    #[test]
    fn things_that_are_not_tcp_or_udp_are_skipped() {
        assert_eq!(parse(1, &eth(0x0806, &[0; 28])), Err(Skip::Other), "ARP");
        assert_eq!(parse(101, &v4(1, &[8, 0, 0, 0])), Err(Skip::Other), "ICMP");
        assert_eq!(parse(9999, &[0; 40]), Err(Skip::Other), "unknown link type");
        assert_eq!(parse(101, &[0x10; 20]), Err(Skip::Other), "not IP");
        assert_eq!(parse(101, &[]), Err(Skip::Malformed));
        assert_eq!(
            parse(108, &[0, 0, 0, 99, 1]),
            Err(Skip::Other),
            "unknown family"
        );
        assert_eq!(parse(0, &[1]), Err(Skip::Malformed));
        assert_eq!(parse(108, &[1]), Err(Skip::Malformed));
        assert_eq!(parse(113, &[1; 15]), Err(Skip::Malformed));
        assert_eq!(parse(276, &[1; 19]), Err(Skip::Malformed));
    }
}
