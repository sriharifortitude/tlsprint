//! Reads client Initial packets. QUIC encrypts its ClientHello, but with keys derived only from
//! values in the packet (RFC 9001 section 5.2), so anyone on the path can read it, and JA4 does.

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

const VERSION_1: u32 = 0x0000_0001;
const VERSION_2: u32 = 0x6b33_43cf;
const SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];
const MAX_CID: usize = 20;

struct VersionRules {
    salt: &'static [u8; 20],
    key_label: &'static [u8],
    iv_label: &'static [u8],
    hp_label: &'static [u8],
    initial_type: u8,
    retry_type: u8,
}

fn rules(version: u32) -> Option<VersionRules> {
    match version {
        VERSION_1 => Some(VersionRules {
            salt: &SALT_V1,
            key_label: b"quic key",
            iv_label: b"quic iv",
            hp_label: b"quic hp",
            initial_type: 0,
            retry_type: 3,
        }),
        VERSION_2 => Some(VersionRules {
            salt: &SALT_V2,
            key_label: b"quicv2 key",
            iv_label: b"quicv2 iv",
            hp_label: b"quicv2 hp",
            initial_type: 1,
            retry_type: 0,
        }),
        _ => None,
    }
}

/// A variable-length integer (RFC 9000 section 16) and the bytes after it.
fn varint(data: &[u8]) -> Option<(u64, &[u8])> {
    let first = *data.first()?;
    let len = 1usize << (first >> 6);
    let bytes = data.get(..len)?;
    let mut v = u64::from(first & 0x3f);
    for b in &bytes[1..] {
        v = v << 8 | u64::from(*b);
    }
    Some((v, &data[len..]))
}

/// One long-header packet from a datagram.
#[derive(Debug, PartialEq, Eq)]
pub struct LongPacket<'a> {
    pub version: u32,
    pub initial: bool,
    pub dcid: &'a [u8],
    /// The whole packet: header, protected packet number and payload.
    pub bytes: &'a [u8],
    /// Where the protected packet number starts.
    pub pn_offset: usize,
}

/// Whether a UDP payload starts with a long header of a version this can read.
pub fn looks_like_initial(data: &[u8]) -> bool {
    data.len() >= 5
        && data[0] & 0xc0 == 0xc0
        && rules(u32::from_be_bytes([data[1], data[2], data[3], data[4]])).is_some()
}

/// Splits off the first packet of a datagram, which can coalesce several. None when it is not a
/// long-header packet of a known version, is cut short, or has no length field to find its end by.
pub fn next_packet(data: &[u8]) -> Option<(LongPacket<'_>, &[u8])> {
    if !looks_like_initial(data) {
        return None;
    }
    let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    let rules = rules(version)?;
    let kind = (data[0] >> 4) & 3;
    if kind == rules.retry_type {
        return None;
    }
    let initial = kind == rules.initial_type;
    let mut at = 5;
    let dcid_len = usize::from(*data.get(at)?);
    if dcid_len > MAX_CID {
        return None;
    }
    let dcid = data.get(at + 1..at + 1 + dcid_len)?;
    at += 1 + dcid_len;
    let scid_len = usize::from(*data.get(at)?);
    if scid_len > MAX_CID {
        return None;
    }
    at += 1 + scid_len;
    let mut rest = data.get(at..)?;
    if initial {
        let (token_len, after) = varint(rest)?;
        rest = after.get(usize::try_from(token_len).ok()?..)?;
    }
    let (length, after) = varint(rest)?;
    let pn_offset = data.len() - after.len();
    let end = pn_offset.checked_add(usize::try_from(length).ok()?)?;
    let bytes = data.get(..end)?;
    Some((
        LongPacket {
            version,
            initial,
            dcid,
            bytes,
            pn_offset,
        },
        &data[end..],
    ))
}

fn expand_label(secret: &[u8], label: &[u8], out: &mut [u8]) -> Option<()> {
    let hk = Hkdf::<Sha256>::from_prk(secret).ok()?;
    let mut info = Vec::with_capacity(4 + 6 + label.len());
    info.extend_from_slice(&u16::try_from(out.len()).ok()?.to_be_bytes());
    info.push(u8::try_from(6 + label.len()).ok()?);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0);
    hk.expand(&info, out).ok()
}

/// Removes the protection from a client Initial and returns its frames. `key_dcid` is the
/// connection ID the keys come from: the one in the client's first packet. None for anything that
/// does not authenticate, which is what a server's Initial or a corrupt packet does.
pub fn decrypt_client_initial(packet: &LongPacket<'_>, key_dcid: &[u8]) -> Option<Vec<u8>> {
    let rules = rules(packet.version)?;
    let (prk, _) = Hkdf::<Sha256>::extract(Some(rules.salt.as_slice()), key_dcid);
    let mut secret = [0u8; 32];
    expand_label(prk.as_slice(), b"client in", &mut secret)?;
    let (mut key, mut iv, mut hp) = ([0u8; 16], [0u8; 12], [0u8; 16]);
    expand_label(&secret, rules.key_label, &mut key)?;
    expand_label(&secret, rules.iv_label, &mut iv)?;
    expand_label(&secret, rules.hp_label, &mut hp)?;

    let pn_offset = packet.pn_offset;
    let sample = packet.bytes.get(pn_offset + 4..pn_offset + 20)?;
    let mut mask = GenericArray::clone_from_slice(sample);
    Aes128::new_from_slice(&hp).ok()?.encrypt_block(&mut mask);

    let first = packet.bytes[0] ^ (mask[0] & 0x0f);
    let pn_len = usize::from(first & 0x03) + 1;
    let mut header = packet.bytes.get(..pn_offset + pn_len)?.to_vec();
    header[0] = first;
    let mut nonce = iv;
    for i in 0..pn_len {
        let pn_byte = header[pn_offset + i] ^ mask[1 + i];
        header[pn_offset + i] = pn_byte;
        nonce[12 - pn_len + i] ^= pn_byte;
    }
    let cipher = Aes128Gcm::new_from_slice(&key).ok()?;
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &packet.bytes[pn_offset + pn_len..],
                aad: &header,
            },
        )
        .ok()
}

/// The CRYPTO frames in decrypted Initial frames, as (offset, data). A client's Initial can only
/// hold a few kinds of frame; anything else ends the walk, keeping what came before.
pub fn crypto_frames(mut frames: &[u8]) -> Vec<(u64, &[u8])> {
    let mut out = Vec::new();
    while let Some(next) = next_frame(frames, &mut out) {
        frames = next;
    }
    out
}

fn next_frame<'a>(frames: &'a [u8], out: &mut Vec<(u64, &'a [u8])>) -> Option<&'a [u8]> {
    let (kind, mut rest) = varint(frames)?;
    match kind {
        0x00 | 0x01 => Some(rest), // PADDING, PING
        0x02 | 0x03 => {
            // ACK: largest, delay, range count, first range, then the ranges and maybe ECN counts.
            let (_, r) = varint(rest)?;
            let (_, r) = varint(r)?;
            let (count, r) = varint(r)?;
            let (_, mut r) = varint(r)?;
            for _ in 0..count {
                let (_, a) = varint(r)?;
                let (_, b) = varint(a)?;
                r = b;
            }
            if kind == 0x03 {
                for _ in 0..3 {
                    let (_, a) = varint(r)?;
                    r = a;
                }
            }
            Some(r)
        }
        0x06 => {
            let (offset, r) = varint(rest)?;
            let (len, r) = varint(r)?;
            let data = r.get(..usize::try_from(len).ok()?)?;
            out.push((offset, data));
            Some(&r[data.len()..])
        }
        0x1c => {
            // CONNECTION_CLOSE: error code, frame type, reason.
            for _ in 0..2 {
                let (_, r) = varint(rest)?;
                rest = r;
            }
            let (len, r) = varint(rest)?;
            r.get(usize::try_from(len).ok()?..)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ja4::{Fingerprint, Protocol};
    use crate::tls::parse_client_hello;

    fn vector(text: &str) -> Vec<u8> {
        let hex: String = text.split_whitespace().collect();
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn rfc9001() -> Vec<u8> {
        vector(include_str!("../testdata/rfc9001-client-initial.hex"))
    }

    fn rfc9369() -> Vec<u8> {
        vector(include_str!("../testdata/rfc9369-client-initial.hex"))
    }

    /// The CRYPTO frame the RFCs print for this packet, which starts with the frame header.
    const RFC_CRYPTO: &str = "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868\
        04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578\
        616d706c652e636f6dff01000100000a00080006001d00170018001000070005\
        04616c706e0005000501000000000033002600 24001d00209370b2c9caa47fba\
        baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400\
        0d0010000e0403050306030203080408050806002d00020101001c0002400100\
        3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000\
        75300901100f088394c8f03e51570806048000ffff";

    #[test]
    fn varints_from_rfc_9000_appendix_a() {
        assert_eq!(
            varint(&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]),
            Some((151_288_809_941_952_652, &[][..]))
        );
        assert_eq!(
            varint(&[0x9d, 0x7f, 0x3e, 0x7d]),
            Some((494_878_333, &[][..]))
        );
        assert_eq!(varint(&[0x7b, 0xbd]), Some((15_293, &[][..])));
        assert_eq!(varint(&[0x25, 0xff]), Some((37, &[0xff][..])));
        assert_eq!(varint(&[]), None);
        assert_eq!(varint(&[0x40]), None);
    }

    #[test]
    fn the_rfc_9001_client_initial_decrypts_to_its_printed_contents() {
        let data = rfc9001();
        let (packet, rest) = next_packet(&data).unwrap();
        assert!(rest.is_empty());
        assert!(packet.initial);
        assert_eq!(packet.dcid, vector("8394c8f03e515708"));
        assert_eq!(packet.pn_offset, 18);
        let frames = decrypt_client_initial(&packet, packet.dcid).unwrap();
        assert_eq!(frames.len(), 1162);
        let want = vector(RFC_CRYPTO);
        assert_eq!(&frames[..want.len()], want.as_slice());
        assert!(
            frames[want.len()..].iter().all(|b| *b == 0),
            "the rest is PADDING"
        );
    }

    #[test]
    fn the_rfc_9369_client_initial_decrypts_under_the_v2_rules() {
        let data = rfc9369();
        let (packet, _) = next_packet(&data).unwrap();
        assert_eq!(packet.version, VERSION_2);
        assert!(packet.initial);
        let frames = decrypt_client_initial(&packet, packet.dcid).unwrap();
        let want = vector(RFC_CRYPTO);
        assert_eq!(&frames[..want.len()], want.as_slice());
    }

    #[test]
    fn the_rfc_packet_gives_the_hello_inside_it() {
        let data = rfc9001();
        let (packet, _) = next_packet(&data).unwrap();
        let frames = decrypt_client_initial(&packet, packet.dcid).unwrap();
        let crypto = crypto_frames(&frames);
        assert_eq!(crypto.len(), 1);
        assert_eq!((crypto[0].0, crypto[0].1.len()), (0, 241));
        let hello = parse_client_hello(&crypto[0].1[4..], false).unwrap();
        assert_eq!(hello.server_name.as_deref(), Some(&b"example.com"[..]));
        assert_eq!(hello.alpn_first.as_deref(), Some(&b"alpn"[..]));
        assert_eq!(hello.ciphers, [0x1301, 0x1302]);
        assert!(Fingerprint::of(&hello, Protocol::Quic)
            .ja4
            .starts_with("q13d0211an_"));
    }

    #[test]
    fn a_changed_byte_or_the_wrong_keys_do_not_authenticate() {
        let mut data = rfc9001();
        let (packet, _) = next_packet(&data).unwrap();
        assert!(decrypt_client_initial(&packet, b"other").is_none());
        let last = data.len() - 1;
        data[last] ^= 1;
        let (packet, _) = next_packet(&data).unwrap();
        assert!(decrypt_client_initial(&packet, packet.dcid).is_none());
    }

    #[test]
    fn a_packet_too_short_for_its_sample_is_refused() {
        let mut p = vec![0xc0, 0, 0, 0, 1, 1, 9, 0, 0, 5];
        p.extend_from_slice(&[0; 5]);
        let (packet, _) = next_packet(&p).unwrap();
        assert!(decrypt_client_initial(&packet, packet.dcid).is_none());
    }

    #[test]
    fn coalesced_packets_are_walked_and_other_types_marked() {
        let handshake = [0xe0, 0, 0, 0, 1, 0, 0, 2, 7, 7];
        let data = [handshake.to_vec(), rfc9001()].concat();
        let (first, rest) = next_packet(&data).unwrap();
        assert!(!first.initial);
        assert_eq!(first.bytes.len(), handshake.len());
        let (second, rest) = next_packet(rest).unwrap();
        assert!(second.initial && rest.is_empty());
    }

    #[test]
    fn what_next_packet_refuses() {
        let good = rfc9001();
        for n in 0..good.len() {
            assert!(next_packet(&good[..n]).is_none(), "cut at {n}");
        }
        assert!(next_packet(&[0x40; 40]).is_none(), "short header");
        assert!(
            next_packet(&[0xc0, 0, 0, 0, 2, 0, 0, 0, 0]).is_none(),
            "unknown version"
        );
        let mut dcid = vec![0xc0, 0, 0, 0, 1, 21];
        dcid.extend_from_slice(&[0; 40]);
        assert!(next_packet(&dcid).is_none(), "destination ID too long");
        let mut scid = vec![0xc0, 0, 0, 0, 1, 0, 21];
        scid.extend_from_slice(&[0; 40]);
        assert!(next_packet(&scid).is_none(), "source ID too long");
        assert!(
            next_packet(&[0xf0, 0, 0, 0, 1, 0, 0, 1, 2, 3]).is_none(),
            "v1 Retry has no length"
        );
        assert!(
            next_packet(&[0xc0, 0x6b, 0x33, 0x43, 0xcf, 0, 0, 1, 2, 3]).is_none(),
            "v2 Retry has no length"
        );
        assert!(
            next_packet(&[0xc0, 0, 0, 0, 1, 0, 0, 0x3f, 0]).is_none(),
            "token past the end"
        );
    }

    #[test]
    fn frames_a_client_initial_can_hold() {
        // PADDING, PING, ACK with a range, ACK with ECN, CONNECTION_CLOSE, then CRYPTO.
        let frames = [
            &[0x00, 0x01][..],
            &[0x02, 5, 0, 1, 0, 1, 1],
            &[0x03, 5, 0, 0, 0, 1, 2, 3],
            &[0x1c, 0, 0, 2, b'n', b'o'],
            &[0x06, 0x05, 0x02, b'a', b'b'],
        ]
        .concat();
        assert_eq!(crypto_frames(&frames), vec![(5, &b"ab"[..])]);
    }

    #[test]
    fn a_frame_it_does_not_expect_ends_the_walk_keeping_earlier_ones() {
        let frames = [0x06, 0, 1, b'a', 0x07, 0x06, 0, 1, b'b'];
        assert_eq!(crypto_frames(&frames), vec![(0, &b"a"[..])]);
        for cut in [
            &[0x06, 0][..],
            &[0x06, 0, 5, b'a'],
            &[0x02, 0],
            &[0x02, 0, 0, 3, 0],
            &[0x03, 0, 0, 0, 0, 1],
            &[0x1c, 0],
            &[0x1c, 0, 0, 9],
        ] {
            assert!(crypto_frames(cut).is_empty(), "{cut:?}");
        }
    }
}
