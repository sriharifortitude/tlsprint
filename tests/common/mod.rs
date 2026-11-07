//! Builds hellos, packets and capture files byte by byte, for the tests and for the demo capture.
#![allow(dead_code)]

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

pub const CLIENT: [u8; 4] = [192, 0, 2, 10];
pub const SERVER: [u8; 4] = [198, 51, 100, 7];

pub struct HelloSpec<'a> {
    pub version: u16,
    pub ciphers: &'a [u16],
    /// Extensions with no contents worth reading.
    pub plain_extensions: &'a [u16],
    pub sni: Option<&'a str>,
    pub alpn: &'a [&'a str],
    pub signatures: &'a [u16],
    pub supported_versions: &'a [u16],
}

/// The ClientHello worked through in FoxIO's specification.
pub fn spec_hello() -> Vec<u8> {
    hello_body(
        &HelloSpec {
            version: 0x0303,
            ciphers: &[
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            plain_extensions: &[
                0x001b, 0x0033, 0x4469, 0x0017, 0x002d, 0x0005, 0x0023, 0x0012, 0xff01, 0x000b,
                0x000a, 0x0015,
            ],
            sni: Some("www.example.org"),
            alpn: &["h2", "http/1.1"],
            signatures: &[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ],
            supported_versions: &[0x0304, 0x0303],
        },
        false,
    )
}
pub const SPEC_JA4: &str = "t13d1516h2_8daaf6152771_e5627efa2ab1";

pub fn hello_body(spec: &HelloSpec<'_>, dtls: bool) -> Vec<u8> {
    let mut b = spec.version.to_be_bytes().to_vec();
    b.extend_from_slice(&[0x42; 32]);
    b.push(0); // session id
    if dtls {
        b.push(0); // cookie
    }
    b.extend_from_slice(&((spec.ciphers.len() * 2) as u16).to_be_bytes());
    for c in spec.ciphers {
        b.extend_from_slice(&c.to_be_bytes());
    }
    b.extend_from_slice(&[1, 0]);
    let mut exts = Vec::new();
    let mut push = |kind: u16, data: &[u8]| {
        exts.extend_from_slice(&kind.to_be_bytes());
        exts.extend_from_slice(&(data.len() as u16).to_be_bytes());
        exts.extend_from_slice(data);
    };
    for e in spec.plain_extensions {
        push(*e, &[]);
    }
    if let Some(name) = spec.sni {
        let n = name.as_bytes();
        let mut v = ((n.len() + 3) as u16).to_be_bytes().to_vec();
        v.push(0);
        v.extend_from_slice(&(n.len() as u16).to_be_bytes());
        v.extend_from_slice(n);
        push(0, &v);
    }
    if !spec.alpn.is_empty() {
        let mut list = Vec::new();
        for a in spec.alpn {
            list.push(a.len() as u8);
            list.extend_from_slice(a.as_bytes());
        }
        let mut v = (list.len() as u16).to_be_bytes().to_vec();
        v.extend(list);
        push(0x10, &v);
    }
    if !spec.signatures.is_empty() {
        let mut v = ((spec.signatures.len() * 2) as u16).to_be_bytes().to_vec();
        for s in spec.signatures {
            v.extend_from_slice(&s.to_be_bytes());
        }
        push(0x0d, &v);
    }
    if !spec.supported_versions.is_empty() {
        let mut v = vec![(spec.supported_versions.len() * 2) as u8];
        for s in spec.supported_versions {
            v.extend_from_slice(&s.to_be_bytes());
        }
        push(0x2b, &v);
    }
    b.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    b.extend(exts);
    b
}

pub fn handshake(body: &[u8]) -> Vec<u8> {
    let n = body.len();
    let mut m = vec![1, (n >> 16) as u8, (n >> 8) as u8, n as u8];
    m.extend_from_slice(body);
    m
}

pub fn record(payload: &[u8]) -> Vec<u8> {
    let mut r = vec![22, 3, 1];
    r.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    r.extend_from_slice(payload);
    r
}

/// A DTLS 1.2 record holding one fragment of a ClientHello.
pub fn dtls_record(message_seq: u16, total: usize, offset: usize, data: &[u8]) -> Vec<u8> {
    let be24 = |v: usize| [(v >> 16) as u8, (v >> 8) as u8, v as u8];
    let mut h = vec![1];
    h.extend_from_slice(&be24(total));
    h.extend_from_slice(&message_seq.to_be_bytes());
    h.extend_from_slice(&be24(offset));
    h.extend_from_slice(&be24(data.len()));
    h.extend_from_slice(data);
    let mut r = vec![22, 0xfe, 0xff, 0, 0, 0, 0, 0, 0, 0, message_seq as u8];
    r.extend_from_slice(&(h.len() as u16).to_be_bytes());
    r.extend(h);
    r
}

fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, body: &[u8]) -> Vec<u8> {
    let mut f = vec![0u8; 12];
    f.extend_from_slice(&[0x08, 0x00, 0x45, 0]);
    f.extend_from_slice(&((body.len() + 20) as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0, 0x40, 0, 64, proto, 0, 0]);
    f.extend_from_slice(&src);
    f.extend_from_slice(&dst);
    f.extend_from_slice(body);
    f
}

pub const FLAG_SYN: u8 = 0x02;
pub const FLAG_RST: u8 = 0x04;
pub const FLAG_ACK: u8 = 0x10;

/// An Ethernet frame of TCP over IPv4.
pub fn tcp_frame(
    src: ([u8; 4], u16),
    dst: ([u8; 4], u16),
    seq: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut t = src.1.to_be_bytes().to_vec();
    t.extend_from_slice(&dst.1.to_be_bytes());
    t.extend_from_slice(&seq.to_be_bytes());
    t.extend_from_slice(&[0, 0, 0, 0, 0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
    t.extend_from_slice(payload);
    ipv4(src.0, dst.0, 6, &t)
}

/// An Ethernet frame of UDP over IPv4.
pub fn udp_frame(src: ([u8; 4], u16), dst: ([u8; 4], u16), payload: &[u8]) -> Vec<u8> {
    let mut u = src.1.to_be_bytes().to_vec();
    u.extend_from_slice(&dst.1.to_be_bytes());
    u.extend_from_slice(&((payload.len() + 8) as u16).to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(payload);
    ipv4(src.0, dst.0, 17, &u)
}

/// A classic little-endian pcap of Ethernet frames, one second apart.
pub fn pcap(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut out = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    for (i, f) in frames.iter().enumerate() {
        out.extend_from_slice(&(1_700_000_000 + i as u32).to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&(f.len() as u32).to_le_bytes());
        out.extend_from_slice(&(f.len() as u32).to_le_bytes());
        out.extend_from_slice(f);
    }
    out
}

fn expand(secret: &[u8], label: &[u8], out: &mut [u8]) {
    let hk = Hkdf::<Sha256>::from_prk(secret).unwrap();
    let mut info = (out.len() as u16).to_be_bytes().to_vec();
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0);
    hk.expand(&info, out).unwrap();
}

/// A protected QUIC v1 client Initial: `frames` sealed under keys from `key_dcid`, sent to `dcid`.
pub fn quic_initial(dcid: &[u8], key_dcid: &[u8], packet_number: u8, frames: &[u8]) -> Vec<u8> {
    let salt = [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
        0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ];
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt.as_slice()), key_dcid);
    let mut secret = [0u8; 32];
    expand(prk.as_slice(), b"client in", &mut secret);
    let (mut key, mut iv, mut hp) = ([0u8; 16], [0u8; 12], [0u8; 16]);
    expand(&secret, b"quic key", &mut key);
    expand(&secret, b"quic iv", &mut iv);
    expand(&secret, b"quic hp", &mut hp);

    // A one-byte packet number; padding keeps the packet long enough to sample.
    let mut plain = frames.to_vec();
    plain.resize(plain.len().max(20), 0);
    let length = 1 + plain.len() + 16;
    let mut header = vec![0xc0, 0, 0, 0, 1, dcid.len() as u8];
    header.extend_from_slice(dcid);
    header.extend_from_slice(&[0, 0]); // no source ID, no token
    header.extend_from_slice(&(0x4000u16 | length as u16).to_be_bytes());
    let pn_offset = header.len();
    header.push(packet_number);
    let mut nonce = iv;
    nonce[11] ^= packet_number;
    let sealed = Aes128Gcm::new_from_slice(&key)
        .unwrap()
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plain,
                aad: &header,
            },
        )
        .unwrap();
    let mut mask = GenericArray::clone_from_slice(&sealed[3..19]);
    Aes128::new_from_slice(&hp)
        .unwrap()
        .encrypt_block(&mut mask);
    header[0] ^= mask[0] & 0x0f;
    header[pn_offset] ^= mask[1];
    header.extend(sealed);
    header
}

/// A CRYPTO frame with two-byte varints.
pub fn crypto_frame(offset: usize, data: &[u8]) -> Vec<u8> {
    let mut f = vec![6];
    f.extend_from_slice(&(0x4000u16 | offset as u16).to_be_bytes());
    f.extend_from_slice(&(0x4000u16 | data.len() as u16).to_be_bytes());
    f.extend_from_slice(data);
    f
}

/// A TLS 1.2 client with no SNI, no ALPN and a short cipher list.
pub fn sparse_hello() -> Vec<u8> {
    hello_body(
        &HelloSpec {
            version: 0x0303,
            ciphers: &[0xc02f, 0xc030, 0x009c, 0x009d],
            plain_extensions: &[0x000a, 0x000b, 0xff01],
            sni: None,
            alpn: &[],
            signatures: &[0x0401, 0x0501],
            supported_versions: &[],
        },
        false,
    )
}

fn from_hex(text: &str) -> Vec<u8> {
    let hex: String = text.split_whitespace().collect();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// The capture behind the README's demo: the specification's client twice over TCP, one of them
/// split across packets; a sparse client; and the RFC 9001 QUIC Initial.
pub fn demo_capture() -> Vec<u8> {
    let (a, b) = (([192, 0, 2, 10], 50000), ([192, 0, 2, 11], 50001));
    let c = ([192, 0, 2, 12], 50002);
    let d = ([192, 0, 2, 13], 50003);
    let web = ([198, 51, 100, 7], 443);
    let other = ([203, 0, 113, 9], 8443);
    let hello = record(&handshake(&spec_hello()));
    pcap(&[
        tcp_frame(a, web, 1000, FLAG_SYN, b""),
        tcp_frame(web, a, 7000, FLAG_SYN | FLAG_ACK, b""),
        tcp_frame(a, web, 1001, FLAG_ACK, &hello[..100]),
        tcp_frame(a, web, 1101, FLAG_ACK, &hello[100..]),
        tcp_frame(b, web, 2001, FLAG_ACK, &hello),
        tcp_frame(
            c,
            other,
            3001,
            FLAG_ACK,
            &record(&handshake(&sparse_hello())),
        ),
        udp_frame(
            d,
            web,
            &from_hex(include_str!("../../testdata/rfc9001-client-initial.hex")),
        ),
    ])
}
