//! Damaged input must never panic. Tests run with overflow checks on, so arithmetic on a hostile
//! length fails here too. The fuzz target goes much further than this in CI.

mod common;

use common::*;
use tlsprint::capture::{Frame, Reader};
use tlsprint::flow::Tracker;

/// A small deterministic generator, so that a failure can be reproduced.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn damage(data: &mut Vec<u8>, rng: &mut Rng) {
    for _ in 0..1 + rng.below(8) {
        if data.is_empty() {
            return;
        }
        let at = rng.below(data.len());
        match rng.below(5) {
            0 => data[at] ^= 1 << rng.below(8),
            1 => data[at] = 0xff,
            2 => data[at] = 0,
            3 => data.truncate(at),
            _ => {
                let insert = rng.next() as u8;
                data.insert(at, insert);
            }
        }
    }
}

fn read_all(data: &[u8]) {
    if let Ok(mut reader) = Reader::new(data) {
        let mut tracker = Tracker::new();
        while let Ok(Some(frame)) = reader.next_frame() {
            tracker.frame(&frame);
        }
    }
}

#[test]
fn damaged_captures_never_panic() {
    let original = demo_capture();
    let mut rng = Rng(0x1234_5678_9abc_def1);
    for _ in 0..3000 {
        let mut data = original.clone();
        damage(&mut data, &mut rng);
        read_all(&data);
    }
}

#[test]
fn damaged_frames_of_every_link_type_never_panic() {
    let hello = record(&handshake(&spec_hello()));
    let dcid = [1, 2, 3, 4];
    let bases = [
        tcp_frame((CLIENT, 1), (SERVER, 443), 1, FLAG_ACK, &hello),
        udp_frame(
            (CLIENT, 1),
            (SERVER, 443),
            &quic_initial(&dcid, &dcid, 0, &crypto_frame(0, &handshake(&spec_hello()))),
        ),
        udp_frame(
            (CLIENT, 1),
            (SERVER, 443),
            &dtls_record(0, 8, 0, b"12345678"),
        ),
    ];
    let mut rng = Rng(0xfeed_face_cafe_beef);
    let mut tracker = Tracker::new();
    for i in 0..6000u64 {
        let mut data = bases[rng.below(bases.len())].clone();
        damage(&mut data, &mut rng);
        let linktype = [1, 1, 1, 0, 101, 108, 113, 228, 229, 276][rng.below(10)];
        tracker.frame(&Frame {
            number: i,
            linktype,
            micros: None,
            data,
        });
    }
}

#[test]
fn damage_to_a_pcapng_header_is_handled() {
    // A minimal pcapng: section, interface, packet.
    let mut original = Vec::new();
    original.extend_from_slice(&[0x0a, 0x0d, 0x0d, 0x0a, 28, 0, 0, 0, 0x4d, 0x3c, 0x2b, 0x1a]);
    original.extend_from_slice(&[
        1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 28, 0, 0, 0,
    ]);
    original.extend_from_slice(&[1, 0, 0, 0, 20, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0]);
    let frame = tcp_frame(
        (CLIENT, 1),
        (SERVER, 443),
        1,
        FLAG_ACK,
        &record(&handshake(&spec_hello())),
    );
    let padded = frame.len().div_ceil(4) * 4;
    let total = (32 + padded) as u32;
    original.extend_from_slice(&[6, 0, 0, 0]);
    original.extend_from_slice(&total.to_le_bytes());
    original.extend_from_slice(&[0; 12]);
    original.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    original.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    original.extend_from_slice(&frame);
    original.resize(original.len() + padded - frame.len(), 0);
    original.extend_from_slice(&total.to_le_bytes());

    let mut reader = Reader::new(&original[..]).unwrap();
    let mut tracker = Tracker::new();
    let found = tracker.frame(&reader.next_frame().unwrap().unwrap());
    assert_eq!(
        found[0].fingerprint.ja4, SPEC_JA4,
        "the undamaged file works"
    );

    let mut rng = Rng(0x0bad_f00d_0bad_f00d);
    for _ in 0..3000 {
        let mut data = original.clone();
        damage(&mut data, &mut rng);
        read_all(&data);
    }
}
