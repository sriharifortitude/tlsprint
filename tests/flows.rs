//! Hellos as they actually cross a network: split, reordered, repeated, wrapped in other things.

mod common;

use common::*;
use tlsprint::capture::Frame;
use tlsprint::flow::{Sighting, Tracker};
use tlsprint::ja4::Protocol;

const C: ([u8; 4], u16) = (CLIENT, 50000);
const S: ([u8; 4], u16) = (SERVER, 443);

fn run(tracker: &mut Tracker, frames: &[Vec<u8>]) -> Vec<Sighting> {
    let mut out = Vec::new();
    for (i, data) in frames.iter().enumerate() {
        out.extend(tracker.frame(&Frame {
            number: i as u64 + 1,
            linktype: 1,
            micros: Some(i as i64),
            data: data.clone(),
        }));
    }
    out
}

fn sightings(frames: &[Vec<u8>]) -> Vec<Sighting> {
    run(&mut Tracker::new(), frames)
}

fn stream() -> Vec<u8> {
    record(&handshake(&spec_hello()))
}

#[test]
fn a_hello_in_one_packet_after_a_syn() {
    let s = sightings(&[
        tcp_frame(C, S, 1000, FLAG_SYN, b""),
        tcp_frame(C, S, 1001, FLAG_ACK, &stream()),
    ]);
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].fingerprint.ja4, SPEC_JA4);
    assert_eq!((s[0].frame, s[0].micros), (2, Some(1)));
    assert_eq!(s[0].protocol, Protocol::Tcp);
    assert_eq!(s[0].src.to_string(), "192.0.2.10");
    assert_eq!((s[0].src_port, s[0].dst_port), (50000, 443));
    assert_eq!(
        s[0].hello.server_name.as_deref(),
        Some(&b"www.example.org"[..])
    );
}

#[test]
fn a_hello_with_no_syn_in_the_capture() {
    assert_eq!(
        sightings(&[tcp_frame(C, S, 7, FLAG_ACK, &stream())])[0]
            .fingerprint
            .ja4,
        SPEC_JA4
    );
}

#[test]
fn a_hello_split_across_packets_arrives_in_any_order() {
    let h = stream();
    let (a, b, c) = (&h[..30], &h[30..90], &h[90..]);
    let syn = tcp_frame(C, S, 1000, FLAG_SYN, b"");
    let at = |offset: u32, data: &[u8]| tcp_frame(C, S, 1001 + offset, FLAG_ACK, data);
    let (fa, fb, fc) = (at(0, a), at(30, b), at(90, c));
    for order in [
        vec![fa.clone(), fb.clone(), fc.clone()],
        vec![fc.clone(), fb.clone(), fa.clone()],
        vec![fb.clone(), fa.clone(), fc.clone()],
        vec![fa.clone(), fc.clone(), fb.clone()],
    ] {
        let mut frames = vec![syn.clone()];
        frames.extend(order);
        let s = sightings(&frames);
        assert_eq!(s.len(), 1);
        assert_eq!(
            (s[0].frame, s[0].fingerprint.ja4.as_str()),
            (4, SPEC_JA4),
            "it completes on the last frame"
        );
    }
}

#[test]
fn a_split_hello_with_no_syn_and_retransmissions() {
    let h = stream();
    let frames = [
        tcp_frame(C, S, 500, FLAG_ACK, &h[..40]),
        tcp_frame(C, S, 500, FLAG_ACK, &h[..40]),
        tcp_frame(C, S, 500, FLAG_ACK, &h[..20]),
        tcp_frame(C, S, 520, FLAG_ACK, &h[20..60]), // overlaps what came before
        tcp_frame(C, S, 500 + 60, FLAG_ACK, &h[60..]),
    ];
    let s = sightings(&frames);
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].frame, 5);
    assert_eq!(s[0].fingerprint.ja4, SPEC_JA4);
}

#[test]
fn a_hello_cut_into_tiny_segments_is_still_found_with_no_syn() {
    // Splitting a hello very small is a way to hide it from tools that look at one packet.
    let h = stream();
    let mut frames = Vec::new();
    for (i, byte) in h.iter().enumerate().take(8) {
        frames.push(tcp_frame(C, S, 500 + i as u32, FLAG_ACK, &[*byte]));
    }
    frames.push(tcp_frame(C, S, 508, FLAG_ACK, &h[8..]));
    let s = sightings(&frames);
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].fingerprint.ja4, SPEC_JA4);
}

#[test]
fn sequence_numbers_that_wrap_around_zero() {
    let h = stream();
    let start = u32::MAX - 9;
    let frames = [
        tcp_frame(C, S, start.wrapping_sub(1), FLAG_SYN, b""),
        tcp_frame(C, S, start, FLAG_ACK, &h[..30]),
        tcp_frame(C, S, start.wrapping_add(30), FLAG_ACK, &h[30..]),
    ];
    assert_eq!(sightings(&frames)[0].fingerprint.ja4, SPEC_JA4);
}

#[test]
fn a_retransmission_from_before_the_start_is_ignored() {
    let h = stream();
    let frames = [
        tcp_frame(C, S, 999, FLAG_SYN, b""),
        tcp_frame(C, S, 900, FLAG_ACK, b"stale data"),
        tcp_frame(C, S, 1000, FLAG_ACK, &h),
    ];
    assert_eq!(sightings(&frames).len(), 1);
}

#[test]
fn a_hello_spanning_records() {
    let m = handshake(&spec_hello());
    let split = [record(&m[..3]), record(&m[3..50]), record(&m[50..])].concat();
    assert_eq!(
        sightings(&[tcp_frame(C, S, 7, FLAG_ACK, &split)])[0]
            .fingerprint
            .ja4,
        SPEC_JA4
    );
}

#[test]
fn data_in_the_syn_itself() {
    let s = sightings(&[tcp_frame(C, S, 1000, FLAG_SYN, &stream())]);
    assert_eq!(s[0].fingerprint.ja4, SPEC_JA4);
}

#[test]
fn only_the_first_hello_of_a_connection_counts() {
    let h = stream();
    let frames = [
        tcp_frame(C, S, 1, FLAG_SYN, b""),
        tcp_frame(C, S, 2, FLAG_ACK, &h),
        tcp_frame(C, S, 2 + h.len() as u32, FLAG_ACK, &h),
    ];
    assert_eq!(sightings(&frames).len(), 1);
}

#[test]
fn a_new_syn_is_a_new_connection_and_a_new_hello() {
    let h = stream();
    let frames = [
        tcp_frame(C, S, 1, FLAG_SYN, b""),
        tcp_frame(C, S, 2, FLAG_ACK, &h),
        tcp_frame(C, S, 9000, FLAG_SYN, b""),
        tcp_frame(C, S, 9001, FLAG_ACK, &h),
    ];
    assert_eq!(
        sightings(&frames)
            .iter()
            .map(|s| s.frame)
            .collect::<Vec<_>>(),
        [2, 4]
    );
}

#[test]
fn a_reset_ends_a_half_finished_hello() {
    let h = stream();
    let frames = [
        tcp_frame(C, S, 1, FLAG_SYN, b""),
        tcp_frame(C, S, 2, FLAG_ACK, &h[..30]),
        tcp_frame(C, S, 32, FLAG_RST, b""),
        tcp_frame(C, S, 32, FLAG_ACK, &h[30..]),
    ];
    assert!(sightings(&frames).is_empty());
}

#[test]
fn a_reset_clears_a_finished_connection_too() {
    let h = stream();
    let frames = [
        tcp_frame(C, S, 2, FLAG_ACK, &h),
        tcp_frame(C, S, 3000, FLAG_RST, b""),
        tcp_frame(C, S, 3000, FLAG_ACK, &h),
    ];
    assert_eq!(sightings(&frames).len(), 2);
}

#[test]
fn starttls_begins_with_something_else() {
    let frames = [
        tcp_frame(C, S, 1, FLAG_SYN, b""),
        tcp_frame(C, S, 2, FLAG_ACK, b"EHLO client.example\r\n"),
        tcp_frame(C, S, 23, FLAG_ACK, b"STARTTLS\r\n"),
        tcp_frame(C, S, 33, FLAG_ACK, &stream()),
    ];
    let s = sightings(&frames);
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].frame, 4);
}

#[test]
fn a_server_hello_and_ordinary_traffic_are_not_clients() {
    let server_hello = record(&[2, 0, 0, 2, 3, 3]);
    let frames = [
        tcp_frame(S, C, 1, FLAG_SYN | FLAG_ACK, b""),
        tcp_frame(S, C, 2, FLAG_ACK, &server_hello),
        tcp_frame(C, S, 2, FLAG_ACK, b"GET / HTTP/1.1\r\n\r\n"),
        tcp_frame(C, S, 20, FLAG_ACK, &[0x16]),
    ];
    let mut t = Tracker::new();
    assert!(run(&mut t, &frames).is_empty());
    assert_eq!(t.stats.hellos_refused, 0, "none of this began as a hello");
}

#[test]
fn a_hello_that_does_not_add_up_is_counted() {
    let mut t = Tracker::new();
    let bad = record(&[1, 0, 0, 2, 3, 3]);
    assert!(run(&mut t, &[tcp_frame(C, S, 2, FLAG_ACK, &bad)]).is_empty());
    assert_eq!(t.stats.hellos_refused, 1);
}

#[test]
fn a_flow_given_up_on_can_still_find_a_hello_later() {
    let bad = record(&[1, 0, 0, 2, 3, 3]);
    let frames = [
        tcp_frame(C, S, 2, FLAG_ACK, &bad),
        tcp_frame(C, S, 2 + bad.len() as u32, FLAG_ACK, &stream()),
    ];
    assert_eq!(sightings(&frames).len(), 1);
}

#[test]
fn flows_are_kept_apart() {
    let h = stream();
    let other = ([192, 0, 2, 99], 50000);
    let frames = [
        tcp_frame(C, S, 2, FLAG_ACK, &h[..30]),
        tcp_frame(other, S, 2, FLAG_ACK, &h[..30]),
        tcp_frame(C, S, 32, FLAG_ACK, &h[30..]),
        tcp_frame(other, S, 32, FLAG_ACK, &h[30..]),
    ];
    assert_eq!(
        sightings(&frames)
            .iter()
            .map(|s| s.frame)
            .collect::<Vec<_>>(),
        [3, 4]
    );
}

#[test]
fn memory_limits_forget_flows_and_say_so() {
    // Each unfinished hello holds its bytes until the limit, then everything is let go.
    let start = record(&[1, 0, 0xff, 0xff, 3]);
    let mut t = Tracker::with_limits(1 << 20, 30);
    let frames: Vec<Vec<u8>> = (0..5)
        .map(|i| tcp_frame((CLIENT, 40000 + i), S, 2, FLAG_ACK, &start))
        .collect();
    assert!(run(&mut t, &frames).is_empty());
    assert_eq!(
        t.stats.flows_evicted, 4,
        "ten bytes each passes 30 on the fourth"
    );

    let mut t = Tracker::with_limits(2, 1 << 20);
    let h = stream();
    let frames: Vec<Vec<u8>> = (0..4)
        .map(|i| tcp_frame((CLIENT, 40000 + i), S, 2, FLAG_ACK, &h))
        .collect();
    assert_eq!(
        run(&mut t, &frames).len(),
        4,
        "finished flows are simply forgotten"
    );
    assert_eq!(t.stats.flows_evicted, 3);
}

#[test]
fn buffered_bytes_are_given_back_when_a_hello_finishes() {
    let h = stream();
    // Far more bytes pass through than the limit allows at once, one flow at a time.
    let mut t = Tracker::with_limits(1 << 20, h.len() + 1);
    let frames: Vec<Vec<u8>> = (0..50)
        .map(|i| tcp_frame((CLIENT, 40000 + i), S, 2, FLAG_ACK, &h))
        .collect();
    assert_eq!(run(&mut t, &frames).len(), 50);
    assert_eq!(t.stats.flows_evicted, 0);
}

#[test]
fn a_hello_too_large_to_hold_is_refused() {
    let mut t = Tracker::new();
    // Promises just under the handshake limit, then keeps sending. The assembler stops at the limit.
    let n = tlsprint::tls::MAX_HELLO - 5;
    let mut body = vec![1, (n >> 16) as u8, (n >> 8) as u8, n as u8];
    body.resize(16000, 0);
    let mut frames = vec![tcp_frame(C, S, 1000, FLAG_ACK, &record(&body))];
    let mut seq = 1000 + 16005;
    for _ in 0..16 {
        let more = record(&[0; 16380]);
        frames.push(tcp_frame(C, S, seq, FLAG_ACK, &more));
        seq += more.len() as u32;
    }
    assert!(run(&mut t, &frames).is_empty());
    assert_eq!(t.stats.hellos_refused, 1);
}

// --- QUIC -----------------------------------------------------------------------------------

fn vector(text: &str) -> Vec<u8> {
    let hex: String = text.split_whitespace().collect();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn the_rfc_packets_as_they_would_be_captured() {
    for text in [
        include_str!("../testdata/rfc9001-client-initial.hex"),
        include_str!("../testdata/rfc9369-client-initial.hex"),
    ] {
        let s = sightings(&[udp_frame(C, S, &vector(text))]);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].protocol, Protocol::Quic);
        assert!(
            s[0].fingerprint.ja4.starts_with("q13d0211an_"),
            "{}",
            s[0].fingerprint.ja4
        );
        assert_eq!(s[0].hello.server_name.as_deref(), Some(&b"example.com"[..]));
    }
}

#[test]
fn a_quic_hello_across_two_packets_with_shuffled_frames() {
    let m = handshake(&spec_hello());
    let (a, b) = m.split_at(40);
    let dcid = [1, 2, 3, 4, 5, 6, 7, 8];
    let second = quic_initial(&dcid, &dcid, 1, &crypto_frame(40, b));
    let first = quic_initial(&dcid, &dcid, 0, &crypto_frame(0, a));
    let s = sightings(&[udp_frame(C, S, &second), udp_frame(C, S, &first)]);
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].frame, 2);
    assert!(s[0].fingerprint.ja4.starts_with("q13d1516h2_"));
}

#[test]
fn keys_stay_those_of_the_first_connection_id() {
    // After the server answers, the client's packets carry a new connection ID but the old keys.
    let m = handshake(&spec_hello());
    let (a, b) = m.split_at(40);
    let original = [1, 2, 3, 4, 5, 6, 7, 8];
    let frames = [
        udp_frame(
            C,
            S,
            &quic_initial(&original, &original, 0, &crypto_frame(0, a)),
        ),
        udp_frame(
            C,
            S,
            &quic_initial(&[9, 9, 9, 9], &original, 1, &crypto_frame(40, b)),
        ),
    ];
    assert_eq!(sightings(&frames).len(), 1);
}

#[test]
fn coalesced_packets_after_a_failed_one_are_still_read() {
    let m = handshake(&spec_hello());
    let dcid = [1, 2, 3, 4];
    // A packet that will not authenticate, then a good one, in one datagram.
    let bad = quic_initial(&dcid, b"different", 0, &crypto_frame(0, &m));
    let good = quic_initial(&dcid, &dcid, 1, &crypto_frame(0, &m));
    assert_eq!(
        sightings(&[udp_frame(C, S, &[bad, good].concat())]).len(),
        1
    );
}

#[test]
fn a_quic_connection_is_reported_once_and_other_messages_not_at_all() {
    let m = handshake(&spec_hello());
    let dcid = [1, 2, 3, 4];
    let p = quic_initial(&dcid, &dcid, 0, &crypto_frame(0, &m));
    assert_eq!(
        sightings(&[udp_frame(C, S, &p), udp_frame(C, S, &p)]).len(),
        1
    );
    let mut t = Tracker::new();
    let not_hello = quic_initial(&dcid, &dcid, 0, &crypto_frame(0, &[2, 0, 0, 0]));
    assert!(run(&mut t, &[udp_frame(C, S, &not_hello)]).is_empty());
    assert_eq!(t.stats.hellos_refused, 1);
}

#[test]
fn undecryptable_udp_holds_no_state() {
    let dcid = [1, 2, 3, 4];
    let m = handshake(&spec_hello());
    let bad = quic_initial(&dcid, b"other", 0, &crypto_frame(0, &m));
    let good = quic_initial(&dcid, &dcid, 0, &crypto_frame(0, &m));
    // The flow is not stuck on keys from the packet that failed.
    assert_eq!(
        sightings(&[udp_frame(C, S, &bad), udp_frame(C, S, &good)]).len(),
        1
    );
}

#[test]
fn quic_bytes_count_against_the_memory_limit() {
    let dcid = [1, 2, 3, 4];
    let p = quic_initial(&dcid, &dcid, 0, &crypto_frame(5, &[0; 100]));
    let mut t = Tracker::with_limits(1 << 20, 150);
    let frames: Vec<Vec<u8>> = (0..2)
        .map(|i| udp_frame((CLIENT, 40000 + i), S, &p))
        .collect();
    run(&mut t, &frames);
    assert_eq!(t.stats.flows_evicted, 2);
}

// --- DTLS -----------------------------------------------------------------------------------

fn dtls_hello() -> Vec<u8> {
    hello_body(
        &HelloSpec {
            version: 0xfefd,
            ciphers: &[0xc02b, 0xc02f],
            plain_extensions: &[0x000b],
            sni: None,
            alpn: &[],
            signatures: &[],
            supported_versions: &[],
        },
        true,
    )
}

#[test]
fn a_dtls_hello_is_reported_with_its_own_letter() {
    let b = dtls_hello();
    let s = sightings(&[udp_frame(C, S, &dtls_record(0, b.len(), 0, &b))]);
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].protocol, Protocol::Dtls);
    assert!(
        s[0].fingerprint.ja4.starts_with("dd2i020100_"),
        "{}",
        s[0].fingerprint.ja4
    );
}

#[test]
fn dtls_fragments_arrive_in_any_order_and_a_second_message_is_passed_over() {
    let b = dtls_hello();
    let (x, y) = b.split_at(30);
    let frames = [
        udp_frame(C, S, &dtls_record(0, b.len(), 30, y)),
        udp_frame(C, S, &dtls_record(7, b.len(), 0, &[0xee; 30])), // another message's fragment
        udp_frame(C, S, &dtls_record(0, b.len(), 0, x)),
        udp_frame(C, S, &dtls_record(1, b.len(), 0, &b)), // the retry after HelloVerifyRequest
    ];
    let s = sightings(&frames);
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].frame, 3);
}

#[test]
fn dtls_that_is_too_large_or_does_not_add_up_is_counted() {
    let mut t = Tracker::new();
    let big = udp_frame(C, S, &dtls_record(0, tlsprint::tls::MAX_HELLO + 1, 0, b"x"));
    let bad = udp_frame(([192, 0, 2, 99], 5), S, &dtls_record(0, 2, 0, b"xx"));
    assert!(run(&mut t, &[big, bad]).is_empty());
    assert_eq!(t.stats.hellos_refused, 2);
}

#[test]
fn other_udp_is_ignored() {
    let frames = [
        udp_frame(C, S, b""),
        udp_frame(C, S, b"\x16"),
        udp_frame(C, S, b"\x16\x03\x01"),
        udp_frame(C, S, &[0xc0; 40]),
    ];
    assert!(sightings(&frames).is_empty());
}

// --- what is counted ------------------------------------------------------------------------

#[test]
fn frames_that_cannot_be_read_are_counted() {
    let mut t = Tracker::new();
    let mut fragment = tcp_frame(C, S, 2, FLAG_ACK, b"x");
    fragment[20] = 0x20; // IP more-fragments flag
    run(
        &mut t,
        &[vec![0; 3], fragment, tcp_frame(C, S, 2, FLAG_ACK, b"x")],
    );
    assert_eq!(
        (t.stats.frames, t.stats.malformed, t.stats.ip_fragments),
        (3, 1, 1)
    );
}
