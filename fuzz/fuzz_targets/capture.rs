#![no_main]

use libfuzzer_sys::fuzz_target;
use tlsprint::capture::{Frame, Reader};
use tlsprint::flow::Tracker;

fuzz_target!(|data: &[u8]| {
    // As a whole capture file.
    if let Ok(mut reader) = Reader::new(data) {
        let mut tracker = Tracker::new();
        while let Ok(Some(frame)) = reader.next_frame() {
            tracker.frame(&frame);
        }
    }
    // As one frame of each link type, which reaches the parsers far more directly.
    let mut tracker = Tracker::new();
    for linktype in [0, 1, 101, 108, 113, 228, 229, 276] {
        tracker.frame(&Frame { number: 1, linktype, micros: None, data: data.to_vec() });
    }
    // As the ClientHello parsers themselves.
    let _ = tlsprint::tls::parse_tcp_stream(data);
    let _ = tlsprint::tls::parse_client_hello(data, true);
    let _ = tlsprint::tls::dtls_fragments(data);
});
