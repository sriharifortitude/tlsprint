//! Follows flows through a capture and reports each client's first hello. A hello can span
//! packets and arrive out of order, and a capture can be built to exhaust memory, so everything
//! held between packets is limited.

use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use crate::capture::Frame;
use crate::ja4::{Fingerprint, Protocol};
use crate::packet::{self, Packet, Skip, Transport};
use crate::quic;
use crate::tls::{self, ClientHello, Stream};

/// How many flows are followed at once.
const MAX_FLOWS: usize = 1 << 20;
/// How many bytes are held for unfinished hellos, across all flows.
const MAX_BUFFERED: usize = 1 << 28;

/// One client's hello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sighting {
    /// The frame that completed the hello.
    pub frame: u64,
    pub micros: Option<i64>,
    pub protocol: Protocol,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub hello: ClientHello,
    pub fingerprint: Fingerprint,
}

/// What was passed over, so that a short result can be told from a clean one.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Stats {
    pub frames: u64,
    pub malformed: u64,
    pub ip_fragments: u64,
    /// Flows forgotten because a limit was reached, whose hellos may therefore be missing.
    pub flows_evicted: u64,
    /// Hellos begun and then given up on as too large or not adding up.
    pub hellos_refused: u64,
}

/// Puts byte ranges back in order. The first bytes to arrive for a position win.
#[derive(Debug, Default)]
struct Assembler {
    data: Vec<u8>,
    pending: BTreeMap<usize, Vec<u8>>,
    pending_bytes: usize,
}

impl Assembler {
    fn held(&self) -> usize {
        self.data.len() + self.pending_bytes
    }

    /// Adds bytes at an offset; returns how much more is held now. Nothing at or past
    /// `tls::MAX_HELLO` is kept.
    fn insert(&mut self, offset: usize, bytes: &[u8]) -> usize {
        let before = self.held();
        let Some(end) = offset.checked_add(bytes.len()) else {
            return 0;
        };
        let end = end.min(tls::MAX_HELLO);
        if offset < end {
            let bytes = &bytes[..end - offset];
            if offset <= self.data.len() {
                self.append(offset, bytes);
                self.drain_pending();
            } else {
                // A later segment for the same offset can be longer, so keep whichever is.
                let slot = self.pending.entry(offset).or_default();
                if bytes.len() > slot.len() {
                    self.pending_bytes += bytes.len() - slot.len();
                    *slot = bytes.to_vec();
                }
            }
        }
        self.held() - before
    }

    fn append(&mut self, offset: usize, bytes: &[u8]) {
        let skip = self.data.len() - offset;
        if skip < bytes.len() {
            self.data.extend_from_slice(&bytes[skip..]);
        }
    }

    fn drain_pending(&mut self) {
        while let Some((&offset, _)) = self.pending.first_key_value() {
            if offset > self.data.len() {
                break;
            }
            let Some(bytes) = self.pending.remove(&offset) else {
                break;
            };
            self.pending_bytes -= bytes.len();
            self.append(offset, &bytes);
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
struct FlowKey {
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
}

#[derive(Debug)]
enum TcpFlow {
    Gathering { base: u32, assembler: Assembler },
    Done,
}

#[derive(Debug)]
enum QuicFlow {
    Gathering {
        key_dcid: Vec<u8>,
        assembler: Assembler,
    },
    Done,
}

#[derive(Debug)]
enum DtlsFlow {
    Gathering {
        message_seq: u16,
        assembler: Assembler,
    },
    Done,
}

pub struct Tracker {
    tcp: HashMap<FlowKey, TcpFlow>,
    quic: HashMap<FlowKey, QuicFlow>,
    dtls: HashMap<FlowKey, DtlsFlow>,
    buffered: usize,
    max_flows: usize,
    max_buffered: usize,
    pub stats: Stats,
}

impl Default for Tracker {
    fn default() -> Self {
        Self::with_limits(MAX_FLOWS, MAX_BUFFERED)
    }
}

impl Tracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// A tracker that forgets everything it holds once it follows more than `max_flows` flows or
    /// holds more than `max_buffered` bytes of unfinished hellos.
    pub fn with_limits(max_flows: usize, max_buffered: usize) -> Self {
        Tracker {
            tcp: HashMap::new(),
            quic: HashMap::new(),
            dtls: HashMap::new(),
            buffered: 0,
            max_flows,
            max_buffered,
            stats: Stats::default(),
        }
    }

    /// Takes one frame and returns any hellos it completes.
    pub fn frame(&mut self, frame: &Frame) -> Vec<Sighting> {
        self.stats.frames += 1;
        let packet = match packet::parse(frame.linktype, &frame.data) {
            Ok(p) => p,
            Err(Skip::Other) => return Vec::new(),
            Err(Skip::Fragment) => {
                self.stats.ip_fragments += 1;
                return Vec::new();
            }
            Err(Skip::Malformed) => {
                self.stats.malformed += 1;
                return Vec::new();
            }
        };
        let key = FlowKey {
            src: packet.src,
            dst: packet.dst,
            src_port: packet.src_port,
            dst_port: packet.dst_port,
        };
        let found = match packet.transport {
            Transport::Tcp { .. } => self.tcp(key, &packet).map(|h| (h, Protocol::Tcp)),
            Transport::Udp { payload } if quic::looks_like_initial(payload) => {
                self.quic(key, payload).map(|h| (h, Protocol::Quic))
            }
            Transport::Udp { payload } => self.dtls(key, payload).map(|h| (h, Protocol::Dtls)),
        };
        self.enforce_limits();
        let Some((hello, protocol)) = found else {
            return Vec::new();
        };
        vec![Sighting {
            frame: frame.number,
            micros: frame.micros,
            protocol,
            src: packet.src,
            dst: packet.dst,
            src_port: packet.src_port,
            dst_port: packet.dst_port,
            fingerprint: Fingerprint::of(&hello, protocol),
            hello,
        }]
    }

    fn enforce_limits(&mut self) {
        let flows = self.tcp.len() + self.quic.len() + self.dtls.len();
        if flows > self.max_flows || self.buffered > self.max_buffered {
            self.stats.flows_evicted += flows as u64;
            self.tcp.clear();
            self.quic.clear();
            self.dtls.clear();
            self.buffered = 0;
        }
    }

    fn release(&mut self, assembler: &Assembler) {
        self.buffered = self.buffered.saturating_sub(assembler.held());
    }

    fn tcp(&mut self, key: FlowKey, packet: &Packet<'_>) -> Option<ClientHello> {
        let Transport::Tcp {
            seq,
            syn,
            ack: _,
            rst,
            payload,
        } = packet.transport
        else {
            return None;
        };
        if rst {
            if let Some(TcpFlow::Gathering { assembler, .. }) = self.tcp.remove(&key) {
                self.release(&assembler);
            }
            return None;
        }
        // A SYN starts a connection over, and the data after it is at sequence + 1.
        if syn {
            if let Some(TcpFlow::Gathering { assembler, .. }) = self.tcp.remove(&key) {
                self.release(&assembler);
            }
            self.tcp.insert(
                key,
                TcpFlow::Gathering {
                    base: seq.wrapping_add(1),
                    assembler: Assembler::default(),
                },
            );
        }
        if payload.is_empty() {
            return None;
        }
        if let Entry::Vacant(slot) = self.tcp.entry(key) {
            // No SYN in the capture, or a stream that began as something else, as STARTTLS does:
            // only a segment that opens like a hello starts one.
            if !tls::starts_like_hello(payload) {
                return None;
            }
            slot.insert(TcpFlow::Gathering {
                base: seq,
                assembler: Assembler::default(),
            });
        }
        let Some(TcpFlow::Gathering { base, assembler }) = self.tcp.get_mut(&key) else {
            return None;
        };
        // Sequence numbers wrap; a retransmission from before the start becomes an offset so large
        // that the assembler drops it. Data in the SYN itself (TCP Fast Open) comes first, though
        // its sequence is the SYN's.
        let offset = if syn { 0 } else { seq.wrapping_sub(*base) };
        let before = assembler.data.len();
        self.buffered += assembler.insert(offset as usize, payload);
        if assembler.data.len() == before {
            return None;
        }
        match tls::parse_tcp_stream(&assembler.data) {
            Stream::NeedMore => {
                if assembler.data.len() >= tls::MAX_HELLO {
                    let held = assembler.held();
                    self.stats.hellos_refused += 1;
                    self.buffered = self.buffered.saturating_sub(held);
                    self.tcp.remove(&key);
                }
                None
            }
            Stream::NotHello => {
                let opened_like_hello =
                    tls::starts_like_hello(&assembler.data) && assembler.data.len() >= 6;
                let held = assembler.held();
                self.buffered = self.buffered.saturating_sub(held);
                self.stats.hellos_refused += u64::from(opened_like_hello);
                self.tcp.remove(&key);
                None
            }
            Stream::Hello(hello) => {
                let held = assembler.held();
                self.buffered = self.buffered.saturating_sub(held);
                self.tcp.insert(key, TcpFlow::Done);
                Some(hello)
            }
        }
    }

    fn quic(&mut self, key: FlowKey, datagram: &[u8]) -> Option<ClientHello> {
        if matches!(self.quic.get(&key), Some(QuicFlow::Done)) {
            return None;
        }
        let mut rest = datagram;
        while let Some((packet, next)) = quic::next_packet(rest) {
            rest = next;
            if !packet.initial {
                continue;
            }
            // Keys come from the client's first connection ID, and later packets may carry another.
            let known = match self.quic.get(&key) {
                Some(QuicFlow::Gathering { key_dcid, .. }) => Some(key_dcid.clone()),
                _ => None,
            };
            let frames = known
                .as_deref()
                .and_then(|dcid| quic::decrypt_client_initial(&packet, dcid))
                .or_else(|| quic::decrypt_client_initial(&packet, packet.dcid));
            let Some(frames) = frames else { continue };
            let flow = self.quic.entry(key).or_insert_with(|| QuicFlow::Gathering {
                key_dcid: packet.dcid.to_vec(),
                assembler: Assembler::default(),
            });
            let QuicFlow::Gathering { assembler, .. } = flow else {
                return None;
            };
            let mut added = 0;
            for (offset, data) in quic::crypto_frames(&frames) {
                if let Ok(offset) = usize::try_from(offset) {
                    added += assembler.insert(offset, data);
                }
            }
            self.buffered += added;
            let Some(hello) = finished_hello(&assembler.data, false) else {
                continue;
            };
            let held = assembler.held();
            self.buffered = self.buffered.saturating_sub(held);
            self.stats.hellos_refused += u64::from(hello.is_none());
            self.quic.insert(key, QuicFlow::Done);
            return hello;
        }
        None
    }

    fn dtls(&mut self, key: FlowKey, datagram: &[u8]) -> Option<ClientHello> {
        if datagram.first() != Some(&22)
            || datagram.get(1) != Some(&0xfe)
            || matches!(self.dtls.get(&key), Some(DtlsFlow::Done))
        {
            return None;
        }
        for fragment in tls::dtls_fragments(datagram) {
            if fragment.total > tls::MAX_HELLO {
                self.stats.hellos_refused += 1;
                continue;
            }
            let flow = self.dtls.entry(key).or_insert_with(|| DtlsFlow::Gathering {
                message_seq: fragment.message_seq,
                assembler: Assembler::default(),
            });
            let DtlsFlow::Gathering {
                message_seq,
                assembler,
            } = flow
            else {
                return None;
            };
            if *message_seq != fragment.message_seq {
                continue;
            }
            let added = assembler.insert(fragment.offset, fragment.data);
            self.buffered += added;
            if assembler.data.len() < fragment.total {
                continue;
            }
            let hello = tls::parse_client_hello(&assembler.data[..fragment.total], true);
            let held = assembler.held();
            self.buffered = self.buffered.saturating_sub(held);
            self.stats.hellos_refused += u64::from(hello.is_none());
            self.dtls.insert(key, DtlsFlow::Done);
            return hello;
        }
        None
    }
}

/// Reads a handshake message that has arrived whole. The outer None means more bytes are needed;
/// the inner None means it is here and is not a ClientHello.
fn finished_hello(handshake: &[u8], dtls: bool) -> Option<Option<ClientHello>> {
    let head = handshake.get(..4)?;
    if head[0] != 1 {
        return Some(None);
    }
    let len = usize::from(head[1]) << 16 | usize::from(head[2]) << 8 | usize::from(head[3]);
    if len > tls::MAX_HELLO {
        return Some(None);
    }
    let body = handshake.get(4..4 + len)?;
    Some(tls::parse_client_hello(body, dtls))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_assembler_takes_any_order_and_any_overlap() {
        let mut a = Assembler::default();
        assert_eq!(a.insert(6, b"gh"), 2);
        assert_eq!(a.insert(3, b"def"), 3);
        assert_eq!(a.data, b"");
        assert_eq!(a.insert(0, b"abc"), 3);
        assert_eq!(a.data, b"abcdefgh");
        assert_eq!(a.pending_bytes, 0);
        // A retransmission adds nothing; an overlap adds only what is new, and the first bytes win.
        assert_eq!(a.insert(0, b"XXX"), 0);
        assert_eq!(a.insert(6, b"YYij"), 2);
        assert_eq!(a.data, b"abcdefghij");
    }

    #[test]
    fn the_assembler_keeps_the_longer_of_two_pending_segments() {
        let mut a = Assembler::default();
        a.insert(2, b"c");
        assert_eq!(a.insert(2, b"cde"), 2);
        assert_eq!(a.insert(2, b"c"), 0);
        a.insert(0, b"ab");
        assert_eq!(a.data, b"abcde");
    }

    #[test]
    fn the_assembler_stops_at_the_limit() {
        let mut a = Assembler::default();
        assert_eq!(a.insert(tls::MAX_HELLO, b"past"), 0);
        assert_eq!(a.insert(tls::MAX_HELLO - 1, b"past"), 1);
        assert_eq!(a.insert(usize::MAX, b"past"), 0);
    }

    #[test]
    fn a_finished_message_is_told_from_an_unfinished_one() {
        assert_eq!(finished_hello(&[1, 0, 0], false), None);
        assert_eq!(finished_hello(&[1, 0, 0, 2, 3], false), None);
        assert_eq!(finished_hello(&[2, 0, 0, 0], false), Some(None));
        assert_eq!(finished_hello(&[1, 0xff, 0xff, 0xff], false), Some(None));
        assert_eq!(finished_hello(&[1, 0, 0, 1, 3], false), Some(None));
    }
}
