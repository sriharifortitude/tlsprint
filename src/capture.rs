//! Reads packets out of pcap and pcapng files. A capture is untrusted input, so no length field
//! is believed before it has been checked against a limit.

use std::fmt;
use std::io::{self, Read};

/// The longest packet accepted. Anything larger is treated as a corrupt file.
pub const MAX_PACKET: usize = 1 << 18;
/// The longest pcapng block whose contents are read into memory; longer ones are skipped.
const MAX_BLOCK: u64 = 1 << 24;

const BLOCK_SECTION: u32 = 0x0a0d_0d0a;
const BLOCK_INTERFACE: u32 = 1;
const BLOCK_OLD_PACKET: u32 = 2;
const BLOCK_SIMPLE_PACKET: u32 = 3;
const BLOCK_ENHANCED_PACKET: u32 = 6;

#[derive(Debug, PartialEq, Eq)]
pub struct Frame {
    /// 1-based position among the packets of the file, as Wireshark numbers them.
    pub number: u64,
    pub linktype: u32,
    /// Capture time in microseconds since the Unix epoch, when the file has one.
    pub micros: Option<i64>,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub enum CaptureError {
    Io(io::Error),
    NotACapture,
    Corrupt(String),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CaptureError::Io(e) => write!(f, "{e}"),
            CaptureError::NotACapture => write!(f, "not a pcap or pcapng file"),
            CaptureError::Corrupt(why) => write!(f, "corrupt capture: {why}"),
        }
    }
}

impl From<io::Error> for CaptureError {
    fn from(e: io::Error) -> Self {
        CaptureError::Io(e)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn u16(self, b: &[u8]) -> u16 {
        let a = [b[0], b[1]];
        match self {
            Endian::Little => u16::from_le_bytes(a),
            Endian::Big => u16::from_be_bytes(a),
        }
    }

    fn u32(self, b: &[u8]) -> u32 {
        let a = [b[0], b[1], b[2], b[3]];
        match self {
            Endian::Little => u32::from_le_bytes(a),
            Endian::Big => u32::from_be_bytes(a),
        }
    }
}

enum Format {
    Pcap {
        endian: Endian,
        linktype: u32,
        /// How many of the timestamp's fraction units make a microsecond: 1, or 1000 for nanoseconds.
        per_micro: u32,
    },
    Pcapng {
        endian: Endian,
        interfaces: Vec<Interface>,
    },
}

#[derive(Clone, Copy)]
struct Interface {
    linktype: u32,
    snaplen: u32,
    /// Timestamp units per second.
    units: u64,
}

pub struct Reader<R> {
    src: R,
    format: Format,
    number: u64,
    /// Set when the file ended partway through a packet, as a capture cut short does.
    pub truncated: bool,
}

/// Reads as much of `buf` as the source has, returning how many bytes that was.
fn read_full<R: Read>(src: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut done = 0;
    while done < buf.len() {
        match src.read(&mut buf[done..]) {
            Ok(0) => break,
            Ok(n) => done += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(done)
}

impl<R: Read> Reader<R> {
    pub fn new(mut src: R) -> Result<Self, CaptureError> {
        let mut magic = [0u8; 4];
        if read_full(&mut src, &mut magic)? < 4 {
            return Err(CaptureError::NotACapture);
        }
        let be = u32::from_be_bytes(magic);
        if be == BLOCK_SECTION {
            let mut reader = Reader {
                src,
                format: Format::Pcapng {
                    endian: Endian::Little,
                    interfaces: Vec::new(),
                },
                number: 0,
                truncated: false,
            };
            if !reader.section_header()? {
                return Err(CaptureError::NotACapture);
            }
            return Ok(reader);
        }
        let (endian, per_micro) = match be {
            0xa1b2_c3d4 => (Endian::Big, 1),
            0xd4c3_b2a1 => (Endian::Little, 1),
            0xa1b2_3c4d => (Endian::Big, 1000),
            0x4d3c_b2a1 => (Endian::Little, 1000),
            _ => return Err(CaptureError::NotACapture),
        };
        let mut rest = [0u8; 20];
        if read_full(&mut src, &mut rest)? < 20 {
            return Err(CaptureError::NotACapture);
        }
        let linktype = endian.u32(&rest[16..]);
        Ok(Reader {
            src,
            format: Format::Pcap {
                endian,
                linktype,
                per_micro,
            },
            number: 0,
            truncated: false,
        })
    }

    pub fn next_frame(&mut self) -> Result<Option<Frame>, CaptureError> {
        match self.format {
            Format::Pcap {
                endian,
                linktype,
                per_micro,
            } => self.next_pcap(endian, linktype, per_micro),
            Format::Pcapng { .. } => self.next_pcapng(),
        }
    }

    fn next_pcap(
        &mut self,
        endian: Endian,
        linktype: u32,
        per_micro: u32,
    ) -> Result<Option<Frame>, CaptureError> {
        let mut head = [0u8; 16];
        let got = read_full(&mut self.src, &mut head)?;
        if got == 0 {
            return Ok(None);
        }
        if got < 16 {
            self.truncated = true;
            return Ok(None);
        }
        let len = endian.u32(&head[8..]) as usize;
        if len > MAX_PACKET {
            return Err(CaptureError::Corrupt(format!(
                "a packet claims to be {len} bytes long"
            )));
        }
        let mut data = vec![0u8; len];
        if read_full(&mut self.src, &mut data)? < len {
            self.truncated = true;
            return Ok(None);
        }
        self.number += 1;
        let micros = i64::from(endian.u32(&head)) * 1_000_000
            + i64::from(endian.u32(&head[4..]) / per_micro);
        Ok(Some(Frame {
            number: self.number,
            linktype,
            micros: Some(micros),
            data,
        }))
    }

    /// Reads a section header whose block type has already been consumed. False when the file
    /// ended first.
    fn section_header(&mut self) -> Result<bool, CaptureError> {
        let mut head = [0u8; 8];
        if read_full(&mut self.src, &mut head)? < 8 {
            return Ok(false);
        }
        let endian = match u32::from_be_bytes([head[4], head[5], head[6], head[7]]) {
            0x1a2b_3c4d => Endian::Big,
            0x4d3c_2b1a => Endian::Little,
            _ => {
                return Err(CaptureError::Corrupt(
                    "a section header has no byte-order magic".into(),
                ))
            }
        };
        let total = u64::from(endian.u32(&head));
        if total < 28 || total % 4 != 0 {
            return Err(CaptureError::Corrupt(format!(
                "a section header claims {total} bytes"
            )));
        }
        // Type, length and magic are read; the rest is versions, section length, options, trailer.
        self.skip(total - 12)?;
        self.format = Format::Pcapng {
            endian,
            interfaces: Vec::new(),
        };
        Ok(true)
    }

    fn skip(&mut self, n: u64) -> Result<(), CaptureError> {
        if io::copy(&mut (&mut self.src).take(n), &mut io::sink())? < n {
            self.truncated = true;
        }
        Ok(())
    }

    fn next_pcapng(&mut self) -> Result<Option<Frame>, CaptureError> {
        loop {
            let mut kind = [0u8; 4];
            let got = read_full(&mut self.src, &mut kind)?;
            if got == 0 {
                return Ok(None);
            }
            if got < 4 {
                self.truncated = true;
                return Ok(None);
            }
            // The section header's type reads the same in either byte order.
            if u32::from_be_bytes(kind) == BLOCK_SECTION {
                if !self.section_header()? {
                    self.truncated = true;
                    return Ok(None);
                }
                continue;
            }
            let Format::Pcapng { endian, .. } = self.format else {
                unreachable!()
            };
            let mut len = [0u8; 4];
            if read_full(&mut self.src, &mut len)? < 4 {
                self.truncated = true;
                return Ok(None);
            }
            let total = u64::from(endian.u32(&len));
            if total < 12 || total % 4 != 0 {
                return Err(CaptureError::Corrupt(format!(
                    "a block claims {total} bytes"
                )));
            }
            let body_len = total - 12;
            let kind = endian.u32(&kind);
            if !matches!(
                kind,
                BLOCK_INTERFACE | BLOCK_OLD_PACKET | BLOCK_SIMPLE_PACKET | BLOCK_ENHANCED_PACKET
            ) {
                self.skip(total - 8)?;
                if self.truncated {
                    return Ok(None);
                }
                continue;
            }
            if body_len > MAX_BLOCK {
                return Err(CaptureError::Corrupt(format!(
                    "a packet block claims {total} bytes"
                )));
            }
            let mut body = vec![0u8; body_len as usize];
            if read_full(&mut self.src, &mut body)? < body.len() {
                self.truncated = true;
                return Ok(None);
            }
            self.skip(4)?;
            if let Some(frame) = self.block(kind, &body, endian)? {
                return Ok(Some(frame));
            }
        }
    }

    fn block(
        &mut self,
        kind: u32,
        body: &[u8],
        endian: Endian,
    ) -> Result<Option<Frame>, CaptureError> {
        let Format::Pcapng { interfaces, .. } = &mut self.format else {
            unreachable!()
        };
        let short = || CaptureError::Corrupt("a block is too short for its type".into());
        match kind {
            BLOCK_INTERFACE => {
                if body.len() < 8 {
                    return Err(short());
                }
                let mut iface = Interface {
                    linktype: u32::from(endian.u16(body)),
                    snaplen: endian.u32(&body[4..]),
                    units: 1_000_000,
                };
                if let Some(units) = timestamp_units(&body[8..], endian) {
                    iface.units = units;
                }
                interfaces.push(iface);
                Ok(None)
            }
            BLOCK_ENHANCED_PACKET | BLOCK_OLD_PACKET => {
                if body.len() < 20 {
                    return Err(short());
                }
                let (id, hi, lo, caplen) = if kind == BLOCK_ENHANCED_PACKET {
                    (
                        endian.u32(body) as usize,
                        endian.u32(&body[4..]),
                        endian.u32(&body[8..]),
                        endian.u32(&body[12..]),
                    )
                } else {
                    (
                        usize::from(endian.u16(body)),
                        endian.u32(&body[4..]),
                        endian.u32(&body[8..]),
                        endian.u32(&body[12..]),
                    )
                };
                let iface = *interfaces.get(id).ok_or_else(|| {
                    CaptureError::Corrupt(format!(
                        "a packet names interface {id}, which does not exist"
                    ))
                })?;
                let caplen = caplen as usize;
                if caplen > MAX_PACKET || caplen > body.len() - 20 {
                    return Err(CaptureError::Corrupt(format!(
                        "a packet claims to be {caplen} bytes long"
                    )));
                }
                self.number += 1;
                let units = (u64::from(hi) << 32) | u64::from(lo);
                Ok(Some(Frame {
                    number: self.number,
                    linktype: iface.linktype,
                    micros: i64::try_from(u128::from(units) * 1_000_000 / u128::from(iface.units))
                        .ok(),
                    data: body[20..20 + caplen].to_vec(),
                }))
            }
            _ => {
                if body.len() < 4 {
                    return Err(short());
                }
                let iface = *interfaces.first().ok_or_else(|| {
                    CaptureError::Corrupt("a simple packet comes before any interface".into())
                })?;
                let mut caplen = endian.u32(body) as usize;
                if iface.snaplen != 0 {
                    caplen = caplen.min(iface.snaplen as usize);
                }
                if caplen > MAX_PACKET || caplen > body.len() - 4 {
                    return Err(CaptureError::Corrupt(format!(
                        "a packet claims to be {caplen} bytes long"
                    )));
                }
                self.number += 1;
                Ok(Some(Frame {
                    number: self.number,
                    linktype: iface.linktype,
                    micros: None,
                    data: body[4..4 + caplen].to_vec(),
                }))
            }
        }
    }
}

/// The if_tsresol option: a power of ten, or of two when the top bit is set.
fn timestamp_units(mut options: &[u8], endian: Endian) -> Option<u64> {
    while options.len() >= 4 {
        let code = endian.u16(options);
        let len = usize::from(endian.u16(&options[2..]));
        let padded = len.checked_add(3)? / 4 * 4;
        let value = options.get(4..4 + len)?;
        if code == 0 {
            return None;
        }
        if code == 9 && len == 1 {
            let (base, exp) = if value[0] & 0x80 != 0 {
                (2u64, value[0] & 0x7f)
            } else {
                (10, value[0])
            };
            // Past this the unit count no longer fits, and no capture has such a clock.
            return base.checked_pow(u32::from(exp)).filter(|u| *u > 0);
        }
        options = options.get(4 + padded..)?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pcap(magic: [u8; 4], big: bool, linktype: u32, packets: &[&[u8]]) -> Vec<u8> {
        let w32 = |v: u32| {
            if big {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            }
        };
        let mut out = magic.to_vec();
        out.extend_from_slice(&[0; 16]);
        out.extend_from_slice(&w32(linktype));
        for (i, p) in packets.iter().enumerate() {
            out.extend_from_slice(&w32(1000 + i as u32));
            out.extend_from_slice(&w32(5000));
            out.extend_from_slice(&w32(p.len() as u32));
            out.extend_from_slice(&w32(p.len() as u32));
            out.extend_from_slice(p);
        }
        out
    }

    fn all(data: &[u8]) -> Vec<Frame> {
        let mut r = Reader::new(data).unwrap();
        let mut out = Vec::new();
        while let Some(f) = r.next_frame().unwrap() {
            out.push(f);
        }
        out
    }

    #[test]
    fn pcap_in_each_byte_order_and_precision() {
        for (magic, big, micros) in [
            ([0xd4, 0xc3, 0xb2, 0xa1], false, 1_000_005_000),
            ([0xa1, 0xb2, 0xc3, 0xd4], true, 1_000_005_000),
            ([0x4d, 0x3c, 0xb2, 0xa1], false, 1_000_000_005),
            ([0xa1, 0xb2, 0x3c, 0x4d], true, 1_000_000_005),
        ] {
            let frames = all(&pcap(magic, big, 113, &[b"abc", b"de"]));
            assert_eq!(frames.len(), 2);
            assert_eq!(
                frames[0],
                Frame {
                    number: 1,
                    linktype: 113,
                    micros: Some(micros),
                    data: b"abc".to_vec()
                }
            );
            assert_eq!(
                (frames[1].number, frames[1].data.as_slice()),
                (2, &b"de"[..])
            );
        }
    }

    #[test]
    fn a_capture_cut_short_keeps_what_it_has() {
        let data = pcap([0xd4, 0xc3, 0xb2, 0xa1], false, 1, &[b"abc", b"defgh"]);
        for cut in [1, 3, 10, 20] {
            let mut r = Reader::new(&data[..data.len() - cut]).unwrap();
            assert_eq!(r.next_frame().unwrap().unwrap().data, b"abc");
            assert!(r.next_frame().unwrap().is_none());
            assert!(r.truncated, "cut {cut}");
        }
    }

    #[test]
    fn lying_lengths_are_refused_before_any_allocation() {
        let mut data = pcap([0xd4, 0xc3, 0xb2, 0xa1], false, 1, &[b"abc"]);
        data[24 + 8..24 + 12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            Reader::new(&data[..]).unwrap().next_frame(),
            Err(CaptureError::Corrupt(_))
        ));
    }

    #[test]
    fn other_files_are_refused() {
        for data in [
            &b""[..],
            b"ab",
            b"GET / HTTP/1.1\r\n",
            &[0xd4, 0xc3, 0xb2, 0xa1, 0, 0],
        ] {
            assert!(
                matches!(Reader::new(data), Err(CaptureError::NotACapture)),
                "{data:?}"
            );
        }
    }

    fn block(big: bool, kind: u32, body: &[u8]) -> Vec<u8> {
        let w32 = |v: u32| {
            if big {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            }
        };
        let total = 12 + body.len() as u32;
        let mut out = w32(kind).to_vec();
        out.extend_from_slice(&w32(total));
        out.extend_from_slice(body);
        out.extend_from_slice(&w32(total));
        out
    }

    fn shb(big: bool) -> Vec<u8> {
        let magic = if big {
            0x1a2b_3c4du32.to_be_bytes()
        } else {
            0x1a2b_3c4du32.to_le_bytes()
        };
        let mut body = magic.to_vec();
        body.extend_from_slice(&[0; 12]);
        block(big, BLOCK_SECTION, &body)
    }

    fn idb(big: bool, linktype: u16, options: &[u8]) -> Vec<u8> {
        let mut body = if big {
            linktype.to_be_bytes()
        } else {
            linktype.to_le_bytes()
        }
        .to_vec();
        body.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        body.extend_from_slice(options);
        block(big, BLOCK_INTERFACE, &body)
    }

    fn epb(big: bool, iface: u32, ts: u64, data: &[u8]) -> Vec<u8> {
        let w32 = |v: u32| {
            if big {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            }
        };
        let mut body = w32(iface).to_vec();
        body.extend_from_slice(&w32((ts >> 32) as u32));
        body.extend_from_slice(&w32(ts as u32));
        body.extend_from_slice(&w32(data.len() as u32));
        body.extend_from_slice(&w32(data.len() as u32));
        body.extend_from_slice(data);
        while body.len() % 4 != 0 {
            body.push(0);
        }
        block(big, BLOCK_ENHANCED_PACKET, &body)
    }

    #[test]
    fn pcapng_in_each_byte_order_with_several_interfaces_and_clocks() {
        for big in [false, true] {
            // if_tsresol = 9 means nanoseconds; the option is padded to four bytes.
            let code: [u8; 2] = if big {
                9u16.to_be_bytes()
            } else {
                9u16.to_le_bytes()
            };
            let one: [u8; 2] = if big {
                1u16.to_be_bytes()
            } else {
                1u16.to_le_bytes()
            };
            let options = [code[0], code[1], one[0], one[1], 9, 0, 0, 0, 0, 0, 0, 0];
            let mut data = shb(big);
            data.extend(idb(big, 1, &[]));
            data.extend(idb(big, 113, &options));
            data.extend(block(big, 4, &[0; 8])); // a name resolution block is skipped
            data.extend(epb(big, 0, 7_000_000, b"abcde"));
            data.extend(epb(big, 1, 7_000_000_000, b"xy"));
            let frames = all(&data);
            assert_eq!(frames.len(), 2);
            assert_eq!(
                frames[0],
                Frame {
                    number: 1,
                    linktype: 1,
                    micros: Some(7_000_000),
                    data: b"abcde".to_vec()
                }
            );
            assert_eq!(
                frames[1],
                Frame {
                    number: 2,
                    linktype: 113,
                    micros: Some(7_000_000),
                    data: b"xy".to_vec()
                }
            );
        }
    }

    #[test]
    fn a_new_section_replaces_the_interfaces_and_may_change_byte_order() {
        let mut data = shb(false);
        data.extend(idb(false, 1, &[]));
        data.extend(epb(false, 0, 1, b"a"));
        data.extend(shb(true));
        data.extend(idb(true, 113, &[]));
        data.extend(epb(true, 0, 1, b"b"));
        let frames = all(&data);
        assert_eq!((frames[1].linktype, frames[1].number), (113, 2));
    }

    #[test]
    fn simple_packets_use_the_first_interface_and_its_snap_length() {
        let mut body = 5u32.to_le_bytes().to_vec();
        body.extend_from_slice(b"abcd");
        let mut iface_body = 1u16.to_le_bytes().to_vec();
        iface_body.extend_from_slice(&[0, 0]);
        iface_body.extend_from_slice(&4u32.to_le_bytes());
        let mut data = shb(false);
        data.extend(block(false, BLOCK_INTERFACE, &iface_body));
        data.extend(block(false, BLOCK_SIMPLE_PACKET, &body));
        let frames = all(&data);
        assert_eq!(frames[0].data, b"abcd");
        assert_eq!(frames[0].micros, None);
    }

    #[test]
    fn broken_pcapng_blocks_are_errors_not_panics() {
        let cases: Vec<Vec<u8>> = vec![
            // A packet on an interface nobody declared.
            [shb(false), epb(false, 3, 0, b"x")].concat(),
            // A capture length past the end of its block.
            {
                let mut d = [shb(false), idb(false, 1, &[]), epb(false, 0, 0, b"abcd")].concat();
                let at = d.len() - 4 - 4 - 8;
                d[at..at + 4].copy_from_slice(&999u32.to_le_bytes());
                d
            },
            // Block lengths that cannot be right.
            [
                shb(false),
                6u32.to_le_bytes().to_vec(),
                5u32.to_le_bytes().to_vec(),
            ]
            .concat(),
            [
                shb(false),
                6u32.to_le_bytes().to_vec(),
                4u32.to_le_bytes().to_vec(),
            ]
            .concat(),
            [
                shb(false),
                6u32.to_le_bytes().to_vec(),
                0xffff_fff0u32.to_le_bytes().to_vec(),
            ]
            .concat(),
            // Too short for its type.
            [shb(false), block(false, BLOCK_INTERFACE, &[0; 4])].concat(),
            [
                shb(false),
                idb(false, 1, &[]),
                block(false, BLOCK_ENHANCED_PACKET, &[0; 8]),
            ]
            .concat(),
            [shb(false), block(false, BLOCK_SIMPLE_PACKET, &[0; 8])].concat(),
        ];
        for (i, data) in cases.iter().enumerate() {
            let mut r = Reader::new(&data[..]).unwrap();
            assert!(
                matches!(r.next_frame(), Err(CaptureError::Corrupt(_))),
                "case {i}"
            );
        }
    }

    #[test]
    fn lengths_that_cannot_be_right_are_refused() {
        // A section header too short for its fixed fields, and one that is not a multiple of 4.
        for total in [16u32, 29] {
            let mut data = shb(false);
            data[4..8].copy_from_slice(&total.to_le_bytes());
            assert!(
                matches!(Reader::new(&data[..]), Err(CaptureError::Corrupt(_))),
                "{total}"
            );
        }
        // A block length long enough but not a multiple of 4.
        let data = [
            shb(false),
            6u32.to_le_bytes().to_vec(),
            13u32.to_le_bytes().to_vec(),
        ]
        .concat();
        assert!(matches!(
            Reader::new(&data[..]).unwrap().next_frame(),
            Err(CaptureError::Corrupt(_))
        ));
        // A packet over the limit, in a block large enough to hold it.
        let huge = vec![0u8; MAX_PACKET + 1];
        let data = [shb(false), idb(false, 1, &[]), epb(false, 0, 0, &huge)].concat();
        let mut r = Reader::new(&data[..]).unwrap();
        assert!(matches!(r.next_frame(), Err(CaptureError::Corrupt(_))));
    }

    #[test]
    fn a_section_header_without_its_magic_is_corrupt() {
        let mut data = shb(false);
        data[8] = 0;
        assert!(matches!(
            Reader::new(&data[..]),
            Err(CaptureError::Corrupt(_))
        ));
    }

    #[test]
    fn timestamp_resolution_in_powers_of_two_and_broken_options() {
        let le = |c: u16, l: u16| [c.to_le_bytes(), l.to_le_bytes()].concat();
        assert_eq!(
            timestamp_units(
                &[le(9, 1), vec![0x80 | 10, 0, 0, 0]].concat(),
                Endian::Little
            ),
            Some(1024)
        );
        assert_eq!(
            timestamp_units(
                &[le(2, 3), vec![1, 2, 3, 0], le(9, 1), vec![3, 0, 0, 0]].concat(),
                Endian::Little
            ),
            Some(1000)
        );
        assert_eq!(
            timestamp_units(&[le(9, 1), vec![200, 0, 0, 0]].concat(), Endian::Little),
            None,
            "too large"
        );
        assert_eq!(
            timestamp_units(&le(9, 500), Endian::Little),
            None,
            "runs off the end"
        );
        assert_eq!(
            timestamp_units(
                &[le(0, 0), le(9, 1), vec![3, 0, 0, 0]].concat(),
                Endian::Little
            ),
            None,
            "end of options"
        );
    }
}
