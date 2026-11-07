//! The JA4 fingerprint of a ClientHello, as FoxIO's specification defines it.

use sha2::{Digest, Sha256};

use crate::tls::ClientHello;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Quic,
    Dtls,
}

/// GREASE values are reserved noise clients send to keep servers honest: 0x0a0a, 0x1a1a, ...
pub fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    /// The fingerprint: `t13d1516h2_8daaf6152771_e5627efa2ab1`.
    pub ja4: String,
    /// With the lists it hashes written out instead, which is what to read when two differ.
    pub ja4_r: String,
    /// As `ja4`, in the order the client sent things, with SNI and ALPN left in the list.
    pub ja4_o: String,
    /// As `ja4_r`, in the order the client sent things.
    pub ja4_ro: String,
}

fn version_code(v: u16) -> &'static str {
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        0xfeff => "d1",
        0xfefd => "d2",
        0xfefc => "d3",
        _ => "00",
    }
}

fn is_alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

fn alpn_code(alpn: Option<&[u8]>) -> String {
    let Some(value) = alpn.filter(|a| !a.is_empty()) else {
        return "00".into();
    };
    let (first, last) = (value[0], value[value.len() - 1]);
    if is_alnum(first) && is_alnum(last) {
        return format!("{}{}", first as char, last as char);
    }
    // Otherwise the first and last characters of the value written in hex.
    format!("{:x}{:x}", first >> 4, last & 0x0f)
}

fn hex_list(values: &[u16]) -> String {
    let parts: Vec<String> = values.iter().map(|v| format!("{v:04x}")).collect();
    parts.join(",")
}

fn truncated_hash(text: &str) -> String {
    let digest = Sha256::digest(text.as_bytes());
    let mut out = String::with_capacity(12);
    for b in &digest[..6] {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// A list's hash, or twelve zeros when the list has nothing in it.
fn hash_or_zeros(empty: bool, text: &str) -> String {
    if empty {
        "000000000000".into()
    } else {
        truncated_hash(text)
    }
}

fn two_digits(n: usize) -> String {
    format!("{:02}", n.min(99))
}

impl Fingerprint {
    pub fn of(hello: &ClientHello, protocol: Protocol) -> Fingerprint {
        let keep = |list: &[u16]| -> Vec<u16> {
            list.iter().copied().filter(|v| !is_grease(*v)).collect()
        };
        let ciphers = keep(&hello.ciphers);
        let extensions = keep(&hello.extensions);
        let signatures = keep(&hello.signature_algorithms);
        let version = keep(&hello.supported_versions)
            .into_iter()
            .max()
            .unwrap_or(hello.version);

        let a = format!(
            "{}{}{}{}{}{}",
            match protocol {
                Protocol::Tcp => 't',
                Protocol::Quic => 'q',
                Protocol::Dtls => 'd',
            },
            version_code(version),
            if extensions.contains(&0x0000) {
                'd'
            } else {
                'i'
            },
            two_digits(ciphers.len()),
            two_digits(extensions.len()),
            alpn_code(hello.alpn_first.as_deref()),
        );

        let mut sorted_ciphers = ciphers.clone();
        sorted_ciphers.sort_unstable();
        let mut hashed_extensions: Vec<u16> = extensions
            .iter()
            .copied()
            .filter(|e| !matches!(e, 0x0000 | 0x0010))
            .collect();
        hashed_extensions.sort_unstable();

        let with_signatures = |list: &[u16]| {
            if signatures.is_empty() {
                hex_list(list)
            } else {
                format!("{}_{}", hex_list(list), hex_list(&signatures))
            }
        };
        let sorted_c = with_signatures(&hashed_extensions);
        let original_c = with_signatures(&extensions);
        let b_sorted = hex_list(&sorted_ciphers);
        let b_original = hex_list(&ciphers);

        Fingerprint {
            ja4: format!(
                "{a}_{}_{}",
                hash_or_zeros(ciphers.is_empty(), &b_sorted),
                hash_or_zeros(hashed_extensions.is_empty(), &sorted_c),
            ),
            ja4_r: format!("{a}_{b_sorted}_{sorted_c}"),
            ja4_o: format!(
                "{a}_{}_{}",
                hash_or_zeros(ciphers.is_empty(), &b_original),
                hash_or_zeros(extensions.is_empty(), &original_c),
            ),
            ja4_ro: format!("{a}_{b_original}_{original_c}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example ClientHello worked through in FoxIO's JA4.md.
    fn spec_example() -> ClientHello {
        ClientHello {
            version: 0x0303,
            ciphers: vec![
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            extensions: vec![
                0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023,
                0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
            ],
            supported_versions: vec![0x0304, 0x0303],
            signature_algorithms: vec![
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ],
            server_name: Some(b"example.org".to_vec()),
            alpn_first: Some(b"h2".to_vec()),
        }
    }

    #[test]
    fn the_specifications_worked_example() {
        let f = Fingerprint::of(&spec_example(), Protocol::Tcp);
        assert_eq!(f.ja4, "t13d1516h2_8daaf6152771_e5627efa2ab1");
        assert_eq!(f.ja4_o, "t13d1516h2_acb858a92679_18f69afefd3d");
        assert_eq!(
            f.ja4_r,
            "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601"
        );
        assert_eq!(
            f.ja4_ro,
            "t13d1516h2_1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035_001b,0000,0033,0010,4469,0017,002d,000d,0005,0023,0012,002b,ff01,000b,000a,0015_0403,0804,0401,0503,0805,0501,0806,0601"
        );
    }

    #[test]
    fn without_signature_algorithms_the_string_ends_without_an_underscore() {
        let mut h = spec_example();
        h.signature_algorithms.clear();
        assert!(Fingerprint::of(&h, Protocol::Tcp)
            .ja4
            .ends_with("_6d807ffa2a79"));
    }

    #[test]
    fn grease_is_ignored_everywhere_and_changes_nothing() {
        let plain = Fingerprint::of(&spec_example(), Protocol::Tcp);
        let mut h = spec_example();
        h.ciphers.insert(0, 0x0a0a);
        h.ciphers.push(0xfafa);
        h.extensions.insert(0, 0x1a1a);
        h.extensions.push(0x2a2a);
        h.signature_algorithms.insert(1, 0x3a3a);
        h.supported_versions.insert(0, 0x4a4a);
        assert_eq!(Fingerprint::of(&h, Protocol::Tcp), plain);
    }

    #[test]
    fn what_counts_as_grease() {
        for v in [
            0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa,
            0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
        ] {
            assert!(is_grease(v), "{v:04x}");
        }
        for v in [
            0x0a1a, 0x1a0a, 0x0a0b, 0x0b0a, 0x0000, 0x00ff, 0x5600, 0xfe00,
        ] {
            assert!(!is_grease(v), "{v:04x}");
        }
    }

    fn a_section(h: &ClientHello, p: Protocol) -> String {
        Fingerprint::of(h, p)
            .ja4
            .split('_')
            .next()
            .unwrap()
            .to_string()
    }

    #[test]
    fn the_version_comes_from_the_highest_supported_version_or_the_hello() {
        for (legacy, supported, want) in [
            (0x0303, vec![0x0304, 0x0303], "13"),
            (0x0303, vec![0x0303, 0x0304], "13"),
            (0x0303, vec![], "12"),
            (0x0302, vec![], "11"),
            (0x0301, vec![], "10"),
            (0x0300, vec![], "s3"),
            (0x0002, vec![], "s2"),
            (0xfeff, vec![], "d1"),
            (0xfefd, vec![], "d2"),
            (0xfefc, vec![], "d3"),
            (0x1234, vec![], "00"),
            (0x0303, vec![0x0a0a], "12"),
        ] {
            let h = ClientHello {
                version: legacy,
                supported_versions: supported.clone(),
                ..Default::default()
            };
            assert_eq!(
                &a_section(&h, Protocol::Tcp)[1..3],
                want,
                "{legacy:04x} {supported:?}"
            );
        }
    }

    #[test]
    fn the_first_letter_names_the_transport_and_sni_comes_from_the_extension() {
        let h = ClientHello::default();
        assert!(a_section(&h, Protocol::Tcp).starts_with('t'));
        assert!(a_section(&h, Protocol::Quic).starts_with('q'));
        assert!(a_section(&h, Protocol::Dtls).starts_with('d'));
        assert_eq!(&a_section(&h, Protocol::Tcp)[3..4], "i");
        // The extension counts even when the name in it could not be read.
        let named = ClientHello {
            extensions: vec![0],
            ..Default::default()
        };
        assert_eq!(&a_section(&named, Protocol::Tcp)[3..4], "d");
    }

    #[test]
    fn counts_are_two_digits_and_stop_at_99() {
        let h = ClientHello {
            ciphers: (1..=150).collect(),
            extensions: vec![0x0005; 6],
            ..Default::default()
        };
        assert_eq!(&a_section(&h, Protocol::Tcp)[4..8], "9906");
        let h = ClientHello {
            ciphers: (1..=99).collect(),
            extensions: (1..=100).collect(),
            ..Default::default()
        };
        assert_eq!(&a_section(&h, Protocol::Tcp)[4..8], "9999");
    }

    #[test]
    fn the_specifications_alpn_table() {
        for (value, want) in [
            (&b"h2"[..], "h2"),
            (b"http/1.1", "h1"),
            (b"a", "aa"),
            (&[0xab], "ab"),
            (&[0x20], "20"),
            (&[0xab, 0xcd], "ad"),
            (&[0x20, 0x61], "21"),
            (&[0x30, 0xab], "3b"),
            (&[0x61, 0x20], "60"),
            (&[0x30, 0x31, 0xab, 0xcd], "3d"),
            (&[0x30, 0xab, 0xcd, 0x31], "01"),
        ] {
            assert_eq!(alpn_code(Some(value)), want, "{value:?}");
        }
        assert_eq!(alpn_code(None), "00");
        assert_eq!(alpn_code(Some(b"")), "00");
    }

    #[test]
    fn empty_lists_hash_to_zeros_rather_than_the_hash_of_nothing() {
        let f = Fingerprint::of(
            &ClientHello {
                version: 0x0303,
                ..Default::default()
            },
            Protocol::Tcp,
        );
        assert_eq!(f.ja4, "t12i000000_000000000000_000000000000");
        // Only SNI and ALPN: nothing left to hash in the sorted form, but the original keeps them.
        let h = ClientHello {
            version: 0x0303,
            extensions: vec![0, 0x10],
            ..Default::default()
        };
        let f = Fingerprint::of(&h, Protocol::Tcp);
        assert!(f.ja4.ends_with("_000000000000"));
        assert!(!f.ja4_o.ends_with("_000000000000"));
        // Signature algorithms with no other extension to hash still give zeros.
        let h = ClientHello {
            version: 0x0303,
            extensions: vec![0x10],
            signature_algorithms: vec![0x0403],
            ..Default::default()
        };
        assert!(Fingerprint::of(&h, Protocol::Tcp)
            .ja4
            .ends_with("_000000000000"));
    }

    #[test]
    fn scsv_and_reserved_ciphers_still_count() {
        let h = ClientHello {
            ciphers: vec![0x00ff, 0x5600, 0xfe00],
            ..Default::default()
        };
        assert_eq!(&a_section(&h, Protocol::Tcp)[4..6], "03");
    }
}
