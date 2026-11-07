mod common;

use std::path::PathBuf;

use common::*;
use tlsprint::cli::{printable, run};

fn tlsprint(args: &[&str], stdin: &[u8]) -> (i32, String, String) {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut input = stdin;
    let code = run(&args, &mut input, &mut out, &mut err);
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

fn temp(name: &str, bytes: &[u8]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tlsprint-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

const DEMO: &str = "testdata/demo.pcap";
const WATCH: &str = "testdata/watch.csv";

#[test]
fn the_committed_demo_capture_is_what_the_generator_writes() {
    assert!(
        std::fs::read(DEMO).unwrap() == demo_capture(),
        "run: cargo run --example mkfixture"
    );
}

#[test]
fn text_output_names_each_client_and_the_summary_groups_them() {
    let (code, out, err) = tlsprint(&[DEMO], b"");
    assert_eq!(code, 0);
    assert_eq!(out.lines().count(), 4);
    assert!(out.contains("frame 4  192.0.2.10:50000 -> 198.51.100.7:443  t13d1516h2_8daaf6152771_e5627efa2ab1  sni=www.example.org  alpn=h2\n"));
    assert!(
        out.contains(
            "frame 6  192.0.2.12:50002 -> 203.0.113.9:8443  t12i040400_93657e4f18b9_c81523bf1a9d\n"
        ),
        "no SNI or ALPN to show"
    );
    assert!(err.contains("7 frames, 4 clients"));

    let (_, out, _) = tlsprint(&["--summary", DEMO], b"");
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 3);
    assert!(
        lines[0].starts_with("     2  t13d1516h2_8daaf6152771_e5627efa2ab1  www.example.org"),
        "most common first"
    );
    assert!(lines[2].ends_with("(no SNI)"));
}

#[test]
fn the_summary_shows_three_names_and_counts_the_rest() {
    let frames: Vec<Vec<u8>> = [
        "a.example",
        "b.example",
        "c.example",
        "d.example",
        "e.example",
    ]
    .iter()
    .enumerate()
    .map(|(i, name)| {
        let body = hello_body(
            &HelloSpec {
                version: 0x0303,
                ciphers: &[1],
                plain_extensions: &[],
                sni: Some(name),
                alpn: &[],
                signatures: &[],
                supported_versions: &[],
            },
            false,
        );
        tcp_frame(
            (CLIENT, 40000 + i as u16),
            (SERVER, 443),
            1,
            FLAG_ACK,
            &record(&handshake(&body)),
        )
    })
    .collect();
    let (_, out, _) = tlsprint(&["--summary", "-"], &pcap(&frames));
    assert!(
        out.contains("a.example, b.example, c.example and 2 more"),
        "{out}"
    );
}

#[test]
fn json_output_has_every_form_of_the_fingerprint() {
    let (code, out, _) = tlsprint(&["--json", DEMO], b"");
    assert_eq!(code, 0);
    let rows: Vec<serde_json::Value> = out
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(rows.len(), 4);
    let first = &rows[0];
    assert_eq!(first["ja4"], "t13d1516h2_8daaf6152771_e5627efa2ab1");
    assert_eq!(first["protocol"], "tls");
    assert_eq!(first["src"], "192.0.2.10");
    assert_eq!(first["src_port"], 50000);
    assert_eq!(first["dst_port"], 443);
    assert_eq!(first["frame"], 4);
    assert_eq!(first["time_us"], 1_700_000_003_000_000i64);
    assert_eq!(first["sni"], "www.example.org");
    assert_eq!(first["alpn"], "h2");
    assert!(first["ja4_r"].as_str().unwrap().contains("002f,0035"));
    assert!(first["ja4_o"].as_str().unwrap().starts_with("t13d1516h2_"));
    assert!(first["ja4_ro"].as_str().unwrap().contains("1301,1302"));
    assert!(first.get("watch").is_none() && first.get("file").is_none());
    assert_eq!(rows[3]["protocol"], "quic");
    assert_eq!(rows[2]["sni"], serde_json::Value::Null);
}

#[test]
fn raw_and_original_add_lines() {
    let (_, out, _) = tlsprint(&["--raw", DEMO], b"");
    assert!(out.contains("\n  ja4_r  t13d1516h2_002f,0035,"));
    assert!(!out.contains("ja4_o"));
    let (_, out, _) = tlsprint(&["--original", DEMO], b"");
    assert!(out.contains("\n  ja4_o  t13d1516h2_"));
    assert!(out.contains("\n  ja4_ro t13d1516h2_1301,1302,"));
}

#[test]
fn the_watch_list_marks_filters_and_sets_the_exit_status() {
    let (code, out, _) = tlsprint(&["--watch", WATCH, DEMO], b"");
    assert_eq!(code, 1);
    assert_eq!(out.lines().count(), 4);
    assert_eq!(out.matches("WATCH").count(), 3);
    let (code, out, _) = tlsprint(&["--watch", WATCH, "--hits", DEMO], b"");
    assert_eq!(code, 1);
    assert_eq!(out.lines().count(), 3);
    assert!(!out.contains("q13"));
    let (code, out, _) = tlsprint(&["--watch", WATCH, "--hits", "--summary", DEMO], b"");
    assert_eq!(code, 1);
    assert_eq!(out.lines().count(), 2);
    assert!(out.contains("WATCH TLS 1.2 to a bare IP address"));
    let (_, out, _) = tlsprint(&["--watch", WATCH, "--json", DEMO], b"");
    let first: serde_json::Value = serde_json::from_str(out.lines().next().unwrap()).unwrap();
    assert_eq!(
        first["watch"][0],
        "the cipher list of the client under investigation"
    );
    let clean = temp("clean.csv", b"zzz_*_*\n");
    let (code, out, _) = tlsprint(&["--watch", clean.to_str().unwrap(), "--hits", DEMO], b"");
    assert_eq!((code, out.as_str()), (0, ""));
}

#[test]
fn several_captures_are_told_apart_and_read_from_stdin() {
    let demo = std::fs::read(DEMO).unwrap();
    let (code, out, err) = tlsprint(&[DEMO, "-"], &demo);
    assert_eq!(code, 0);
    assert_eq!(out.lines().count(), 8);
    assert!(out.contains("testdata/demo.pcap: frame 4  "));
    assert!(out.contains("-: frame 4  "));
    assert_eq!(err.matches("4 clients").count(), 2);
    let (_, out, _) = tlsprint(&["--json", DEMO, DEMO], b"");
    let first: serde_json::Value = serde_json::from_str(out.lines().next().unwrap()).unwrap();
    assert_eq!(first["file"], DEMO);
}

#[test]
fn a_hostile_server_name_cannot_reach_the_terminal() {
    let name = "evil\u{1b}[2J\u{7}.example\\";
    let body = hello_body(
        &HelloSpec {
            version: 0x0303,
            ciphers: &[1],
            plain_extensions: &[],
            sni: Some(name),
            alpn: &["\u{1b}]0;x"],
            signatures: &[],
            supported_versions: &[],
        },
        false,
    );
    let capture = pcap(&[tcp_frame(
        (CLIENT, 1),
        (SERVER, 443),
        1,
        FLAG_ACK,
        &record(&handshake(&body)),
    )]);
    let (_, out, _) = tlsprint(&["-"], &capture);
    assert!(!out.contains('\u{1b}') && !out.contains('\u{7}'), "{out:?}");
    assert!(out.contains(r"sni=evil\x1b[2J\x07.example\\"), "{out:?}");
    assert!(out.contains(r"alpn=\x1b]0;x"), "{out:?}");
    let (_, out, _) = tlsprint(&["--summary", "-"], &capture);
    assert!(!out.contains('\u{1b}'), "{out:?}");
    assert_eq!(
        printable(&[0x7e, 0x7f, 0x20, 0x1f, 0xff]),
        r"~\x7f \x1f\xff"
    );
}

#[test]
fn notes_say_what_was_passed_over() {
    let mut fragment = tcp_frame((CLIENT, 1), (SERVER, 443), 1, FLAG_ACK, b"x");
    fragment[20] = 0x20;
    let refused = tcp_frame(
        (CLIENT, 2),
        (SERVER, 443),
        1,
        FLAG_ACK,
        &record(&[1, 0, 0, 2, 3, 3]),
    );
    let mut capture = pcap(&[vec![0; 3], fragment, refused]);
    let (code, _, err) = tlsprint(&["-"], &capture);
    assert_eq!(code, 0);
    assert!(
        err.contains(
            "3 frames, 0 clients; 1 malformed; 1 IP fragments, not reassembled; 1 hellos refused"
        ),
        "{err}"
    );
    capture.truncate(capture.len() - 1);
    let (code, _, err) = tlsprint(&["-"], &capture);
    assert_eq!(code, 0);
    assert!(
        err.contains("the capture ends partway through a packet"),
        "{err}"
    );
}

#[test]
fn errors_exit_with_two_and_other_captures_are_still_read() {
    let not_capture = temp("note.txt", b"this is not a capture");
    let (code, out, err) = tlsprint(&[not_capture.to_str().unwrap(), DEMO], b"");
    assert_eq!(code, 2);
    assert!(err.contains("not a pcap or pcapng file"), "{err}");
    assert_eq!(out.lines().count(), 4, "the good capture is still read");
    let (code, _, err) = tlsprint(&["testdata/no-such-file.pcap"], b"");
    assert_eq!(code, 2);
    assert!(err.contains("no-such-file"));
    let mut corrupt = demo_capture();
    corrupt[24 + 8..24 + 12].copy_from_slice(&u32::MAX.to_le_bytes());
    let (code, _, err) = tlsprint(&["-"], &corrupt);
    assert_eq!(code, 2);
    assert!(err.contains("corrupt capture"), "{err}");
    // Failure outranks a watch hit: the list cannot be called checked if a capture was not read.
    let (code, _, _) = tlsprint(&["--watch", WATCH, DEMO, "testdata/no-such-file.pcap"], b"");
    assert_eq!(code, 2);
}

#[test]
fn usage_errors() {
    let bad_watch = temp("bad.csv", b"not_a_fingerprint_at_all,x\n");
    let bad_watch = bad_watch.to_str().unwrap();
    for (args, want) in [
        (vec![], "no capture named"),
        (vec!["--nope", DEMO], "unknown flag --nope"),
        (vec!["--hits", DEMO], "--hits needs --watch"),
        (vec!["--summary", "--json", DEMO], "cannot be combined"),
        (vec!["--watch"], "--watch needs a file"),
        (
            vec!["--watch", "testdata/no-such-list", DEMO],
            "no-such-list",
        ),
        (vec!["--watch", bad_watch, DEMO], "line 1"),
    ] {
        let (code, _, err) = tlsprint(&args, b"");
        assert_eq!(code, 2, "{args:?}");
        assert!(err.contains(want), "{args:?}: {err}");
    }
    let (code, out, _) = tlsprint(&["--help"], b"");
    assert!(code == 0 && out.contains("usage:"));
    let (code, out, _) = tlsprint(&["-h"], b"");
    assert!(code == 0 && out.contains("usage:"));
    let (code, out, _) = tlsprint(&["--version"], b"");
    assert!(code == 0 && out.starts_with("tlsprint "));
    // After --, even a name that looks like a flag is a file.
    let (code, _, err) = tlsprint(&["--", "--json"], b"");
    assert_eq!(code, 2);
    assert!(!err.contains("unknown flag"), "{err}");
}

#[test]
fn ipv6_addresses_are_bracketed() {
    let (_, out, _) = tlsprint(&["-"], &ipv6_capture());
    assert!(
        out.contains("[2001:db8::1]:50000 -> [2001:db8::2]:443"),
        "{out}"
    );
}

fn ipv6_capture() -> Vec<u8> {
    let stream = record(&handshake(&spec_hello()));
    let mut t = 50000u16.to_be_bytes().to_vec();
    t.extend_from_slice(&443u16.to_be_bytes());
    t.extend_from_slice(&[
        0, 0, 0, 1, 0, 0, 0, 0, 0x50, FLAG_ACK, 0xff, 0xff, 0, 0, 0, 0,
    ]);
    t.extend_from_slice(&stream);
    let mut f = vec![0u8; 12];
    f.extend_from_slice(&[0x86, 0xdd, 0x60, 0, 0, 0]);
    f.extend_from_slice(&(t.len() as u16).to_be_bytes());
    f.extend_from_slice(&[6, 64, 0x20, 0x01, 0x0d, 0xb8]);
    f.extend_from_slice(&[0; 11]);
    f.push(1);
    f.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
    f.extend_from_slice(&[0; 11]);
    f.push(2);
    f.extend(t);
    pcap(&[f])
}
