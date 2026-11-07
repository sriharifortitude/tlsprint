//! The command line: reads captures, prints fingerprints, checks them against a watch list.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufReader, Read, Write};

use serde_json::json;

use crate::capture::{CaptureError, Reader};
use crate::flow::{Sighting, Stats, Tracker};
use crate::ja4::Protocol;
use crate::watch::WatchList;

const USAGE: &str = "tlsprint: JA4 fingerprints of the TLS and QUIC clients in packet captures.

usage: tlsprint [flags] CAPTURE...      a pcap or pcapng file, or - for standard input

flags:
  --summary       one line per fingerprint: how many, and which server names
  --json          one JSON object per client
  --raw           also print each fingerprint's lists in full (JA4_r)
  --original      also print the fingerprints in the client's own order (JA4_o, JA4_ro)
  --watch FILE    mark fingerprints on a watch list: `fingerprint,label` per line, # for comments,
                  and * for a whole section or the end of one (t13d*_*_e5627efa2ab1)
  --hits          with --watch, print only the clients on the list
  --version

exit status: 0 nothing on the watch list, 1 something on it, 2 usage error or unreadable capture
";

#[derive(Default)]
struct Options {
    summary: bool,
    json: bool,
    raw: bool,
    original: bool,
    hits: bool,
    watch: Option<WatchList>,
    captures: Vec<String>,
}

pub fn run(args: &[String], stdin: &mut dyn Read, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    match run_inner(args, stdin, out, err) {
        Ok(code) => code,
        // A closed pipe is the reader having seen enough, as with `| head`.
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => 0,
        Err(e) => {
            let _ = writeln!(err, "tlsprint: {e}");
            2
        }
    }
}

fn run_inner(
    args: &[String],
    stdin: &mut dyn Read,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> io::Result<i32> {
    let opts = match parse_args(args) {
        Ok(Some(opts)) => opts,
        Ok(None) => {
            write!(out, "{USAGE}")?;
            return Ok(0);
        }
        Err(Parsed::Version) => {
            writeln!(out, "tlsprint {}", env!("CARGO_PKG_VERSION"))?;
            return Ok(0);
        }
        Err(Parsed::Bad(why)) => {
            write!(err, "tlsprint: {why}\n\n{USAGE}")?;
            return Ok(2);
        }
    };
    let mut failed = false;
    let mut hit = false;
    let mut summary: BTreeMap<String, Group> = BTreeMap::new();
    let several = opts.captures.len() > 1;
    for name in &opts.captures {
        let file_label = if several { Some(name.as_str()) } else { None };
        let result = if name == "-" {
            scan(&mut *stdin, &opts, file_label, &mut summary, out)
        } else {
            match File::open(name) {
                Ok(f) => scan(BufReader::new(f), &opts, file_label, &mut summary, out),
                Err(e) => Err(ScanError::Capture(CaptureError::Io(e))),
            }
        };
        match result {
            Ok(done) => {
                hit |= done.hit;
                let stats = &done.stats;
                let mut notes = Vec::new();
                for (n, what) in [
                    (stats.malformed, "malformed"),
                    (stats.ip_fragments, "IP fragments, not reassembled"),
                    (stats.hellos_refused, "hellos refused"),
                    (stats.flows_evicted, "flows forgotten at a memory limit"),
                ] {
                    if n > 0 {
                        notes.push(format!("{n} {what}"));
                    }
                }
                if done.truncated {
                    notes.push("the capture ends partway through a packet".to_string());
                }
                let notes = if notes.is_empty() {
                    String::new()
                } else {
                    format!("; {}", notes.join("; "))
                };
                writeln!(
                    err,
                    "{}: {} frames, {} clients{notes}",
                    printable(name.as_bytes()),
                    stats.frames,
                    done.clients
                )?;
            }
            Err(ScanError::Output(e)) => return Err(e),
            Err(ScanError::Capture(e)) => {
                failed = true;
                writeln!(err, "tlsprint: {}: {e}", printable(name.as_bytes()))?;
            }
        }
    }
    if opts.summary {
        print_summary(&summary, &opts, out)?;
    }
    out.flush()?;
    Ok(if failed {
        2
    } else if hit {
        1
    } else {
        0
    })
}

enum Parsed {
    Version,
    Bad(String),
}

fn parse_args(args: &[String]) -> Result<Option<Options>, Parsed> {
    let mut opts = Options::default();
    let mut only_files = false;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if only_files || arg == "-" || !arg.starts_with('-') {
            opts.captures.push(arg.clone());
            continue;
        }
        match arg.as_str() {
            "--" => only_files = true,
            "--summary" => opts.summary = true,
            "--json" => opts.json = true,
            "--raw" => opts.raw = true,
            "--original" => opts.original = true,
            "--hits" => opts.hits = true,
            "--watch" => {
                let path = it
                    .next()
                    .ok_or_else(|| Parsed::Bad("--watch needs a file".into()))?;
                let text = std::fs::read_to_string(path)
                    .map_err(|e| Parsed::Bad(format!("{path}: {e}")))?;
                opts.watch =
                    Some(WatchList::parse(&text).map_err(|e| Parsed::Bad(format!("{path}: {e}")))?);
            }
            "--version" => return Err(Parsed::Version),
            "--help" | "-h" => return Ok(None),
            other => return Err(Parsed::Bad(format!("unknown flag {other}"))),
        }
    }
    if opts.captures.is_empty() {
        return Err(Parsed::Bad("no capture named".into()));
    }
    if opts.hits && opts.watch.is_none() {
        return Err(Parsed::Bad("--hits needs --watch".into()));
    }
    if opts.summary && opts.json {
        return Err(Parsed::Bad(
            "--summary and --json cannot be combined".into(),
        ));
    }
    Ok(Some(opts))
}

enum ScanError {
    Capture(CaptureError),
    Output(io::Error),
}

struct Done {
    stats: Stats,
    clients: u64,
    hit: bool,
    truncated: bool,
}

#[derive(Default)]
struct Group {
    count: u64,
    names: BTreeMap<String, u64>,
}

fn scan<R: Read>(
    src: R,
    opts: &Options,
    file: Option<&str>,
    summary: &mut BTreeMap<String, Group>,
    out: &mut dyn Write,
) -> Result<Done, ScanError> {
    let mut reader = Reader::new(src).map_err(ScanError::Capture)?;
    let mut tracker = Tracker::new();
    let (mut clients, mut hit) = (0, false);
    while let Some(frame) = reader.next_frame().map_err(ScanError::Capture)? {
        for s in tracker.frame(&frame) {
            clients += 1;
            let labels = opts
                .watch
                .as_ref()
                .map_or_else(Vec::new, |w| w.matches(&s.fingerprint.ja4));
            hit |= !labels.is_empty();
            if opts.summary {
                let group = summary.entry(s.fingerprint.ja4.clone()).or_default();
                group.count += 1;
                let name = s
                    .hello
                    .server_name
                    .as_deref()
                    .map_or_else(|| "(no SNI)".to_string(), printable);
                *group.names.entry(name).or_default() += 1;
            } else if !opts.hits || !labels.is_empty() {
                print_sighting(&s, &labels, opts, file, out).map_err(ScanError::Output)?;
            }
        }
    }
    Ok(Done {
        stats: tracker.stats,
        clients,
        hit,
        truncated: reader.truncated,
    })
}

/// Text from a capture is attacker-controlled, and terminals obey control sequences, so everything
/// but printable ASCII is escaped before it is printed.
pub fn printable(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for b in bytes {
        match b {
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(*b as char),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    out
}

fn protocol_name(p: Protocol) -> &'static str {
    match p {
        Protocol::Tcp => "tls",
        Protocol::Quic => "quic",
        Protocol::Dtls => "dtls",
    }
}

fn endpoint(ip: std::net::IpAddr, port: u16) -> String {
    match ip {
        std::net::IpAddr::V4(_) => format!("{ip}:{port}"),
        std::net::IpAddr::V6(_) => format!("[{ip}]:{port}"),
    }
}

fn print_sighting(
    s: &Sighting,
    labels: &[String],
    opts: &Options,
    file: Option<&str>,
    out: &mut dyn Write,
) -> io::Result<()> {
    let f = &s.fingerprint;
    if opts.json {
        let lossy = |b: &Option<Vec<u8>>| {
            b.as_deref()
                .map(|v| String::from_utf8_lossy(v).into_owned())
        };
        let mut value = json!({
            "frame": s.frame,
            "time_us": s.micros,
            "protocol": protocol_name(s.protocol),
            "src": s.src.to_string(),
            "src_port": s.src_port,
            "dst": s.dst.to_string(),
            "dst_port": s.dst_port,
            "ja4": f.ja4,
            "ja4_r": f.ja4_r,
            "ja4_o": f.ja4_o,
            "ja4_ro": f.ja4_ro,
            "sni": lossy(&s.hello.server_name),
            "alpn": lossy(&s.hello.alpn_first),
        });
        if let Some(file) = file {
            value["file"] = json!(file);
        }
        if opts.watch.is_some() {
            value["watch"] = json!(labels);
        }
        return writeln!(out, "{value}");
    }
    if let Some(file) = file {
        write!(out, "{}: ", printable(file.as_bytes()))?;
    }
    write!(
        out,
        "frame {}  {} -> {}  {}",
        s.frame,
        endpoint(s.src, s.src_port),
        endpoint(s.dst, s.dst_port),
        f.ja4
    )?;
    if let Some(name) = &s.hello.server_name {
        write!(out, "  sni={}", printable(name))?;
    }
    if let Some(alpn) = &s.hello.alpn_first {
        write!(out, "  alpn={}", printable(alpn))?;
    }
    for label in labels {
        write!(out, "  WATCH {}", printable(label.as_bytes()))?;
    }
    writeln!(out)?;
    if opts.raw {
        writeln!(out, "  ja4_r  {}", f.ja4_r)?;
    }
    if opts.original {
        writeln!(out, "  ja4_o  {}\n  ja4_ro {}", f.ja4_o, f.ja4_ro)?;
    }
    Ok(())
}

fn print_summary(
    summary: &BTreeMap<String, Group>,
    opts: &Options,
    out: &mut dyn Write,
) -> io::Result<()> {
    let mut groups: Vec<(&String, &Group)> = summary.iter().collect();
    groups.sort_by(|a, b| b.1.count.cmp(&a.1.count).then(a.0.cmp(b.0)));
    for (ja4, group) in groups {
        let labels = opts
            .watch
            .as_ref()
            .map_or_else(Vec::new, |w| w.matches(ja4));
        if opts.hits && labels.is_empty() {
            continue;
        }
        let mut names: Vec<(&String, &u64)> = group.names.iter().collect();
        names.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        let shown: Vec<&str> = names.iter().take(3).map(|(n, _)| n.as_str()).collect();
        let more = names.len().saturating_sub(3);
        let more = if more > 0 {
            format!(" and {more} more")
        } else {
            String::new()
        };
        write!(out, "{:>6}  {ja4}  {}{more}", group.count, shown.join(", "))?;
        for label in labels {
            write!(out, "  WATCH {}", printable(label.as_bytes()))?;
        }
        writeln!(out)?;
    }
    Ok(())
}
