# tlsprint

[![CI](https://github.com/sriharifortitude/tlsprint/actions/workflows/ci.yml/badge.svg)](https://github.com/sriharifortitude/tlsprint/actions/workflows/ci.yml)

Reads a packet capture and computes the JA4 fingerprint of every TLS and QUIC client in it, then
checks them against a watch list. It follows hellos split across packets and out of order, and
decrypts QUIC Initials to reach the hello inside. Rust, MIT.

## What it is for

IP addresses and domains change with every campaign. The way a client builds its TLS ClientHello
changes much less often, because it comes from the library the client was built with. JA4 reduces
that hello to a short string, so a capture can be asked questions like "which clients here are not
browsers?" or "where else did this tool's TLS stack show up?" without decrypting anything.

The capture below is hand-built, not a recording: the client from FoxIO's specification twice, a
sparse TLS 1.2 client, and the QUIC packet from RFC 9001.

<!-- demo:start -->
```
$ tlsprint testdata/demo.pcap
frame 4  192.0.2.10:50000 -> 198.51.100.7:443  t13d1516h2_8daaf6152771_e5627efa2ab1  sni=www.example.org  alpn=h2
frame 5  192.0.2.11:50001 -> 198.51.100.7:443  t13d1516h2_8daaf6152771_e5627efa2ab1  sni=www.example.org  alpn=h2
frame 6  192.0.2.12:50002 -> 203.0.113.9:8443  t12i040400_93657e4f18b9_c81523bf1a9d
frame 7  192.0.2.13:50003 -> 198.51.100.7:443  q13d0211an_62ed6f6ca7ad_4d634acda6c0  sni=example.com  alpn=alpn
testdata/demo.pcap: 7 frames, 4 clients

$ tlsprint --summary testdata/demo.pcap
testdata/demo.pcap: 7 frames, 4 clients
     2  t13d1516h2_8daaf6152771_e5627efa2ab1  www.example.org
     1  q13d0211an_62ed6f6ca7ad_4d634acda6c0  example.com
     1  t12i040400_93657e4f18b9_c81523bf1a9d  (no SNI)

$ tlsprint --watch testdata/watch.csv --hits testdata/demo.pcap
frame 4  192.0.2.10:50000 -> 198.51.100.7:443  t13d1516h2_8daaf6152771_e5627efa2ab1  sni=www.example.org  alpn=h2  WATCH the cipher list of the client under investigation
frame 5  192.0.2.11:50001 -> 198.51.100.7:443  t13d1516h2_8daaf6152771_e5627efa2ab1  sni=www.example.org  alpn=h2  WATCH the cipher list of the client under investigation
frame 6  192.0.2.12:50002 -> 203.0.113.9:8443  t12i040400_93657e4f18b9_c81523bf1a9d  WATCH TLS 1.2 to a bare IP address
testdata/demo.pcap: 7 frames, 4 clients
```
<!-- demo:end -->

The first client's hello was split across two packets, which is why it is reported on frame 4 and
not 3. The three sections of a fingerprint mean different things: the first is readable (`t13d1516h2`
is TLS over TCP, version 1.3, a domain name, 15 ciphers, 16 extensions, ALPN `h2`), and the other
two are hashes of the cipher list and the extension list. Hunting usually fixes one section and
leaves the others open, so a watch list can do that:

```
# fingerprint,label
*_8daaf6152771_*,the cipher list of the client under investigation
t12i*_*_*,TLS 1.2 to a bare IP address
```

## Usage

```bash
cargo install --git https://github.com/sriharifortitude/tlsprint --tag v0.1.0

tlsprint capture.pcapng                       # one line per client
tlsprint --summary capture.pcap               # one line per fingerprint: how many, which names
tlsprint --json capture.pcap                  # one JSON object per client, every form of JA4
tlsprint --raw --original capture.pcap        # the lists behind the hashes, and the client's order
tlsprint --watch list.csv --hits capture.pcap # only what is on the list
tcpdump -w - -i eth0 | tlsprint -             # standard input
```

Exit codes: 0 nothing on the watch list, 1 something on it, 2 a usage error or a capture that could
not be read. Standard error says what was passed over: IP fragments, malformed frames, refused
hellos, flows forgotten at a memory limit, and a capture that ends partway through a packet.

## What it reads

- **Files**: pcap in either byte order and either precision; pcapng with several sections and
  interfaces, in either byte order.
- **Links**: Ethernet with stacked VLAN tags, Linux cooked capture 1 and 2, raw IP, null and
  loopback. IPv4 and IPv6, through IPv6 extension headers.
- **TCP**: a hello split across packets and records, out of order, retransmitted, with sequence
  numbers wrapping around, in the SYN (TCP Fast Open), with no SYN in the capture, and after a
  plaintext start such as SMTP STARTTLS. On any port: it goes by the bytes.
- **QUIC**: versions 1 and 2. Initial packets are encrypted with keys anyone can derive from the
  packet, so reading the hello needs no secrets. Handles coalesced packets, a hello across several
  Initials, and shuffled CRYPTO frames.
- **DTLS**: 1.0 to 1.3, with fragments reassembled.

Each connection is reported once, for its first hello; a new SYN starts a new one. Captures are
treated as hostile: see [ADR 2](docs/adr/0002-a-capture-is-hostile-input.md) for the limits on
memory and why a server name cannot put escape sequences on your terminal.

It computes JA4 and none of the rest of JA4+, which has a different licence:
[ADR 1](docs/adr/0001-implement-ja4-only-and-from-the-specification.md).

## Tested

```bash
cargo test                                            # 104 tests
python3 scripts/compare_foxio.py PATH_TO_FOXIO_JA4    # against FoxIO's stored results
python3 scripts/compare_tshark.py PATH_TO_CAPTURES    # against Wireshark's own JA4 field
```

**Against FoxIO's results.** FoxIO publishes capture files with the output of its own Rust
implementation. tlsprint was written from the specification without reading that source. CI fetches
the captures at a pinned commit and compares connection by connection, on addresses, ports and
fingerprint. On the first run, 202 of the 203 stored fingerprints matched (151 of 152 over TCP and
all 51 over QUIC), and tlsprint reported no connection FoxIO did not. FoxIO has one more stored
result whose capture it no longer ships.

The one difference is a client whose ALPN is the bytes `BA AD`. The stored result says `99`, while
FoxIO's current specification gives the first and last hex digits, `bd`, with a table of examples.
tlsprint follows the specification, and the script accepts that exact row and fails on any other.

**Against Wireshark.** `scripts/compare_tshark.py` compares the set of fingerprints in each capture
with Wireshark's own `tls.handshake.ja4` field. There is no tshark on the Windows machine this was
written on, so this runs in CI. It has been written and has not been run yet; this paragraph will say
what it found.

**Against the RFCs.** The client Initial packets printed in RFC 9001 and RFC 9369 are test
vectors here: they have to decrypt to exactly the CRYPTO frame those RFCs print. FoxIO's worked
example is one too: each hash in its specification, in all four forms, has a test. Writing those
down from the RFC rather than from memory paid off: the secret I remembered was wrong partway through.

**Damaged input.** Tests run with overflow checks on and feed in 12,000 randomly damaged captures
and frames, and CI fuzzes the capture reader and parsers for 60 seconds per run. Fuzzing can only
run on Linux, so the first time it runs is in CI.

**Mutation testing.** I broke the code in 70 places on purpose. On the first run 11 mutants survived,
and one did not match the source. One survivor was a real bug: with no SYN in the capture, a first
segment under six bytes was refused, so a client that cut its hello into tiny segments, a known way
to hide from tools that read one packet at a time, was not seen. That is fixed and tested. Six were
tests that could not fail, among them no UDP length shorter than what IP says is there, and no
oversized packet in a block large enough to hold it. Three marked checks that changed nothing, which I
deleted, and the next run found a fourth. Of the 67 mutants left, 65 are caught. The other two remove
checks that only save work (one avoids copying every non-TLS packet, one avoids decrypting repeated
QUIC Initials), so the results stay the same without them.

## Not tested, and not done

- Traffic inside tunnels (GRE, VXLAN, GTP, IPsec) is not decapsulated, so hellos inside them are not
  seen. Neither are hellos that span IP fragments; the count of fragments on standard error shows
  when that might matter.
- A hello in the old SSLv2 format is not parsed.
- Draft versions of QUIC are not read, only versions 1 and 2.
- It has been run on files from the sources named above, and has not been measured on a large or
  live capture. A flood of long-header UDP packets costs an AES and HKDF run each.
- DTLS 1.3 fingerprints are computed from the rule as the specification words it, "the highest value",
  though DTLS versions count downwards. No capture here exercises it, so that reading is unconfirmed.
- A JA4 identifies a client's TLS stack, not the client. Many programs share a stack, and a tool can
  imitate another's hello, so a match on a watch list is a lead rather than a verdict.
