#!/usr/bin/env python3
"""Compares tlsprint with Wireshark's own JA4 field, capture by capture.

For each capture it asks tshark for tls.handshake.ja4 and compares the set of fingerprints with
tlsprint's. Sets, because the two can count differently: tshark reports every ClientHello it
dissects, and tlsprint the first of each connection. A fingerprint only one of them finds is a
disagreement to print and explain; the ones already explained are listed in KNOWN, exactly.

    python scripts/compare_tshark.py CAPTURE_OR_DIRECTORY... [--tlsprint BIN]
"""

import argparse
import collections
import json
import pathlib
import subprocess
import sys


# (only tshark, only tlsprint, why) for each capture where the two are known to differ.
SECOND_HELLO = (
    "the client's second hello after a HelloRetryRequest, in the same connection as the first; "
    "tlsprint and FoxIO report the first, tshark both"
)
KNOWN = {
    "sigalg-grease.pcapng": (
        {"t13d1517h2_8daaf6152771_f10ceb9fcfd7"},
        {"t13d1517h2_8daaf6152771_cb7bf5808d99"},
        "tshark hashes the GREASE signature algorithm 0a0a, which the specification says to ignore",
    ),
    "tls-handshake.pcapng": ({"t13d1515h2_8daaf6152771_f37e75b10bcc"}, set(), SECOND_HELLO),
    "tls-sni.pcapng": ({"t13d1515h2_8daaf6152771_f37e75b10bcc"}, set(), SECOND_HELLO),
}


def ja4_fields() -> list[str]:
    """The JA4 fields this tshark has: TLS always, and DTLS if it has one."""
    listing = subprocess.run(["tshark", "-G", "fields"], capture_output=True, text=True, check=False).stdout
    names = {line.split("\t")[2] for line in listing.splitlines() if line.count("\t") >= 2}
    return [f for f in ("tls.handshake.ja4", "dtls.handshake.ja4") if f in names]


def from_tshark(capture: pathlib.Path, fields: list[str]) -> set[str] | None:
    extract = [arg for f in fields for arg in ("-e", f)]
    # tshark picks the TLS dissector by port, and tlsprint goes by the bytes. The demo capture's
    # sparse client is on 8443, with no handshake for tshark to recognise it by.
    run = subprocess.run(
        ["tshark", "-r", str(capture), "-d", "tcp.port==8443,tls", "-Y", " or ".join(fields), "-T", "fields", *extract],
        capture_output=True,
        text=True,
        check=False,
    )
    if run.returncode != 0 and not run.stdout:
        print(f"{capture.name}: tshark failed: {run.stderr.strip()[:200]}")
        return None
    found = set()
    for line in run.stdout.split():
        # A frame carrying several QUIC hellos lists them comma-separated.
        found.update(line.split(","))
    return found


def show_frames(capture: pathlib.Path) -> None:
    """What tshark makes of each frame, to see why it found no fingerprint."""
    run = subprocess.run(
        ["tshark", "-r", str(capture), "-d", "tcp.port==8443,tls", "-T", "fields", "-e", "frame.number",
         "-e", "frame.protocols", "-e", "tcp.dstport", "-e", "tls.handshake.type", "-e", "_ws.expert.message"],
        capture_output=True,
        text=True,
        check=False,
    )
    for line in run.stdout.splitlines()[:40]:
        print("    " + line.replace("\t", "  ")[:160])


def from_tlsprint(binary: str, capture: pathlib.Path) -> set[str] | None:
    run = subprocess.run([binary, "--json", str(capture)], capture_output=True, text=True, check=False)
    if run.returncode not in (0, 1):
        print(f"{capture.name}: tlsprint failed: {run.stderr.strip()[:200]}")
        return None
    return {json.loads(line)["ja4"] for line in run.stdout.splitlines()}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+", type=pathlib.Path)
    ap.add_argument("--tlsprint", default="target/release/tlsprint")
    args = ap.parse_args()
    captures = []
    for path in args.paths:
        if path.is_dir():
            captures.extend(sorted(p for p in path.iterdir() if p.suffix in (".pcap", ".pcapng", ".cap")))
        else:
            captures.append(path)
    fields = ja4_fields()
    print("tshark fields:", ", ".join(fields))
    totals = collections.Counter()
    for capture in captures:
        theirs, ours = from_tshark(capture, fields), from_tlsprint(args.tlsprint, capture)
        if theirs is None or ours is None:
            totals["captures that could not be read"] += 1
            continue
        totals["captures"] += 1
        totals["fingerprints from tshark"] += len(theirs)
        totals["fingerprints agreed"] += len(theirs & ours)
        known = KNOWN.get(capture.name)
        if known and theirs - ours == known[0] and ours - theirs == known[1]:
            totals["documented differences"] += 1
            print(f"{capture.name}: {known[2]}")
        elif theirs != ours:
            totals["captures that differ"] += 1
            print(capture.name)
            for f in sorted(theirs - ours):
                print(f"  only tshark:   {f}")
                totals["only tshark"] += 1
            for f in sorted(ours - theirs):
                print(f"  only tlsprint: {f}")
                totals["only tlsprint"] += 1
            show_frames(capture)
    for key, value in sorted(totals.items()):
        print(f"{key}: {value}")
    return 1 if totals["captures that differ"] or totals["captures that could not be read"] else 0


if __name__ == "__main__":
    sys.exit(main())
