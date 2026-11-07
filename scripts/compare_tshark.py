#!/usr/bin/env python3
"""Compares tlsprint with Wireshark's own JA4 field, capture by capture.

For each capture it asks tshark for tls.handshake.ja4 and compares the set of fingerprints with
tlsprint's. Sets, because the two can count differently: tshark reports every ClientHello it
dissects, and tlsprint the first of each connection. A fingerprint only one of them finds is a
disagreement to print and explain.

    python scripts/compare_tshark.py CAPTURE_OR_DIRECTORY... [--tlsprint BIN]
"""

import argparse
import collections
import json
import pathlib
import subprocess
import sys


def from_tshark(capture: pathlib.Path) -> set[str] | None:
    run = subprocess.run(
        ["tshark", "-r", str(capture), "-Y", "tls.handshake.ja4", "-T", "fields", "-e", "tls.handshake.ja4"],
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
    totals = collections.Counter()
    for capture in captures:
        theirs, ours = from_tshark(capture), from_tlsprint(args.tlsprint, capture)
        if theirs is None or ours is None:
            totals["captures that could not be read"] += 1
            continue
        totals["captures"] += 1
        totals["fingerprints from tshark"] += len(theirs)
        totals["fingerprints agreed"] += len(theirs & ours)
        if theirs != ours:
            totals["captures that differ"] += 1
            print(capture.name)
            for f in sorted(theirs - ours):
                print(f"  only tshark:   {f}")
                totals["only tshark"] += 1
            for f in sorted(ours - theirs):
                print(f"  only tlsprint: {f}")
                totals["only tlsprint"] += 1
    for key, value in sorted(totals.items()):
        print(f"{key}: {value}")
    return 1 if totals["captures that differ"] or totals["captures that could not be read"] else 0


if __name__ == "__main__":
    sys.exit(main())
