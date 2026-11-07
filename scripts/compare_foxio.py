#!/usr/bin/env python3
"""Compares tlsprint with the results FoxIO publishes for the captures in its JA4 repository.

FoxIO's own implementation produced those results, and tlsprint shares no code with it. Each
expected fingerprint is matched by connection: transport, addresses, ports. Connections are
listed by stream in FoxIO's files, and several can share a fingerprint, so what is compared
for each capture is the multiset of (src, src port, dst, dst port, fingerprint).

    python scripts/compare_foxio.py PATH_TO_FOXIO_JA4_CHECKOUT [--tlsprint BIN]

Nothing from FoxIO's repository is copied here: the checkout is fetched at a pinned commit.
"""

import argparse
import collections
import json
import pathlib
import re
import subprocess
import sys

ROW = re.compile(r"^(- |  )(src|dst|src_port|dst_port|ja4|transport):\s*(.+?)\s*$")

# Where FoxIO's stored result and FoxIO's written specification disagree, and tlsprint follows the
# specification. This ALPN is the bytes BA AD: the specification's table gives the first and last
# hex digits, "bd", and the stored result has the "99" of an earlier version. See README.md.
KNOWN = {
    "tls-non-ascii-alpn.pcapng": (
        ("192.168.1.168", "50112", "142.251.16.94", "443", "t13d151699_8daaf6152771_e5627efa2ab1"),
        ("192.168.1.168", "50112", "142.251.16.94", "443", "t13d1516bd_8daaf6152771_e5627efa2ab1"),
    ),
}


def expected(snapshot: pathlib.Path) -> collections.Counter:
    """Reads the fields of FoxIO's YAML snapshot, one record per connection."""
    out = collections.Counter()
    record = {}

    def flush() -> None:
        if "ja4" in record:
            out[(record["src"], record["src_port"], record["dst"], record["dst_port"], record["ja4"])] += 1

    for line in snapshot.read_text(encoding="utf-8").splitlines():
        if line.startswith("- "):
            flush()
            record = {}
        match = ROW.match(line)
        if match:
            record[match.group(2)] = match.group(3)
    flush()
    return out


def actual(binary: str, capture: pathlib.Path) -> collections.Counter:
    run = subprocess.run([binary, "--json", str(capture)], capture_output=True, text=True, check=False)
    if run.returncode not in (0, 1):
        print(f"{capture.name}: tlsprint failed: {run.stderr.strip()}")
    out = collections.Counter()
    for line in run.stdout.splitlines():
        s = json.loads(line)
        out[(s["src"], str(s["src_port"]), s["dst"], str(s["dst_port"]), s["ja4"])] += 1
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("checkout", type=pathlib.Path)
    ap.add_argument("--tlsprint", default="target/release/tlsprint")
    args = ap.parse_args()
    snapshots = args.checkout / "rust/ja4/src/snapshots"
    totals = collections.Counter()
    for snap in sorted(snapshots.glob("ja4__insta@*.snap")):
        name = snap.name.removeprefix("ja4__insta@").removesuffix(".snap")
        capture = args.checkout / "pcap" / name
        if not capture.exists():
            print(f"{name}: FoxIO has a result but no longer ships the capture")
            totals["results without a capture"] += 1
            continue
        want, got = expected(snap), actual(args.tlsprint, capture)
        missing, extra = want - got, got - want
        if name in KNOWN and missing == collections.Counter([KNOWN[name][0]]) and extra == collections.Counter([KNOWN[name][1]]):
            totals["documented differences"] += 1
            missing, extra = collections.Counter(), collections.Counter()
        totals["captures"] += 1
        totals["expected"] += sum(want.values())
        totals["agree"] += sum((want & got).values())
        totals["missing"] += sum(missing.values())
        totals["extra"] += sum(extra.values())
        if missing or extra:
            totals["captures that differ"] += 1
            print(name)
            for row in sorted(missing):
                print(f"  only FoxIO:    {row[0]}:{row[1]} -> {row[2]}:{row[3]}  {row[4]}")
            for row in sorted(extra):
                print(f"  only tlsprint: {row[0]}:{row[1]} -> {row[2]}:{row[3]}  {row[4]}")
    for key, value in sorted(totals.items()):
        print(f"{key}: {value}")
    return 1 if totals["missing"] or totals["extra"] else 0


if __name__ == "__main__":
    sys.exit(main())
