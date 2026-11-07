#!/usr/bin/env bash
# Prints the README's example: each command, then what it prints. Run from anywhere.
set -u
cd "$(dirname "$0")/.."
bin=${TLSPRINT:-./target/release/tlsprint}
run() {
  echo "\$ tlsprint $*"
  "$bin" "$@" 2>&1 | tr -d '\r'
}
run testdata/demo.pcap
echo
run --summary testdata/demo.pcap
echo
run --watch testdata/watch.csv --hits testdata/demo.pcap
