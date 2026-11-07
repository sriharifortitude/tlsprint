//! Writes testdata/demo.pcap: hand-built traffic, not a recording. tests/cli.rs checks that the
//! committed file is what this writes.

#[path = "../tests/common/mod.rs"]
mod common;

fn main() {
    std::fs::write("testdata/demo.pcap", common::demo_capture()).expect("write testdata/demo.pcap");
}
