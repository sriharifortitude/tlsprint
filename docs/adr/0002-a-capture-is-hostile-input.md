# 2. A capture is hostile input

Status: accepted

## Context

The people who run this point it at traffic they are suspicious of, so the bytes may have been
written by the attacker they are looking for. Every length in a capture, an IP header, a TLS
record and a QUIC packet is a claim that can be false, and server names are text the attacker
chooses that end up on an analyst's terminal. Packet parsers have a long record of memory bugs for
this reason, which is the main reason to write one in Rust. That removes memory corruption, and
leaves three ways to go wrong: panicking, running out of memory, and printing something harmful.

## Decision

**No panics.** All parsing goes through checked reads, and a message that does not add up is
refused whole. Tests run with overflow checks on and feed in randomly damaged captures, and CI
fuzzes the same entry points.

**Bounded memory.** A capture is read packet by packet rather than loaded. A length is checked
against a limit before anything is allocated for it: 256 KiB for a packet, 16 MiB for a pcapng
block. A hello is held only up to 256 KiB. Across all flows, at most 256 MiB and about a million
flows are held; past that everything held is forgotten, and the count of forgotten flows is
reported, because a result with hellos missing should not look like a clean one.

Forgetting everything rather than evicting the oldest flow is a deliberate simplification. A
capture built to hit the limit can make this tool miss hellos, and it says so when that happens.

**Nothing raw reaches the terminal.** Server names and ALPN values are printed with everything
other than printable ASCII escaped, so a name cannot carry escape sequences. JSON output goes
through a serializer, with invalid UTF-8 replaced.

**What was passed over is reported.** IP fragments, malformed frames, refused hellos and a capture
that ends partway are counted on standard error, since silence would read as "nothing there".

## Consequences

- A hello that spans IP fragments is not read. Reassembling them is more state for an attacker to
  fill, and clients avoid fragmenting these packets. The count of fragments shows if it matters.
- Bytes overlapping in a TCP stream are resolved by keeping the first to arrive. A receiver might
  keep the later ones, so a client that sends two different hellos in overlapping segments can show
  this tool a different one from the server. Evasion of that kind needs a tool that knows the
  receiver's operating system, and this one does not.
