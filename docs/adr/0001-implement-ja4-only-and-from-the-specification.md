# 1. Implement JA4 only, from its specification

Status: accepted

## Context

JA4 fingerprints a TLS client from its ClientHello. It is the first of a family that FoxIO calls
JA4+: JA4S for servers, JA4H for HTTP, JA4X for certificates and others. Those are licensed
differently. JA4 is BSD 3-Clause, and FoxIO's README says it has no patent claims on it and is not
planning any. FoxIO describes the rest as patent-pending and under the FoxIO License 1.1, which it
says allows academic and internal business use but not monetization.

FoxIO also publishes tools that compute these, in Rust, Python and as a Wireshark plugin, with
capture files and stored results to test them against.

## Decision

Implement JA4 and nothing else from the family, written from `technical_details/JA4.md`. The
reference Rust source was not read. Nothing from FoxIO's repository is copied into this one: CI
fetches it at a pinned commit, runs the tool over the captures, and compares with the stored
results. That also makes the comparison mean something, since two implementations that share code
would share mistakes.

When the specification and a stored result disagree, follow the specification and write the
disagreement down.

## Consequences

- A client's fingerprint can be used in a commercial setting under the same terms as this MIT
  repository. Someone wanting server or certificate fingerprints needs FoxIO's tools and licence.
- There was one such disagreement. A capture whose ALPN is the bytes `BA AD` has `99` in FoxIO's
  stored result, the behaviour of an earlier version of the method; the specification's table
  gives the first and last hex digits, `bd`. `scripts/compare_foxio.py` accepts exactly that row
  and fails on any other.
- Not reading the reference means learning its behaviour only from where results differ, which
  covers what the captures exercise and no more. See "Not tested" in the README.
