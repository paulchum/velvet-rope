# Velvet Rope Proxy Structure Refactor Notes

## Module Map

| Module | Responsibility |
| --- | --- |
| `crates/velvet-rope-proxy/src/ledger/mod.rs` | Ledger module wiring and public surface reexports. |
| `src/ledger/records.rs` | Canonical and OAP ledger record types plus post-execution record builders. |
| `src/ledger/binary.rs` | Binary `.vledger` frame encoding, byte decoding, and byte-level verification entry points. |
| `src/ledger/verify.rs` | Ledger chain verification, semantic binding checks, and thread validation. |
| `src/ledger/reporting.rs` | Ledger report rendering and JSONL append helpers. |
| `src/ledger/signing.rs` | Local signing envelopes, hosted signing requests, and signature verification glue. |
| `src/ledger/support.rs` | Shared ledger hashing, canonicalization, time, redaction, and test/demo helpers. |
| `src/tests/mod.rs` | Rope Proxy unit-test module wiring. |
| `src/tests/support.rs` | Shared unit-test servers, fixtures, config builders, and assertions. |
| `src/tests/{approvals,config,enforcement,ledger,oap,permits,policy_bundle,transport}.rs` | Unit tests split by runtime concern. |
| `src/oap.rs` | Left in place beyond the existing `src/oap/tests.rs` extraction; artifact construction and verification helpers are still interleaved enough that a two-file split would be refactor work, not plumbing. |

## Decode Hardening

- Added Rust integration properties in `crates/velvet-rope-proxy/tests/ledger_decode_properties.rs` for valid record roundtrips, bounded arbitrary byte mutations, boundary truncations, and length-prefix lies.
- Added Python Hypothesis coverage in `tests/test_ledger_decode_properties.py` for the Python binary ledger verifier path.
- Added cargo-fuzz targets in `crates/velvet-rope-proxy/fuzz/` for `decode_ledger` and `verify_ledger`.
- Added `.github/workflows/fuzz.yml` as a manual and weekly workflow. It is intentionally outside required CI.

## Visibility Notes

The integration tests and fuzz targets need crate-root byte entry points. The following binary-ledger decode items were made public:

- `BinaryLedgerDecodeErrorKind`
- `BinaryLedgerDecodeError`
- `BinaryLedgerFrame`
- `encode_binary_ledger_record`
- `decode_binary_ledger_frames`
- `parse_binary_ledger_frame`
- `verify_binary_ledger_bytes`

No external call sites were changed for the mechanical file split; `ledger/mod.rs` reexports the existing surface.

## Verification Snapshot

| Check | Result |
| --- | --- |
| Pre-existing unit/OAP test names after split | 103, unchanged by the split |
| `cargo test -p velvet-rope-proxy -- --list \| wc -l` | 107 before this work order; 115 after adding six decode property tests |
| `cargo test -p velvet-rope-proxy` | pass |
| Rust fuzz `decode_ledger` local run | 951,128 runs in 61s, peak RSS 44 MB, zero crashes |
| Rust fuzz `verify_ledger` local run | 1,038,828 runs in 61s, peak RSS 44 MB, zero crashes |

Local macOS note: the default ASan fuzz binary stalled in sanitizer initialization before target execution on this machine. The recorded local runs used `cargo +nightly-2025-11-21 fuzz run --sanitizer none ... -max_total_time=60 -max_len=4096`; the Linux scheduled workflow keeps cargo-fuzz's default sanitizer.
