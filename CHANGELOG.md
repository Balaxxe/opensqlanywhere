# Changelog

All notable changes to this project will be documented here. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `opensqlany inspect --verify-crc` now verifies page 0 as well as ordinary
  pages and exits unsuccessfully after printing its integrity summary when a
  CRC or trailer check fails.
- `opensqlany slots` now reports directory entries in their physical order,
  including deleted slots, rather than renumbering sorted live rows.
- Partial Boolean-tail decoding rejects sidecars truncated after the row
  header/null map, and exact materialized carriers reject trailing bytes.
- Materialized table pages reject records whose offsets overlap the directory.
- `PageStore::open` uses a checked, size-stable bounded read and revalidates
  final size/alignment; same-length rewrites still require an immutable copy or
  external locking.
- Non-zero bytes before a slot directory are exposed as an unclassified prefix
  rather than being claimed as row-continuation evidence.
- Page-type classification keeps the raw on-disk byte available instead of
  implying that lowercase variants can be reconstructed from the enum alone.
- The documented development invocation now works in Windows PowerShell.

### Changed

- CI now tests the declared Rust 1.87 MSRV. The release workflow uses
  crates.io trusted publishing via GitHub OIDC instead of a stored registry
  token.

## [0.1.1] - 2026-08-12

### Added

- `Superblock::flags_06_variant_bits` and `FLAGS_06_BASE`. `flags_06`
  (superblock offset `0x06`) was documented as one of two magic values
  (`0x09`/`0x49`); a QuickBooks Enterprise 24.0 file adds a third, `0x29`,
  which is `0x09 | 0x20` - the same bit-6 relationship the original
  `0x49 = 0x09 | 0x40` already had. Exposes it as a bitfield over
  `FLAGS_06_BASE` instead, so a future edition setting another bit doesn't
  need a new literal-match arm. What each bit means is still unknown.
  Reported against [openqbw#16](https://github.com/Sigilweaver/OpenQBW/issues/16)
  by @pete-green.

### Fixed

- `PageType::from_byte` only classified uppercase page-type bytes. A
  QuickBooks Desktop Enterprise 24.0 file carries the same page types in
  **lowercase** (`'e'` 0x65 instead of `'E'` 0x45) on otherwise-ordinary
  extent/data pages; every consumer filtering on `PageType::Extent` (e.g.
  `openqbw`'s SYSTABLE walk) silently skipped the entire data population
  since they all landed in `PageType::Other(0x65)` instead. Classification
  is now case-insensitive; the raw byte (case included) is still preserved
  in `Other(_)` since the case bit itself may be meaningful. Fixes #8
  (finding 1). Reported by @pete-green.
- `ApModel::deobfuscate_with_store` trusted a single `bv` learned per
  16-page block, applying it to every page in the block. That assumption
  doesn't hold on the same Enterprise 24.0 file: across 2,920 sampled
  pages, 394/439 blocks showed 6-8 distinct per-page `bv` values, so a
  block's learned value (from whichever pure-AP page happened to be in
  it) was silently wrong for most of the block's dense data pages. Added
  `ApModel::recover_bv_for_page` (the same histogram-peak brute-force
  search as `recover_bv_for_block`, scoped to one page) and switched
  `deobfuscate_with_store` to resolve `bv` per page unconditionally
  instead of trusting the block-level value. `recover_bv_for_block` and
  the rest of the block-level API are unchanged, for callers that
  specifically want the cheaper approximation. Fixes #8 (finding 2).
  Reported by @pete-green.

## [0.1.0] - 2026-05-22

First publication-ready release.

### Added

- `opensqlany` library: `PageStore`, `Superblock`, `Page`, slotted-page
  parsing, CRC verification, and `ApModel` for the additive-progression
  deobfuscation layer used by QuickBooks `.QBW` files.
- `opensqlany` CLI binary: `inspect`, `dump-page`, `slots` subcommands
  against a page-store file.
- `SPECIFICATION.md` covering the SA17 (build 2182, 2015) on-disk
  page-store format derived from clean-room observation and SAP public
  documentation.
- Workspace metadata, MSRV 1.87, `unsafe_code = "forbid"`.
- CI matrix (Linux + macOS + Windows): `cargo fmt`, `cargo clippy
  --workspace --all-targets -- -D warnings`, `cargo test --workspace`.
- Tag-triggered crates.io release workflow (`opensqlany` then
  `opensqlany-cli`) via trusted publishing.
- `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`.
- Documentation site at <https://sigilweaver.app/opensqlanywhere/docs/>.

[Unreleased]: https://github.com/Sigilweaver/OpenSQLAnywhere/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Sigilweaver/OpenSQLAnywhere/releases/tag/v0.1.0
