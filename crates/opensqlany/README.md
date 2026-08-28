# opensqlany

A Rust library for reading SAP SQL Anywhere on-disk page-store files.

Targets SA17 (build 2182, 2015 release). The implementation is based on
clean-room observation of the on-disk format and SAP's public documentation.
No SAP code or binaries are included.

```toml
[dependencies]
opensqlany = "0.1"
```

## What it does

- Open observed SA17-style `.db` or `.qbw` page-store files
- Iterate over 4 KiB pages
- Validate per-page CRC-32 footers
- Classify pages by type (`'E'` extent, `'A'` alloc, `'I'` index, ...)
- Parse the superblock (magic, format version triple)
- Parse slotted-page row directories (`'E'` and `'C'` pages)
- Expose page-boundary row-overflow prefixes
- Remove the additive-progression (AP) fill obfuscation used in QuickBooks `.qbw` files

## Quick start

```rust
use opensqlany::{ApModel, PageStore};

let store = PageStore::open("company.qbw")?;
let model = ApModel::learn(&store);

for page in store.pages().skip(1) {
    page.verify_crc()?;
    let plain = model.deobfuscate_with_store(page.bytes(), page.index(), &store);
    let t = page.trailer();
    println!("page {} type {:?}", page.index(), t.page_type());
}
# Ok::<(), opensqlany::Error>(())
```

## Scope

v0.1 covers the **page-store layer**: opening, iterating, CRC validation,
page-type classification, slotted-page directory parsing, and AP
deobfuscation.

The crate also provides bounded, fail-closed typed-row decoding primitives for
callers that already possess a proven row layout. It does not provide a
universal SA17 schema decoder, catalog traversal, or B-tree traversal. Those
remain caller- and dialect-specific work.

## License

[Apache-2.0](../../LICENSE).
