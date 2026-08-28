---
title: Physical row segments
sidebar_label: Physical row segments
---

# Physical row segments

`opensqlany` exposes a small, fail-closed parser for the physical SA17 row
segment header. It is useful only after a caller already has a trusted slice
of a containing page or row area.

## Established grammar

The segment starts with a total length and flags:

| Offset | Size | Meaning |
| ---: | ---: | --- |
| 0 | 2 | total segment length, `u16` little-endian |
| 2 | 1 | flags |
| 3 | 4 | next resolver key, only when `flags & 0x04 != 0` |
| 7 | 2 | next record ID, only when `flags & 0x04 != 0` |
| 3 or 9 | remainder | payload |

`0x04` is the only flag bit interpreted by this parser. A clear bit selects a
three-byte header; a set bit selects a nine-byte header and decodes the target
as `{ resolver_key: u32, record_id: u16 }`, both little-endian. In raw-byte
terms, `resolver_key = b3 + (b4 << 8) + (b5 << 16) + (b6 << 24)` and
`record_id = b7 + (b8 << 8)`. The record ID is consumed through a
materialized owner-local directory and is not a physical page number. The
resolver key remains intentionally neutral: the header does not contain the
caller-owned context needed to resolve it.
Other flag bits are retained as raw flags because their meaning is not
established here.

```rust
use opensqlany::{ROW_SEGMENT_CONTINUED, parse_row_segment};

let bytes = [10, 0, ROW_SEGMENT_CONTINUED, 1, 2, 3, 4, 5, 6, 0xaa];
let segment = parse_row_segment(&bytes)?;
assert_eq!(segment.next_target().unwrap().resolver_key(), 0x0403_0201);
assert_eq!(segment.next_target().unwrap().record_id(), 0x0605);
assert_eq!(segment.payload(), &[0xaa]);
# Ok::<(), opensqlany::RowSegmentError>(())
```

## Bounds and deliberate limits

The parser rejects a segment unless its declared length is at least the
selected header length and no greater than the bytes supplied by the caller.
It exposes only the declared bytes, so a non-continued segment cannot acquire
a target from adjacent bytes.

## Bounded caller-resolved chains

`walk_row_segment_chain` can join segments only when the caller supplies both
the initial target and a resolver closure. The required initial target means
the library never invents an initial continuation identity. The closure is responsible
for resolving each `{resolver key, record ID}` in one fixed caller-owned context;
it can capture that context itself. A walk must not change context, because
repeated raw targets are cycle errors. There is no file-selection,
page-directory, slot, table-owner, or QBW-specific behavior in this API.

```rust
use opensqlany::{
    ContinuationTarget, ROW_SEGMENT_CONTINUED, RowSegmentChainLimits,
    walk_row_segment_chain,
};

let first = ContinuationTarget::new(10, 1);
let next = ContinuationTarget::new(11, 1);
let initial = [10, 0, ROW_SEGMENT_CONTINUED, 11, 0, 0, 0, 1, 0, 0xaa];
let final_segment = [4, 0, 0, 0xbb];
let chain = walk_row_segment_chain(first, &initial, RowSegmentChainLimits::new(2, 2), |target| {
    assert_eq!(target, next); // caller resolves this in its own file/context
    Ok::<_, core::convert::Infallible>(final_segment.to_vec())
})?;
assert_eq!(chain.segments()[0].payload(), &[0xaa]);
assert_eq!(chain.segments()[1].payload(), &[0xbb]);
# Ok::<(), opensqlany::RowSegmentChainError<core::convert::Infallible>>(())
```

The walk is fail-closed: it requires the initial and resolver-provided slices
to contain exactly one declared segment; imposes caller-selected segment and
aggregate-payload caps; detects repeated targets (including a link back to the
supplied initial target); and returns resolver errors unchanged. Payloads are
copied into the result, so a resolver may reuse transient page buffers safely.
Neither target field is a byte offset. Determining a QBW table owner or the
first long-value locator remains outside this primitive; no such bridge is
implied by it.
