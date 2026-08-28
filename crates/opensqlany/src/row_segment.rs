//! Bounded parser for SA17 physical row-segment headers.
//!
//! A row segment begins with a little-endian `u16` segment length and a
//! flag byte.  The `0x04` flag bit changes the header from three bytes to
//! nine bytes and adds a six-byte continuation target: a four-byte resolver
//! key followed by a two-byte record identifier. This module deliberately
//! parses one segment only: resolving either field and walking a chain require
//! independent evidence and are outside
//! this API.  [`walk_row_segment_chain`] adds a bounded walker, but still
//! requires its caller to supply both the initial target and every target
//! resolution in an explicit caller-owned file/context.

use core::fmt;
use std::{borrow::Cow, collections::BTreeSet};

/// The flag bit that marks a segment as continued.
pub const ROW_SEGMENT_CONTINUED: u8 = 0x04;

/// Header length for a segment without [`ROW_SEGMENT_CONTINUED`].
pub const ROW_SEGMENT_HEADER_LEN: usize = 3;

/// Header length for a segment with [`ROW_SEGMENT_CONTINUED`].
pub const CONTINUED_ROW_SEGMENT_HEADER_LEN: usize = 9;

/// The on-disk continuation target stored in a physical SQL Anywhere row
/// segment header.
///
/// The six bytes encode `{ resolver_key: u32, record_id: u16 }`, both
/// little-endian: bytes `3..7` are `resolver_key.to_le_bytes()` and bytes
/// `7..9` are `record_id.to_le_bytes()`. `record_id` is consumed as an index
/// into a materialized owner-local directory; it is not a physical page
/// number. `resolver_key` is intentionally neutral: resolving it requires
/// caller-owned context that is not stored in this header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContinuationTarget {
    resolver_key: u32,
    record_id: u16,
}

impl ContinuationTarget {
    /// Construct a raw continuation target.
    pub const fn new(resolver_key: u32, record_id: u16) -> Self {
        Self {
            resolver_key,
            record_id,
        }
    }

    /// Four-byte little-endian resolver key.
    ///
    /// This is not proven to be a raw page number, byte offset, or standalone
    /// row identity.
    pub const fn resolver_key(self) -> u32 {
        self.resolver_key
    }

    /// Two-byte little-endian record identifier within the resolved owner's
    /// materialized directory. It is not a physical page number.
    pub const fn record_id(self) -> u16 {
        self.record_id
    }

    fn from_le_bytes(bytes: &[u8]) -> Self {
        debug_assert_eq!(bytes.len(), 6);
        Self::new(
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            u16::from_le_bytes([bytes[4], bytes[5]]),
        )
    }
}

impl fmt::Display for ContinuationTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "resolver_key=0x{:08X}, record_id=0x{:04X}",
            self.resolver_key, self.record_id
        )
    }
}

/// A checked physical row segment borrowed from its containing row area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowSegment<'a> {
    declared_len: usize,
    flags: u8,
    next_target: Option<ContinuationTarget>,
    bytes: &'a [u8],
}

impl<'a> RowSegment<'a> {
    /// Parse the first complete segment in `input`.
    ///
    /// `input` may include following row-area bytes.  This method returns a
    /// slice exactly bounded by the header's declared segment length and
    /// never interprets following bytes as a continuation target.
    pub fn parse(input: &'a [u8]) -> Result<Self, RowSegmentError> {
        parse_row_segment(input)
    }

    /// Declared total length of the header and payload, in bytes.
    pub const fn declared_len(self) -> usize {
        self.declared_len
    }

    /// Raw header flags, retained without assigning meaning to unproven bits.
    pub const fn flags(self) -> u8 {
        self.flags
    }

    /// Whether the proven continuation bit is set.
    pub const fn is_continued(self) -> bool {
        self.next_target.is_some()
    }

    /// Header length selected by the continuation bit.
    pub const fn header_len(self) -> usize {
        if self.is_continued() {
            CONTINUED_ROW_SEGMENT_HEADER_LEN
        } else {
            ROW_SEGMENT_HEADER_LEN
        }
    }

    /// Raw target of the next segment, only for a continued segment.
    ///
    /// Resolving this target additionally needs caller-owned context that is
    /// not represented in this header.
    pub const fn next_target(self) -> Option<ContinuationTarget> {
        self.next_target
    }

    /// Full, checked segment bytes, including the header.
    pub const fn bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Checked payload bytes after the selected header.
    pub fn payload(self) -> &'a [u8] {
        &self.bytes[self.header_len()..]
    }
}

/// Failure while validating a physical row-segment boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowSegmentError {
    /// The slice does not contain the fixed three-byte header.
    MissingHeader {
        /// Bytes supplied by the caller.
        available: usize,
    },
    /// The declared length cannot contain the selected header or extends
    /// beyond the caller's trusted containing row area.
    InvalidLength {
        /// u16 length decoded from the first two bytes.
        declared: usize,
        /// Header length selected solely by the continuation bit.
        header_len: usize,
        /// Bytes supplied by the caller.
        available: usize,
    },
}

impl fmt::Display for RowSegmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingHeader { available } => write!(
                f,
                "row segment needs a three-byte header but only {available} bytes are available"
            ),
            Self::InvalidLength {
                declared,
                header_len,
                available,
            } => write!(
                f,
                "row segment declares {declared} bytes; it needs at least its {header_len}-byte header and has {available} bytes available"
            ),
        }
    }
}

impl std::error::Error for RowSegmentError {}

/// Caller-selected resource limits for [`walk_row_segment_chain`].
///
/// These are limits on parsed physical segments, not on pages, rows, files,
/// or database objects.  The caller owns all of those mappings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowSegmentChainLimits {
    /// Maximum number of segments, including the caller-supplied initial one.
    pub max_segments: usize,
    /// Maximum combined payload length across all segments.
    pub max_total_payload_bytes: usize,
}

impl RowSegmentChainLimits {
    /// Construct explicit chain-walk limits.
    pub const fn new(max_segments: usize, max_total_payload_bytes: usize) -> Self {
        Self {
            max_segments,
            max_total_payload_bytes,
        }
    }
}

/// One fully bounded segment returned by [`walk_row_segment_chain`].
///
/// `target` is the caller-supplied identity used to request this segment from
/// its resolver.  It is not sufficient to identify a file by itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowSegmentChainSegment {
    target: ContinuationTarget,
    flags: u8,
    declared_len: usize,
    payload: Vec<u8>,
}

impl RowSegmentChainSegment {
    /// Caller-supplied identity of this segment in its resolver context.
    pub const fn target(&self) -> ContinuationTarget {
        self.target
    }

    /// Raw physical header flags.
    pub const fn flags(&self) -> u8 {
        self.flags
    }

    /// Checked total segment length, including its header.
    pub const fn declared_len(&self) -> usize {
        self.declared_len
    }

    /// Checked payload after this segment's selected header.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// A bounded, ownership-neutral physical row continuation chain.
///
/// The segments are ordered from the caller-supplied initial segment through
/// each continuation.  Payloads are copied so they remain valid after the
/// caller's resolver returns; no page, file, or database owner is retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowSegmentChain {
    segments: Vec<RowSegmentChainSegment>,
    total_payload_bytes: usize,
}

impl RowSegmentChain {
    /// Segments in physical continuation order.
    pub fn segments(&self) -> &[RowSegmentChainSegment] {
        &self.segments
    }

    /// Number of parsed segments, including the initial segment.
    pub fn len(&self) -> usize {
        self.segments.len()
    }

    /// Whether this chain contains no segments.
    ///
    /// A successful walk always has an initial segment, so this is normally
    /// false; it is provided for collection-style callers.
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// Sum of all checked payload byte lengths.
    pub const fn total_payload_bytes(&self) -> usize {
        self.total_payload_bytes
    }
}

/// Failure while walking a caller-resolved continuation chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowSegmentChainError<E> {
    /// A segment could not be parsed within the exact bytes supplied by the
    /// caller's resolver.
    InvalidSegment {
        /// Caller-supplied target for the malformed segment.
        target: ContinuationTarget,
        /// Zero-based position in the chain.
        segment_index: usize,
        /// Boundary validation failure.
        source: RowSegmentError,
    },
    /// A supplied initial or resolved slice contains bytes after its one
    /// declared physical segment.
    TrailingBytes {
        /// Caller-local target for the segment.
        target: ContinuationTarget,
        /// Zero-based position in the chain.
        segment_index: usize,
        /// Checked segment length declared by its header.
        declared_len: usize,
        /// Total bytes supplied for that segment.
        available: usize,
    },
    /// The caller's explicit target resolver declined or failed to resolve a
    /// continuation.  The walker never falls back to another file or page.
    Resolver {
        /// Target the resolver was asked to resolve.
        target: ContinuationTarget,
        /// Resolver-provided failure.
        source: E,
    },
    /// Following another continuation would exceed `max_segments`.
    SegmentLimit {
        /// Configured maximum number of segments.
        max_segments: usize,
        /// Number that would have been required.
        attempted_segments: usize,
    },
    /// Adding a checked payload would exceed `max_total_payload_bytes`.
    PayloadLimit {
        /// Configured maximum combined payload length.
        max_total_payload_bytes: usize,
        /// Combined length that would have been required.
        attempted_total_payload_bytes: usize,
    },
    /// A continuation target was encountered more than once, including a
    /// continuation back to the caller-supplied initial target.
    Cycle {
        /// Repeated target.
        target: ContinuationTarget,
    },
}

impl<E: fmt::Display> fmt::Display for RowSegmentChainError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSegment {
                target,
                segment_index,
                source,
            } => write!(
                f,
                "row segment {segment_index} at {target} is invalid: {source}"
            ),
            Self::TrailingBytes {
                target,
                segment_index,
                declared_len,
                available,
            } => write!(
                f,
                "row segment {segment_index} at {target} declares {declared_len} bytes, but its resolver supplied {available} bytes"
            ),
            Self::Resolver { target, source } => {
                write!(
                    f,
                    "could not resolve row continuation target {target}: {source}"
                )
            }
            Self::SegmentLimit {
                max_segments,
                attempted_segments,
            } => write!(
                f,
                "row continuation chain needs {attempted_segments} segments, exceeding its {max_segments}-segment limit"
            ),
            Self::PayloadLimit {
                max_total_payload_bytes,
                attempted_total_payload_bytes,
            } => write!(
                f,
                "row continuation chain needs {attempted_total_payload_bytes} payload bytes, exceeding its {max_total_payload_bytes}-byte limit"
            ),
            Self::Cycle { target } => write!(f, "row continuation chain cycles at {target}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for RowSegmentChainError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidSegment { source, .. } => Some(source),
            Self::TrailingBytes { .. } => None,
            Self::Resolver { source, .. } => Some(source),
            Self::SegmentLimit { .. } | Self::PayloadLimit { .. } | Self::Cycle { .. } => None,
        }
    }
}

/// Walk a physical row continuation chain through an explicit caller resolver.
///
/// `initial_target` is deliberately required: the row-segment format has no
/// complete resolver context, so only the caller can state the identity of
/// the first segment in its resolver context. `resolve` is called only for later targets and
/// must resolve every target in that one fixed context for the entire walk.
/// Cycle detection uses the raw [`ContinuationTarget`] values, so changing
/// the resolver context during a walk is unsupported. This function does not
/// select a file, find a page, infer a slot, or assign a table owner.
///
/// `initial_bytes` and every resolver result must contain exactly one declared
/// segment. The resolver returns owned bytes so it can make the file/page
/// ownership boundary fully explicit and may safely reuse transient buffers.
/// The walker copies only each checked payload into its result, checks
/// resource limits before adding it, and terminates on malformed data,
/// trailing bytes, resolver failures, repeated targets, or a limit rather
/// than making a best-effort recovery.
pub fn walk_row_segment_chain<E, F>(
    initial_target: ContinuationTarget,
    initial_bytes: &[u8],
    limits: RowSegmentChainLimits,
    mut resolve: F,
) -> Result<RowSegmentChain, RowSegmentChainError<E>>
where
    F: FnMut(ContinuationTarget) -> Result<Vec<u8>, E>,
{
    let mut visited = BTreeSet::from([initial_target]);
    let mut segments = Vec::new();
    let mut total_payload_bytes = 0usize;
    let mut target = initial_target;
    // The initial bytes remain borrowed, avoiding an allocation before their
    // header and exact-segment boundary are validated. Later resolver results
    // are owned only for the iteration in which they are consumed.
    let mut bytes = Cow::Borrowed(initial_bytes);

    loop {
        let segment_index = segments.len();
        if segment_index >= limits.max_segments {
            return Err(RowSegmentChainError::SegmentLimit {
                max_segments: limits.max_segments,
                attempted_segments: segment_index.saturating_add(1),
            });
        }

        let segment = parse_row_segment(bytes.as_ref()).map_err(|source| {
            RowSegmentChainError::InvalidSegment {
                target,
                segment_index,
                source,
            }
        })?;
        if segment.declared_len() != bytes.len() {
            return Err(RowSegmentChainError::TrailingBytes {
                target,
                segment_index,
                declared_len: segment.declared_len(),
                available: bytes.len(),
            });
        }
        let payload = segment.payload();
        let attempted_total_payload_bytes = total_payload_bytes.saturating_add(payload.len());
        if payload.len()
            > limits
                .max_total_payload_bytes
                .saturating_sub(total_payload_bytes)
        {
            return Err(RowSegmentChainError::PayloadLimit {
                max_total_payload_bytes: limits.max_total_payload_bytes,
                attempted_total_payload_bytes,
            });
        }

        total_payload_bytes += payload.len();
        let next_target = segment.next_target();
        segments.push(RowSegmentChainSegment {
            target,
            flags: segment.flags(),
            declared_len: segment.declared_len(),
            payload: payload.to_vec(),
        });

        let Some(next_target) = next_target else {
            return Ok(RowSegmentChain {
                segments,
                total_payload_bytes,
            });
        };
        if !visited.insert(next_target) {
            return Err(RowSegmentChainError::Cycle {
                target: next_target,
            });
        }
        if segments.len() >= limits.max_segments {
            return Err(RowSegmentChainError::SegmentLimit {
                max_segments: limits.max_segments,
                attempted_segments: segments.len().saturating_add(1),
            });
        }
        let resolved = resolve(next_target).map_err(|source| RowSegmentChainError::Resolver {
            target: next_target,
            source,
        })?;
        // The next iteration consumes these owned bytes before requesting
        // another caller-owned resolution.
        bytes = Cow::Owned(resolved);
        target = next_target;
    }
}

/// Parse the first complete SA17 physical row segment in `input`.
///
/// The returned segment is fail-closed: its declared length must fit entirely
/// inside `input` and must contain the header selected by `flags & 0x04`.
/// This is a header parser, not a continuation-chain walker.
pub fn parse_row_segment(input: &[u8]) -> Result<RowSegment<'_>, RowSegmentError> {
    if input.len() < ROW_SEGMENT_HEADER_LEN {
        return Err(RowSegmentError::MissingHeader {
            available: input.len(),
        });
    }

    let declared_len = usize::from(u16::from_le_bytes([input[0], input[1]]));
    let flags = input[2];
    let continued = flags & ROW_SEGMENT_CONTINUED != 0;
    let header_len = if continued {
        CONTINUED_ROW_SEGMENT_HEADER_LEN
    } else {
        ROW_SEGMENT_HEADER_LEN
    };
    if declared_len < header_len || declared_len > input.len() {
        return Err(RowSegmentError::InvalidLength {
            declared: declared_len,
            header_len,
            available: input.len(),
        });
    }

    let next_target = continued.then(|| ContinuationTarget::from_le_bytes(&input[3..9]));
    Ok(RowSegment {
        declared_len,
        flags,
        next_target,
        bytes: &input[..declared_len],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_non_continued_segment_and_bounds_its_payload() {
        let bytes = [5, 0, 0x80, 0xAA, 0xBB, 0x99, 0x88];
        let segment = parse_row_segment(&bytes).expect("ordinary segment");

        assert_eq!(segment.declared_len(), 5);
        assert_eq!(segment.flags(), 0x80);
        assert!(!segment.is_continued());
        assert_eq!(segment.header_len(), 3);
        assert_eq!(segment.next_target(), None);
        assert_eq!(segment.bytes(), &[5, 0, 0x80, 0xAA, 0xBB]);
        assert_eq!(segment.payload(), &[0xAA, 0xBB]);
    }

    #[test]
    fn non_continued_segment_does_not_promote_trailing_bytes_to_a_locator() {
        let bytes = [3, 0, 0, 1, 2, 3, 4, 5, 6];
        let segment = RowSegment::parse(&bytes).expect("ordinary segment");

        assert_eq!(segment.next_target(), None);
        assert_eq!(segment.payload(), &[]);
        assert_eq!(segment.bytes(), &[3, 0, 0]);
    }

    #[test]
    fn parses_continued_segment_as_resolver_key_and_record_id() {
        let bytes = [11, 0, ROW_SEGMENT_CONTINUED, 1, 2, 3, 4, 5, 6, 0xA1, 0xA2];
        let segment = parse_row_segment(&bytes).expect("continued segment");

        assert!(segment.is_continued());
        assert_eq!(segment.header_len(), 9);
        let target = segment.next_target().expect("continued segment target");
        assert_eq!(target.resolver_key(), 0x0403_0201);
        assert_eq!(target.record_id(), 0x0605);
        assert_eq!(segment.payload(), &[0xA1, 0xA2]);
        assert_eq!(
            target.to_string(),
            "resolver_key=0x04030201, record_id=0x0605"
        );
    }

    #[test]
    fn continuation_target_uses_the_disk_writer_byte_order() {
        // dbserv17's continuation writer emits the low-to-high bytes of the
        // resolver key at +3..+6 and record ID at +7..+8. Use
        // non-palindromic values so this cannot pass under a byte-swapped
        // decoder.
        let bytes = [
            9,
            0,
            ROW_SEGMENT_CONTINUED,
            0x78,
            0x56,
            0x34,
            0x12,
            0xCD,
            0xAB,
        ];
        let target = parse_row_segment(&bytes)
            .expect("continued segment")
            .next_target()
            .expect("continuation target");

        assert_eq!(target, ContinuationTarget::new(0x1234_5678, 0xABCD));
    }

    #[test]
    fn accepts_zero_continuation_target_without_inventing_an_unproven_sentinel() {
        let bytes = [9, 0, ROW_SEGMENT_CONTINUED, 0, 0, 0, 0, 0, 0];
        let segment = parse_row_segment(&bytes).expect("zero remains representable");

        assert_eq!(segment.next_target(), Some(ContinuationTarget::new(0, 0)));
    }

    #[test]
    fn preserves_unknown_flag_bits_while_using_only_the_proven_bit() {
        let bytes = [9, 0, 0xF4, 1, 0, 0, 0, 0, 0];
        let segment = parse_row_segment(&bytes).expect("continued segment");

        assert_eq!(segment.flags(), 0xF4);
        assert!(segment.is_continued());
        assert_eq!(segment.next_target(), Some(ContinuationTarget::new(1, 0)));
    }

    #[test]
    fn rejects_each_prefix_shorter_than_the_fixed_header() {
        for available in 0..ROW_SEGMENT_HEADER_LEN {
            let err = parse_row_segment(&[0; ROW_SEGMENT_HEADER_LEN][..available])
                .expect_err("fixed header is incomplete");
            assert_eq!(err, RowSegmentError::MissingHeader { available });
        }
    }

    #[test]
    fn rejects_normal_length_shorter_than_header() {
        let err = parse_row_segment(&[2, 0, 0]).expect_err("two bytes cannot hold a header");
        assert_eq!(
            err,
            RowSegmentError::InvalidLength {
                declared: 2,
                header_len: 3,
                available: 3,
            }
        );
    }

    #[test]
    fn rejects_continued_length_shorter_than_continued_header() {
        let err = parse_row_segment(&[8, 0, ROW_SEGMENT_CONTINUED, 0, 0, 0, 0, 0])
            .expect_err("continued header needs nine bytes");
        assert_eq!(
            err,
            RowSegmentError::InvalidLength {
                declared: 8,
                header_len: 9,
                available: 8,
            }
        );
    }

    #[test]
    fn rejects_declared_length_outside_containing_area() {
        let err = parse_row_segment(&[10, 0, 0, 0, 0]).expect_err("truncated segment");
        assert_eq!(
            err,
            RowSegmentError::InvalidLength {
                declared: 10,
                header_len: 3,
                available: 5,
            }
        );
    }

    #[test]
    fn continuation_target_preserves_each_raw_component() {
        let target = ContinuationTarget::new(0xFEDC_BA98, 0x7654);
        assert_eq!(target.resolver_key(), 0xFEDC_BA98);
        assert_eq!(target.record_id(), 0x7654);
    }

    fn continued(target: ContinuationTarget, payload: &[u8]) -> Vec<u8> {
        let len = CONTINUED_ROW_SEGMENT_HEADER_LEN + payload.len();
        let mut bytes = Vec::with_capacity(len);
        bytes.extend_from_slice(&(len as u16).to_le_bytes());
        bytes.push(ROW_SEGMENT_CONTINUED);
        bytes.extend_from_slice(&target.resolver_key().to_le_bytes());
        bytes.extend_from_slice(&target.record_id().to_le_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    fn final_segment(payload: &[u8]) -> Vec<u8> {
        let len = ROW_SEGMENT_HEADER_LEN + payload.len();
        let mut bytes = Vec::with_capacity(len);
        bytes.extend_from_slice(&(len as u16).to_le_bytes());
        bytes.push(0);
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn walks_a_bounded_chain_through_the_callers_explicit_resolver() {
        let initial_target = ContinuationTarget::new(10, 1);
        let next_target = ContinuationTarget::new(11, 1);
        let initial = continued(next_target, &[0xAA]);
        let terminal = final_segment(&[0xBB, 0xCC]);
        let mut requested = Vec::new();

        let chain = walk_row_segment_chain(
            initial_target,
            &initial,
            RowSegmentChainLimits::new(2, 3),
            |target| -> Result<Vec<u8>, &'static str> {
                requested.push(target);
                assert_eq!(target, next_target);
                Ok(terminal.clone())
            },
        )
        .expect("bounded chain");

        assert_eq!(requested, [next_target]);
        assert_eq!(chain.len(), 2);
        assert!(!chain.is_empty());
        assert_eq!(chain.total_payload_bytes(), 3);
        assert_eq!(chain.segments()[0].target(), initial_target);
        assert_eq!(chain.segments()[0].flags(), ROW_SEGMENT_CONTINUED);
        assert_eq!(chain.segments()[0].declared_len(), 10);
        assert_eq!(chain.segments()[0].payload(), &[0xAA]);
        assert_eq!(chain.segments()[1].target(), next_target);
        assert_eq!(chain.segments()[1].payload(), &[0xBB, 0xCC]);
    }

    #[test]
    fn rejects_a_cycle_back_to_the_explicit_initial_target_without_resolving_it() {
        let initial_target = ContinuationTarget::new(1, 7);
        let initial = continued(initial_target, &[]);
        let mut resolver_called = false;

        let err = walk_row_segment_chain(
            initial_target,
            &initial,
            RowSegmentChainLimits::new(2, 0),
            |_| -> Result<Vec<u8>, &'static str> {
                resolver_called = true;
                Ok(final_segment(&[]))
            },
        )
        .expect_err("cycle");

        assert!(!resolver_called);
        assert_eq!(
            err,
            RowSegmentChainError::Cycle {
                target: initial_target
            }
        );
    }

    #[test]
    fn enforces_segment_limit_before_calling_the_next_resolver() {
        let initial_target = ContinuationTarget::new(1, 1);
        let next_target = ContinuationTarget::new(2, 1);
        let initial = continued(next_target, &[]);
        let mut resolver_called = false;

        let err = walk_row_segment_chain(
            initial_target,
            &initial,
            RowSegmentChainLimits::new(1, 0),
            |_| -> Result<Vec<u8>, &'static str> {
                resolver_called = true;
                Ok(final_segment(&[]))
            },
        )
        .expect_err("segment cap");

        assert!(!resolver_called);
        assert_eq!(
            err,
            RowSegmentChainError::SegmentLimit {
                max_segments: 1,
                attempted_segments: 2,
            }
        );
    }

    #[test]
    fn enforces_aggregate_payload_limit_before_resolving_a_continuation() {
        let initial_target = ContinuationTarget::new(1, 1);
        let next_target = ContinuationTarget::new(2, 1);
        let initial = continued(next_target, &[1, 2]);
        let mut resolver_called = false;

        let err = walk_row_segment_chain(
            initial_target,
            &initial,
            RowSegmentChainLimits::new(2, 1),
            |_| -> Result<Vec<u8>, &'static str> {
                resolver_called = true;
                Ok(final_segment(&[]))
            },
        )
        .expect_err("payload cap");

        assert!(!resolver_called);
        assert_eq!(
            err,
            RowSegmentChainError::PayloadLimit {
                max_total_payload_bytes: 1,
                attempted_total_payload_bytes: 2,
            }
        );
    }

    #[test]
    fn propagates_resolver_error_without_a_fallback_resolution() {
        let initial_target = ContinuationTarget::new(1, 1);
        let next_target = ContinuationTarget::new(2, 1);
        let initial = continued(next_target, &[]);

        let err = walk_row_segment_chain(
            initial_target,
            &initial,
            RowSegmentChainLimits::new(2, 0),
            |_| -> Result<Vec<u8>, &'static str> { Err("outside caller context") },
        )
        .expect_err("resolver error");

        assert_eq!(
            err,
            RowSegmentChainError::Resolver {
                target: next_target,
                source: "outside caller context",
            }
        );
    }

    #[test]
    fn reports_malformed_resolved_segment_at_its_exact_target_and_position() {
        let initial_target = ContinuationTarget::new(1, 1);
        let next_target = ContinuationTarget::new(2, 1);
        let initial = continued(next_target, &[]);

        let err = walk_row_segment_chain(
            initial_target,
            &initial,
            RowSegmentChainLimits::new(2, 0),
            |_| -> Result<Vec<u8>, &'static str> { Ok(vec![2, 0, 0]) },
        )
        .expect_err("bad resolved segment");

        assert_eq!(
            err,
            RowSegmentChainError::InvalidSegment {
                target: next_target,
                segment_index: 1,
                source: RowSegmentError::InvalidLength {
                    declared: 2,
                    header_len: 3,
                    available: 3,
                },
            }
        );
    }

    #[test]
    fn reports_malformed_initial_segment_at_the_callers_explicit_target() {
        let initial_target = ContinuationTarget::new(0xAA, 3);

        let err = walk_row_segment_chain(
            initial_target,
            &[2, 0, 0],
            RowSegmentChainLimits::new(1, 0),
            |_| -> Result<Vec<u8>, &'static str> { unreachable!("no continuation") },
        )
        .expect_err("bad initial segment");

        assert_eq!(
            err,
            RowSegmentChainError::InvalidSegment {
                target: initial_target,
                segment_index: 0,
                source: RowSegmentError::InvalidLength {
                    declared: 2,
                    header_len: 3,
                    available: 3,
                },
            }
        );
    }

    #[test]
    fn rejects_trailing_bytes_for_initial_or_resolved_chain_segments() {
        let initial_target = ContinuationTarget::new(1, 1);
        let next_target = ContinuationTarget::new(2, 1);

        let err = walk_row_segment_chain(
            initial_target,
            &[3, 0, 0, 0xAA],
            RowSegmentChainLimits::new(1, 0),
            |_| -> Result<Vec<u8>, &'static str> { unreachable!("no continuation") },
        )
        .expect_err("initial trailing bytes");
        assert_eq!(
            err,
            RowSegmentChainError::TrailingBytes {
                target: initial_target,
                segment_index: 0,
                declared_len: 3,
                available: 4,
            }
        );

        let initial = continued(next_target, &[]);
        let err = walk_row_segment_chain(
            initial_target,
            &initial,
            RowSegmentChainLimits::new(2, 0),
            |_| -> Result<Vec<u8>, &'static str> { Ok(vec![3, 0, 0, 0xAA]) },
        )
        .expect_err("resolved trailing bytes");
        assert_eq!(
            err,
            RowSegmentChainError::TrailingBytes {
                target: next_target,
                segment_index: 1,
                declared_len: 3,
                available: 4,
            }
        );
    }

    #[test]
    fn zero_segment_limit_fails_before_parsing_or_calling_the_resolver() {
        let initial_target = ContinuationTarget::new(1, 1);
        let err = walk_row_segment_chain(
            initial_target,
            &[3, 0, 0],
            RowSegmentChainLimits::new(0, 0),
            |_| -> Result<Vec<u8>, &'static str> { unreachable!("no continuation") },
        )
        .expect_err("zero segment cap");

        assert_eq!(
            err,
            RowSegmentChainError::SegmentLimit {
                max_segments: 0,
                attempted_segments: 1,
            }
        );
    }
}
