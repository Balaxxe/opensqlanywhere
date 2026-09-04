//! Parser for an already-materialized SA17 type-4 table page.
//!
//! This module accepts only a caller-supplied 4096-byte in-memory page whose
//! type byte is already `4`. It does not map file bytes to that representation,
//! choose an owner, or assign a table to the page.

use core::fmt;

use crate::{RowSegment, RowSegmentError};

/// Exact byte length of the materialized table-page representation.
pub const MATERIALIZED_TABLE_PAGE_LEN: usize = 4096;

/// Required type byte at offset `0x10` of a materialized table page.
pub const MATERIALIZED_TABLE_PAGE_TYPE: u8 = 4;

const PAGE_KEY_OFFSET: usize = 0;
const PAGE_TYPE_OFFSET: usize = 0x10;
const RECORD_COUNT_OFFSET: usize = 0x16;
const DIRECTORY_OFFSET: usize = 0x1c;
const DIRECTORY_ENTRY_LEN: usize = 2;

/// A checked, already-materialized type-4 page.
///
/// Its `key` is an opaque page-local value from offset zero. It is not claimed
/// to be a raw QBW page number, table identifier, or file offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaterializedTablePage<'a> {
    bytes: &'a [u8],
    key: u32,
    record_count: u16,
}

impl<'a> MaterializedTablePage<'a> {
    /// Parse and fully validate an already-materialized 4096-byte type-4 page.
    ///
    /// Every nonzero directory entry is checked as a bounded physical row
    /// record: its little-endian `u16` must exactly bound the record within
    /// this page. Bytes after that length are intentionally not treated as a
    /// [`RowSegment`] header: their carrier grammar is table-specific and a
    /// first post-length byte can coincidentally look like a segment flag.
    /// Zero directory entries remain unavailable records because the proven
    /// runtime resolver rejects a requested zero entry.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, MaterializedPageError> {
        if bytes.len() != MATERIALIZED_TABLE_PAGE_LEN {
            return Err(MaterializedPageError::InvalidPageLength {
                actual: bytes.len(),
            });
        }
        let page_type = bytes[PAGE_TYPE_OFFSET];
        if page_type != MATERIALIZED_TABLE_PAGE_TYPE {
            return Err(MaterializedPageError::WrongPageType { actual: page_type });
        }

        let key = u32::from_le_bytes([
            bytes[PAGE_KEY_OFFSET],
            bytes[PAGE_KEY_OFFSET + 1],
            bytes[PAGE_KEY_OFFSET + 2],
            bytes[PAGE_KEY_OFFSET + 3],
        ]);
        let record_count =
            u16::from_le_bytes([bytes[RECORD_COUNT_OFFSET], bytes[RECORD_COUNT_OFFSET + 1]]);
        let page = Self {
            bytes,
            key,
            record_count,
        };
        page.directory_end()?;

        for record_id in 0..record_count {
            let offset = page.directory_entry(record_id)?;
            if offset != 0 {
                page.row_at(record_id, offset)?;
            }
        }
        Ok(page)
    }

    /// Opaque little-endian key stored at page offset zero.
    pub const fn key(self) -> u32 {
        self.key
    }

    /// Number of directory entries at page offset `0x1c`.
    pub const fn record_count(self) -> u16 {
        self.record_count
    }

    /// Return one checked record selected by its directory identifier.
    pub fn record(
        self,
        record_id: u16,
    ) -> Result<MaterializedRowRecord<'a>, MaterializedPageError> {
        let offset = self.directory_entry(record_id)?;
        if offset == 0 {
            return Err(MaterializedPageError::MissingRecord { record_id });
        }
        let (byte_offset, bytes) = self.row_at(record_id, offset)?;
        Ok(MaterializedRowRecord {
            record_id,
            directory_offset: offset,
            byte_offset,
            bytes,
        })
    }

    fn directory_end(self) -> Result<usize, MaterializedPageError> {
        let bytes = usize::from(self.record_count)
            .checked_mul(DIRECTORY_ENTRY_LEN)
            .ok_or(MaterializedPageError::DirectoryOutOfBounds {
                record_count: self.record_count,
            })?;
        let end = DIRECTORY_OFFSET.checked_add(bytes).ok_or(
            MaterializedPageError::DirectoryOutOfBounds {
                record_count: self.record_count,
            },
        )?;
        if end > self.bytes.len() {
            return Err(MaterializedPageError::DirectoryOutOfBounds {
                record_count: self.record_count,
            });
        }
        Ok(end)
    }

    fn directory_entry(self, record_id: u16) -> Result<u16, MaterializedPageError> {
        if record_id >= self.record_count {
            return Err(MaterializedPageError::RecordIdOutOfRange {
                record_id,
                record_count: self.record_count,
            });
        }
        self.directory_end()?;
        let index = usize::from(record_id)
            .checked_mul(DIRECTORY_ENTRY_LEN)
            .ok_or(MaterializedPageError::RecordIdOutOfRange {
                record_id,
                record_count: self.record_count,
            })?;
        let entry = DIRECTORY_OFFSET.checked_add(index).ok_or(
            MaterializedPageError::RecordIdOutOfRange {
                record_id,
                record_count: self.record_count,
            },
        )?;
        let end = entry.checked_add(DIRECTORY_ENTRY_LEN).ok_or(
            MaterializedPageError::RecordIdOutOfRange {
                record_id,
                record_count: self.record_count,
            },
        )?;
        let bytes =
            self.bytes
                .get(entry..end)
                .ok_or(MaterializedPageError::RecordIdOutOfRange {
                    record_id,
                    record_count: self.record_count,
                })?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn row_at(
        self,
        record_id: u16,
        directory_offset: u16,
    ) -> Result<(usize, &'a [u8]), MaterializedPageError> {
        let directory_end = self.directory_end()?;
        let start = DIRECTORY_OFFSET
            .checked_add(usize::from(directory_offset))
            .ok_or(MaterializedPageError::RecordOutOfBounds {
                record_id,
                directory_offset,
            })?;
        if start < directory_end {
            return Err(MaterializedPageError::RecordOutOfBounds {
                record_id,
                directory_offset,
            });
        }
        let record_bytes =
            self.bytes
                .get(start..)
                .ok_or(MaterializedPageError::RecordOutOfBounds {
                    record_id,
                    directory_offset,
                })?;
        if record_bytes.len() < 2 {
            return Err(MaterializedPageError::InvalidRecordLength {
                record_id,
                directory_offset,
                declared: 0,
                available: record_bytes.len(),
            });
        }
        let declared = usize::from(u16::from_le_bytes([record_bytes[0], record_bytes[1]]));
        if declared < 2 || declared > record_bytes.len() {
            return Err(MaterializedPageError::InvalidRecordLength {
                record_id,
                directory_offset,
                declared,
                available: record_bytes.len(),
            });
        }
        Ok((start, &record_bytes[..declared]))
    }
}

/// A checked physical row record selected from a [`MaterializedTablePage`]
/// directory.
///
/// The leading two bytes are a bounded little-endian total length. No
/// interpretation of bytes after that length is implied. In particular,
/// application table rows may use a table-specific carrier grammar rather
/// than the header of [`RowSegment`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaterializedRowRecord<'a> {
    record_id: u16,
    directory_offset: u16,
    byte_offset: usize,
    bytes: &'a [u8],
}

impl<'a> MaterializedRowRecord<'a> {
    /// Identifier used to select this record in its page-local directory.
    pub const fn record_id(self) -> u16 {
        self.record_id
    }

    /// Raw `u16` directory value, relative to page offset `0x1c`.
    pub const fn directory_offset(self) -> u16 {
        self.directory_offset
    }

    /// Checked resolved byte offset within the materialized page.
    ///
    /// This is `0x1c + directory_offset`; it is not a raw QBW file offset.
    pub const fn byte_offset(self) -> usize {
        self.byte_offset
    }

    /// Checked physical row length, including its little-endian `u16` header.
    pub const fn declared_len(self) -> usize {
        self.bytes.len()
    }

    /// Checked raw row bytes, including its two-byte length header.
    pub const fn bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Explicitly parse this record as an SA17 row segment.
    ///
    /// This is not performed automatically because a materialized table row's
    /// post-length carrier grammar is not inferred. Call it only when
    /// independent evidence establishes the row-segment carrier.
    pub fn as_row_segment(self) -> Result<RowSegment<'a>, RowSegmentError> {
        RowSegment::parse(self.bytes)
    }
}

/// Backwards-compatible name for a materialized physical row record.
///
/// New code should use [`MaterializedRowRecord`], which makes clear that no
/// row-segment payload or continuation semantics are inferred.
pub type MaterializedRecord<'a> = MaterializedRowRecord<'a>;

/// Failure while parsing or selecting a materialized type-4 page record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaterializedPageError {
    /// The supplied representation is not exactly 4096 bytes.
    InvalidPageLength {
        /// Bytes supplied by the caller.
        actual: usize,
    },
    /// The page's type byte at offset `0x10` is not the required value `4`.
    WrongPageType {
        /// Type byte found in the supplied page.
        actual: u8,
    },
    /// The record directory cannot fit in the supplied fixed-size page.
    DirectoryOutOfBounds {
        /// Declared number of directory entries.
        record_count: u16,
    },
    /// The requested record identifier is not in the declared directory.
    RecordIdOutOfRange {
        /// Requested page-local record identifier.
        record_id: u16,
        /// Declared number of directory entries.
        record_count: u16,
    },
    /// A requested directory entry is zero and therefore unavailable.
    MissingRecord {
        /// Requested page-local record identifier.
        record_id: u16,
    },
    /// A nonzero directory offset cannot address this page.
    RecordOutOfBounds {
        /// Page-local record identifier.
        record_id: u16,
        /// Raw directory offset relative to page offset `0x1c`.
        directory_offset: u16,
    },
    /// A nonzero directory entry does not contain a complete bounded row.
    InvalidRecordLength {
        /// Page-local record identifier.
        record_id: u16,
        /// Raw directory offset relative to page offset `0x1c`.
        directory_offset: u16,
        /// Length read from the record's first two bytes, or zero when those
        /// two bytes were unavailable.
        declared: usize,
        /// Bytes available from the directory-selected offset to page end.
        available: usize,
    },
}

impl fmt::Display for MaterializedPageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPageLength { actual } => write!(
                f,
                "materialized table page needs exactly {MATERIALIZED_TABLE_PAGE_LEN} bytes, got {actual}"
            ),
            Self::WrongPageType { actual } => write!(
                f,
                "materialized table page has type {actual}, want {MATERIALIZED_TABLE_PAGE_TYPE}"
            ),
            Self::DirectoryOutOfBounds { record_count } => write!(
                f,
                "materialized table page directory for {record_count} records is out of bounds"
            ),
            Self::RecordIdOutOfRange {
                record_id,
                record_count,
            } => write!(
                f,
                "record id {record_id} is outside a {record_count}-entry materialized page directory"
            ),
            Self::MissingRecord { record_id } => {
                write!(
                    f,
                    "record id {record_id} is unavailable in the materialized page"
                )
            }
            Self::RecordOutOfBounds {
                record_id,
                directory_offset,
            } => write!(
                f,
                "record id {record_id} has out-of-bounds directory offset {directory_offset}"
            ),
            Self::InvalidRecordLength {
                record_id,
                directory_offset,
                ..
            } => write!(
                f,
                "record id {record_id} at directory offset {directory_offset} has invalid bounded-row length"
            ),
        }
    }
}

impl std::error::Error for MaterializedPageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidPageLength { .. }
            | Self::WrongPageType { .. }
            | Self::DirectoryOutOfBounds { .. }
            | Self::RecordIdOutOfRange { .. }
            | Self::MissingRecord { .. }
            | Self::RecordOutOfBounds { .. }
            | Self::InvalidRecordLength { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ROW_SEGMENT_CONTINUED;

    fn synthetic_page(key: u32, record_count: u16) -> [u8; MATERIALIZED_TABLE_PAGE_LEN] {
        let mut page = [0_u8; MATERIALIZED_TABLE_PAGE_LEN];
        page[..4].copy_from_slice(&key.to_le_bytes());
        page[PAGE_TYPE_OFFSET] = MATERIALIZED_TABLE_PAGE_TYPE;
        page[RECORD_COUNT_OFFSET..RECORD_COUNT_OFFSET + 2]
            .copy_from_slice(&record_count.to_le_bytes());
        page
    }

    fn set_record(page: &mut [u8], record_id: u16, relative_offset: u16, segment: &[u8]) {
        let entry = DIRECTORY_OFFSET + usize::from(record_id) * DIRECTORY_ENTRY_LEN;
        page[entry..entry + 2].copy_from_slice(&relative_offset.to_le_bytes());
        let start = DIRECTORY_OFFSET + usize::from(relative_offset);
        page[start..start + segment.len()].copy_from_slice(segment);
    }

    #[test]
    fn parses_synthetic_page_4296_record_17_metadata_without_payload_fixture() {
        let mut bytes = synthetic_page(4296, 18);
        set_record(&mut bytes, 17, 128, &[3, 0, 0]);

        let page = MaterializedTablePage::parse(&bytes).expect("type-4 page");
        let record = page.record(17).expect("record 17");
        assert_eq!(page.key(), 4296);
        assert_eq!(page.record_count(), 18);
        assert_eq!(record.record_id(), 17);
        assert_eq!(record.directory_offset(), 128);
        assert_eq!(record.byte_offset(), DIRECTORY_OFFSET + 128);
        assert_eq!(record.declared_len(), 3);
        assert_eq!(record.bytes(), &[3, 0, 0]);
        assert!(matches!(
            record.as_row_segment(),
            Ok(segment) if segment.flags() == 0 && segment.payload().is_empty()
        ));
    }

    #[test]
    fn parses_synthetic_page_3980_record_16_continuation_metadata() {
        let mut bytes = synthetic_page(3980, 17);
        set_record(
            &mut bytes,
            16,
            160,
            &[
                9,
                0,
                ROW_SEGMENT_CONTINUED,
                0x78,
                0x56,
                0x34,
                0x12,
                0xCD,
                0xAB,
            ],
        );

        let record = MaterializedTablePage::parse(&bytes)
            .expect("type-4 page")
            .record(16)
            .expect("record 16");
        assert_eq!(record.record_id(), 16);
        assert_eq!(record.directory_offset(), 160);
        assert_eq!(record.byte_offset(), DIRECTORY_OFFSET + 160);
        assert_eq!(record.declared_len(), 9);
        assert_eq!(record.bytes()[2], ROW_SEGMENT_CONTINUED);
        assert_eq!(
            record.as_row_segment().unwrap().next_target(),
            Some(crate::ContinuationTarget::new(0x1234_5678, 0xABCD))
        );
    }

    #[test]
    fn rejects_non_materialized_length_and_type() {
        assert_eq!(
            MaterializedTablePage::parse(&[0; MATERIALIZED_TABLE_PAGE_LEN - 1]),
            Err(MaterializedPageError::InvalidPageLength {
                actual: MATERIALIZED_TABLE_PAGE_LEN - 1,
            })
        );
        let mut bytes = synthetic_page(1, 0);
        bytes[PAGE_TYPE_OFFSET] = 3;
        assert_eq!(
            MaterializedTablePage::parse(&bytes),
            Err(MaterializedPageError::WrongPageType { actual: 3 })
        );
    }

    #[test]
    fn accepts_bounded_rows_that_are_not_row_segments() {
        let mut bytes = synthetic_page(1, 1);
        set_record(&mut bytes, 0, 128, &[2, 0, 0]);

        let record = MaterializedTablePage::parse(&bytes)
            .unwrap()
            .record(0)
            .unwrap();
        assert_eq!(record.bytes(), &[2, 0]);
        assert_eq!(
            record.as_row_segment(),
            Err(RowSegmentError::MissingHeader { available: 2 })
        );
    }

    #[test]
    fn rejects_record_id_outside_directory_and_zero_directory_entry() {
        let bytes = synthetic_page(1, 2);
        let page = MaterializedTablePage::parse(&bytes).expect("empty entries are valid");

        assert_eq!(
            page.record(2),
            Err(MaterializedPageError::RecordIdOutOfRange {
                record_id: 2,
                record_count: 2,
            })
        );
        assert_eq!(
            page.record(1),
            Err(MaterializedPageError::MissingRecord { record_id: 1 })
        );
    }

    #[test]
    fn rejects_directory_offset_that_cannot_address_a_row_length() {
        let mut bytes = synthetic_page(1, 1);
        let relative_offset = (MATERIALIZED_TABLE_PAGE_LEN - DIRECTORY_OFFSET - 2) as u16;
        let entry = DIRECTORY_OFFSET;
        bytes[entry..entry + 2].copy_from_slice(&relative_offset.to_le_bytes());

        assert_eq!(
            MaterializedTablePage::parse(&bytes),
            Err(MaterializedPageError::InvalidRecordLength {
                record_id: 0,
                directory_offset: relative_offset,
                declared: 0,
                available: 2,
            })
        );
    }

    #[test]
    fn eagerly_rejects_a_record_offset_inside_its_directory() {
        let mut bytes = synthetic_page(1, 2);
        // The two entries occupy 0x1c..0x20; a relative offset of two points
        // at 0x1e, inside that directory rather than at a row body.
        bytes[DIRECTORY_OFFSET..DIRECTORY_OFFSET + 2].copy_from_slice(&2_u16.to_le_bytes());

        assert_eq!(
            MaterializedTablePage::parse(&bytes),
            Err(MaterializedPageError::RecordOutOfBounds {
                record_id: 0,
                directory_offset: 2,
            })
        );
    }
}
