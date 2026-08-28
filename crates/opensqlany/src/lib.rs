//! SAP SQL Anywhere page-store reader.
//!
//! This crate parses the on-disk page-store format of SAP SQL Anywhere
//! (initially targeting SA17 build 2182, 2015 release). It provides:
//!
//! * [`PageStore`]: zero-copy random-access iteration over 4 KiB pages.
//! * [`Superblock`]: page-0 parser (magic, format version triple).
//! * [`PageTrailer`]: the universal 12-byte trailer at `0xFF0..0xFFB`.
//!   Call [`Page::verify_crc`] for per-page CRC-32 integrity checks.
//! * [`SlottedPage`]: descending row-offset-array catalog-page parser.
//! * [`ApModel`]: arithmetic-progression stream-cipher deobfuscation.
//!
//! # Scope
//!
//! This release (v0.1) covers the page-store layer plus conservative,
//! schema-driven typed-row and page-link primitives. It does not discover
//! table ownership, resolve overflow/LONG values, or interpret an application
//! catalog; those responsibilities remain with a dialect-specific caller such
//! as OpenQBW.
//!
//! # Example
//!
//! ```no_run
//! use opensqlany::PageStore;
//!
//! let store = PageStore::open("database.db")?;
//! let sb = store.superblock()?;
//! assert!(sb.magic_ok());
//!
//! for (pn, page) in store.pages().enumerate().skip(1) {
//!     let trailer = page.trailer();
//!     page.verify_crc()?;
//!     println!("page {pn}: type {:?}", trailer.page_type());
//! }
//! # Ok::<(), opensqlany::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod ap;
mod error;
mod materialized_page;
mod page;
mod page_links;
mod page_permutation;
mod row_decoder;
mod row_segment;
mod slotted;
mod store;
mod superblock;

pub use ap::{
    ApModel, ApPageRecoveryConfidence, ApSectorRecoveryConfidence, SECTOR_SIZE, SECTORS_PER_PAGE,
};
pub use error::{Error, Result};
pub use materialized_page::{
    MATERIALIZED_TABLE_PAGE_LEN, MATERIALIZED_TABLE_PAGE_TYPE, MaterializedPageError,
    MaterializedRecord, MaterializedRowRecord, MaterializedTablePage,
};
pub use page::{PAGE_SIZE, Page, PageTrailer, PageType};
pub use page_links::{
    PageLinkMetadata, PageLinkTarget, PageLinkWalk, PageLinkWalkStop, find_page_link_metadata,
    walk_page_links,
};
pub use page_permutation::{
    PAGE_PERMUTATION_SECTOR_LEN, PagePermutationError, permute_power_of_two_in_place,
    permute_sector_in_place,
};
pub use row_decoder::{
    BooleanTailLayout, ColumnDef, ColumnType, Decimal, DecodeError, DecodedRow,
    EnterpriseNumericToken, EnumLayout, NullBitmapCoverage, NullBitmapLayout, NumericLayout,
    PartialDecodedRow, PartialRowValue, ROW_FLAG_OVERFLOW, ROW_FLAG_REFERENCE,
    ROW_FLAG_REFERENCE_DESTINATION, ROW_SIZE_MASK, RowPrefixLayout, RowSchema, SaDate, SaDateTime,
    Value, VariableLengthLayout, VariableOverflowLayout, decode_materialized_row_record_exact,
    decode_row, decode_row_exact, decode_row_prefix_and_boolean_tail, legacy_syscolumn_schema,
    legacy_systable_schema,
};
pub use row_segment::{
    CONTINUED_ROW_SEGMENT_HEADER_LEN, ContinuationTarget, ROW_SEGMENT_CONTINUED,
    ROW_SEGMENT_HEADER_LEN, RowSegment, RowSegmentChain, RowSegmentChainError,
    RowSegmentChainLimits, RowSegmentChainSegment, RowSegmentError, parse_row_segment,
    walk_row_segment_chain,
};
pub use slotted::{SlotDirectory, SlottedPage};
pub use store::{PageStore, Pages};
pub use superblock::{SA_COPYRIGHT_MARKER, SA_MAGIC, Superblock};
