//! Typed SQL Anywhere row decoding.
//!
//! This module deliberately decodes only the self-contained part of an SA
//! row.  It never follows overflow or row-reference pointers: callers must
//! provide a verified resolver for those records before treating them as
//! application data.
//!
//! ## Provenance
//!
//! The on-disk grammar modelled here was cross-checked against
//! `DBReaderSybase.pas` from [serbod/DBReader], Sergey Bodrov (MIT), revision
//! 2025.12.01.  This is an independent Rust implementation; in particular it
//! keeps variable-length overflow values unsupported, keeps numeric values
//! decimal rather than converting them to binary floating point, and makes
//! boolean-tail layout an explicit schema choice.
//!
//! [serbod/DBReader]: https://github.com/serbod/DBReader

use std::fmt;

/// Mask for the low thirteen row-size bits.
pub const ROW_SIZE_MASK: u16 = 0x1fff;
/// Row contains an overflow fragment or pointer.
pub const ROW_FLAG_OVERFLOW: u16 = 0x2000;
/// Row is a pointer to another row.
pub const ROW_FLAG_REFERENCE: u16 = 0x4000;
/// Row is the destination of a row reference.
pub const ROW_FLAG_REFERENCE_DESTINATION: u16 = 0x8000;

/// SQL Anywhere physical column domain identifiers observed in system and
/// QuickBooks tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ColumnType {
    /// `SMALLINT`.
    SmallInt = 1,
    /// Signed integer; its schema width determines 1, 2, 4, or 8 bytes.
    Integer = 2,
    /// SQL Anywhere base-100 decimal.
    Numeric = 3,
    /// Alternate signed integer domain.
    Integer2 = 4,
    /// Signed minute count from SQL Anywhere's legacy date epoch.
    Date = 6,
    /// Variable-length character/octet string.
    Char = 8,
    /// Variable-length character/octet string.
    Char2 = 9,
    /// Variable-length text/octet string.
    Text = 10,
    /// Variable-length text/octet string.
    Text2 = 11,
    /// Date minutes plus an uninterpreted signed 32-bit subminute field.
    DateTime = 13,
    /// Enumerated domain.
    ///
    /// The DBReader domain map identifies domain 19 as `ENUM`, but the
    /// reference grammar does not establish its physical scalar width or
    /// signedness.  It is therefore recognized, then rejected by the typed
    /// decoder rather than guessed as an integer or boolean.
    Enum = 19,
    /// Unsigned 64-bit integer.
    UInt64 = 20,
    /// Unsigned 32-bit integer.
    UInt32 = 21,
    /// Signed 64-bit integer.
    Int64 = 23,
    /// Boolean stored in a schema-defined tail sidecar or inline byte.
    Boolean = 24,
}

impl ColumnType {
    /// Convert a system-catalog domain identifier to a supported physical type.
    pub fn from_domain_id(id: u16) -> Option<Self> {
        Some(match id {
            1 => Self::SmallInt,
            2 => Self::Integer,
            3 => Self::Numeric,
            4 => Self::Integer2,
            6 => Self::Date,
            8 => Self::Char,
            9 => Self::Char2,
            10 => Self::Text,
            11 => Self::Text2,
            13 => Self::DateTime,
            19 => Self::Enum,
            20 => Self::UInt64,
            21 => Self::UInt32,
            23 => Self::Int64,
            24 => Self::Boolean,
            _ => return None,
        })
    }

    fn is_variable(self) -> bool {
        matches!(self, Self::Char | Self::Char2 | Self::Text | Self::Text2)
    }
}

/// A physical column in a [`RowSchema`].  `width` is required for integer
/// domains whose catalog definition controls their storage width; it is
/// ignored for variable and date-like types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnDef {
    /// Stable catalog column identifier, where known.
    pub id: u32,
    /// Human-readable catalog column name.
    pub name: String,
    /// On-disk domain type.
    pub column_type: ColumnType,
    /// Declared width from `SYSCOLUMN`; see type-specific semantics above.
    pub width: u16,
    /// Whether this column consumes a bit in the row null bitmap.
    pub nullable: bool,
}

impl ColumnDef {
    /// Build a column definition.
    pub fn new(
        id: u32,
        name: impl Into<String>,
        column_type: ColumnType,
        width: u16,
        nullable: bool,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            column_type,
            width,
            nullable,
        }
    }
}

/// How Boolean values are physically stored.
///
/// SQL Anywhere catalog metadata does not itself identify this detail, so a
/// caller must choose it rather than allowing the decoder to guess.  The
/// legacy layouts keep all Boolean values in a sidecar after the sequential
/// fields.  `InlineBytes` instead consumes one byte at the Boolean column's
/// physical ordinal, just like a fixed-width scalar.  It exists because an
/// Enterprise materialized-row layout must not be silently forced into the
/// legacy tail grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BooleanTailLayout {
    /// A byte (zero=false, nonzero=true) for each present boolean column.
    #[default]
    Bytes,
    /// One MSB-first bitmap covering present boolean columns.
    PackedMsbFirst,
    /// One byte (zero=false, nonzero=true) at each present Boolean column's
    /// physical ordinal.
    InlineBytes,
    /// MSB-first packed bytes at each maximal consecutive run of present
    /// Boolean columns, at that run's physical ordinal.
    InlinePackedRunsMsbFirst,
    /// LSB-first packed bytes at each maximal consecutive run of present
    /// Boolean columns, at that run's physical ordinal.
    InlinePackedRunsLsbFirst,
    /// Little-endian `u16` (zero=false, one=true) at each present Boolean
    /// column's physical ordinal.
    InlineU16Le,
}

/// Physical representation selected for `NUMERIC` fields.
///
/// SQL Anywhere's legacy on-disk row decoder and the Enterprise materialized
/// table carrier use different, independently evidenced base-100 order/sign
/// conventions. A schema must choose explicitly; the default preserves the
/// legacy decoder behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NumericLayout {
    /// The DBReader-compatible forward-digit legacy representation.
    #[default]
    LegacyForward,
    /// Enterprise materialized numeric token: raw marker plus little-endian
    /// base-100 digits.
    ///
    /// The decoder retains a bounded raw token rather than assigning marker
    /// sign/scale semantics or a decimal scale, because those facts have not
    /// been proven for every Enterprise materialized `NUMERIC` field.
    EnterpriseMaterializedRaw,
}

/// Physical representation selected for domain-19 `ENUM` fields.
///
/// A catalog domain identifier alone does not prove an enum scalar layout.
/// The default therefore rejects it. Callers may opt into raw unsigned scalar
/// preservation only after independently proving the declared column width.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EnumLayout {
    /// Reject ENUM fields rather than guessing their representation.
    #[default]
    Unsupported,
    /// Preserve a proven fixed-width unsigned scalar using `ColumnDef::width`.
    FixedWidthUnsigned,
}

/// How a variable-length `0xff` overflow marker is handled.
///
/// This does not resolve an overflow value. It only permits a caller with
/// independent pointer-width evidence to retain the exact bounded pointer
/// bytes and continue decoding later columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VariableOverflowLayout {
    /// Reject overflow markers because no pointer representation is proven.
    #[default]
    Unsupported,
    /// Preserve exactly this many raw pointer bytes after the `0xff` marker.
    Pointer {
        /// Independently proven pointer width in bytes.
        width: u8,
    },
}

/// Length-prefix representation for variable character and text fields.
///
/// The catalog width is not itself sufficient to select a representation, so
/// a schema must choose explicitly. Mixed mode permits a caller to attest a
/// width-based distinction without changing the logical column order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VariableLengthLayout {
    /// One-byte length; `0xff` is the overflow sentinel.
    #[default]
    U8,
    /// Little-endian two-byte length; `0xffff` is the overflow sentinel.
    U16Le,
    /// One-byte lengths below `wide_at_or_above`, two-byte lengths at or above it.
    DeclaredWidth {
        /// Catalog width selecting the two-byte representation.
        wide_at_or_above: u16,
    },
}

/// Bit ordering and polarity for a physical row null bitmap.
///
/// This is intentionally schema-owned: nullability metadata alone does not
/// establish whether a set bit means present or null, nor bit order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NullBitmapLayout {
    /// Most-significant-bit first, with a set bit meaning the field is present.
    #[default]
    MsbPresent,
    /// Least-significant-bit first, with a set bit meaning the field is present.
    LsbPresent,
    /// Most-significant-bit first, with a set bit meaning the field is null.
    MsbNull,
    /// Least-significant-bit first, with a set bit meaning the field is null.
    LsbNull,
}

/// Which logical columns consume positions in a physical null bitmap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NullBitmapCoverage {
    /// Only catalog-nullable columns consume bitmap positions.
    #[default]
    NullableColumns,
    /// Every logical column consumes a bitmap position; bits for nonnullable
    /// columns are ignored when deciding nullness.
    AllColumns,
}

/// Bytes between the leading row length and the null bitmap.
///
/// The default keeps the legacy direct-row grammar. A caller may explicitly
/// select a one-byte carrier prefix only after proving that representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RowPrefixLayout {
    /// Null bitmap begins immediately after the leading `u16` row length.
    #[default]
    None,
    /// One opaque carrier byte precedes the null bitmap.
    OneByteCarrier,
    /// Two opaque carrier bytes precede the null bitmap.
    TwoByteCarrier,
    /// Three opaque carrier bytes precede the null bitmap.
    ThreeByteCarrier,
}

/// Schema required to decode one row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowSchema {
    /// Columns in physical row order.  Primary-key ordering, if applicable,
    /// must already have been resolved by the caller.
    pub columns: Vec<ColumnDef>,
    /// Physical Boolean storage layout.
    ///
    /// This field retains its historical name for source compatibility.  See
    /// [`BooleanTailLayout::InlineBytes`] for an inline representation.
    pub boolean_tail: BooleanTailLayout,
    /// Explicit physical encoding for `NUMERIC` columns.
    pub numeric_layout: NumericLayout,
    /// Explicit physical encoding for domain-19 `ENUM` columns.
    pub enum_layout: EnumLayout,
    /// Explicit handling for variable-value overflow markers.
    pub variable_overflow_layout: VariableOverflowLayout,
    /// Explicit length-prefix representation for variable columns.
    pub variable_length_layout: VariableLengthLayout,
    /// Explicit bit ordering and polarity for nullable columns.
    pub null_bitmap_layout: NullBitmapLayout,
    /// Which logical columns consume null-bitmap positions.
    pub null_bitmap_coverage: NullBitmapCoverage,
    /// Explicit optional carrier prefix before the null bitmap.
    pub row_prefix_layout: RowPrefixLayout,
}

impl RowSchema {
    /// Construct a schema using legacy byte-per-Boolean tail storage.
    pub fn new(columns: Vec<ColumnDef>) -> Self {
        Self {
            columns,
            boolean_tail: BooleanTailLayout::Bytes,
            numeric_layout: NumericLayout::LegacyForward,
            enum_layout: EnumLayout::Unsupported,
            variable_overflow_layout: VariableOverflowLayout::Unsupported,
            variable_length_layout: VariableLengthLayout::U8,
            null_bitmap_layout: NullBitmapLayout::MsbPresent,
            null_bitmap_coverage: NullBitmapCoverage::NullableColumns,
            row_prefix_layout: RowPrefixLayout::None,
        }
    }

    /// Number of nullable fields, and therefore null-bitmap bits.
    pub fn nullable_count(&self) -> usize {
        self.columns.iter().filter(|column| column.nullable).count()
    }

    /// Number of physical bitmap positions selected by this schema.
    pub fn null_bitmap_bit_count(&self) -> usize {
        match self.null_bitmap_coverage {
            NullBitmapCoverage::NullableColumns => self.nullable_count(),
            NullBitmapCoverage::AllColumns => self.columns.len(),
        }
    }
}

/// A lossless decimal magnitude.  `coefficient` contains decimal digits only
/// and `scale` is the number of digits to the right of the decimal point.
///
/// The referenced grammar documents the one-byte (`count == 0`) form's signed
/// bias but provides no proven sign encoding for multi-byte base-100 values.
/// Accordingly multi-byte values decode as a non-negative magnitude.  Do not
/// use a negative multi-byte amount for accounting until its sign encoding is
/// established from a controlled fixture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decimal {
    /// `true` when the value is negative.
    pub negative: bool,
    /// Canonical, non-empty decimal digits without a sign or decimal point.
    pub coefficient: String,
    /// Decimal digits after the point.
    pub scale: u32,
}

impl Decimal {
    /// Return a canonical plain-decimal rendering without exponent notation.
    pub fn to_plain_string(&self) -> String {
        let mut digits = self.coefficient.clone();
        if self.scale as usize >= digits.len() {
            let zeros = self.scale as usize + 1 - digits.len();
            digits = format!("{}{}", "0".repeat(zeros), digits);
        }
        let split = digits.len() - self.scale as usize;
        let mut out = if self.scale == 0 {
            digits
        } else {
            format!("{}.{}", &digits[..split], &digits[split..])
        };
        // `coefficient` is canonical, but a nonzero declared scale can make
        // its rendered zero take any of the forms `0.0`, `0.00`, etc.  A
        // decimal renderer must never expose a negative zero merely because
        // its scale is greater than one.
        if self.negative && self.coefficient != "0" {
            out.insert(0, '-');
        }
        out
    }
}

impl fmt::Display for Decimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_plain_string())
    }
}

/// Calendar date decoded from SQL Anywhere's minute-based date representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SaDate {
    /// Original signed minute count, retained without epoch conversion.
    pub raw_minutes: i32,
}

impl SaDate {
    /// Whole days since SQL Anywhere's observed date epoch.
    pub fn days_since_sa_epoch(self) -> i32 {
        self.raw_minutes.div_euclid(1_440)
    }

    /// Convert the date to proleptic-Gregorian `(year, month, day)`.
    pub fn ymd(self) -> (i32, u8, u8) {
        // The reference decoder computes a Delphi TDateTime day as
        // `(raw_minutes div 1440) - 109512`; because Delphi day zero is
        // 1899-12-30, raw day zero is 1600-02-29.  Hinnant's algorithm takes
        // days since 1970-01-01; this epoch is 135,081 days before it.
        let z = i64::from(self.days_since_sa_epoch()) - 135_081 + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
        let mut year = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = mp + if mp < 10 { 3 } else { -9 };
        year += if month <= 2 { 1 } else { 0 };
        (year as i32, month as u8, day as u8)
    }
}

/// SQL Anywhere datetime.  The source grammar establishes the first field as
/// minute count; the meaning/unit of `subminute_raw` is not assumed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SaDateTime {
    /// Date component obtained by floor-dividing `minutes_since_sa_epoch` by 1440.
    pub date: SaDate,
    /// Raw signed minute count from SQL Anywhere's observed date epoch.
    pub minutes_since_sa_epoch: i32,
    /// The second signed 32-bit datetime word, retained losslessly.
    pub subminute_raw: i32,
}

/// A decoded field value.  Text remains bytes because code-page selection is a
/// database-level concern, not a property safely inferable from one row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// SQL NULL.
    Null,
    /// Signed integer.
    Integer(i64),
    /// Unsigned integer.
    Unsigned(u64),
    /// Exact base-100 decimal.
    Decimal(Decimal),
    /// Bounded raw Enterprise materialized base-100 numeric token.
    EnterpriseNumeric(EnterpriseNumericToken),
    /// Raw unsigned ENUM scalar from an explicitly selected layout.
    Enum(u64),
    /// Raw bounded overflow pointer bytes, not the referenced value.
    OverflowPointer(Vec<u8>),
    /// Raw bytes from a non-overflow character/text value.
    Bytes(Vec<u8>),
    /// Date.
    Date(SaDate),
    /// Datetime.
    DateTime(SaDateTime),
    /// Boolean.
    Boolean(bool),
}

/// A bounded raw numeric token from an Enterprise materialized row.
///
/// The marker and little-endian base-100 digits are preserved without a
/// universal decimal-scale interpretation. A table-specific caller may
/// convert it only after proving the relevant domain semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnterpriseNumericToken {
    /// Raw sign/scale marker byte.
    pub marker: u8,
    /// Raw little-endian base-100 digits, excluding count and marker bytes.
    pub digits: Vec<u8>,
}

/// A fully decoded row, with values in [`RowSchema::columns`] order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedRow {
    /// Declared row length including the two-byte header.
    pub declared_size: usize,
    /// Number of bytes consumed by the decoded physical fields, including the
    /// two-byte row header and all assigned Boolean storage.
    ///
    /// This can be smaller than [`Self::declared_size`] when callers use the
    /// permissive [`decode_row`] API with a partial schema.  Consumers that
    /// have an independently complete schema should instead use
    /// [`decode_row_exact`], which rejects that condition.
    pub consumed_size: usize,
    /// Header flags, after removing [`ROW_SIZE_MASK`].
    pub flags: u16,
    /// Values in schema order.
    pub values: Vec<Value>,
}

/// One value returned by a bounded prefix decode, retaining schema provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialRowValue {
    /// Zero-based position in [`RowSchema::columns`].
    pub column_index: usize,
    /// Catalog column identifier supplied by the schema.
    pub column_id: u32,
    /// Decoded value (including `NULL`).
    pub value: Value,
}

/// A bounded prefix decode with independently decoded Boolean storage.
///
/// For tail layouts every present Boolean is available independently. For
/// inline layouts only Booleans through the selected prefix are available;
/// later bytes remain opaque with the unselected fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialDecodedRow {
    /// Declared physical row size including its two-byte header.
    pub declared_size: usize,
    /// Header flags after removing [`ROW_SIZE_MASK`].
    pub flags: u16,
    /// Inclusive one-based ordinal requested by the caller.
    pub through_ordinal: u32,
    /// Present/null decisions and decoded non-Boolean fields through the
    /// requested ordinal.
    pub prefix_values: Vec<PartialRowValue>,
    /// Boolean values decoded with their schema provenance.
    pub boolean_values: Vec<PartialRowValue>,
    /// Bytes intentionally left opaque after the selected prefix and before a
    /// tail sidecar, where one exists.
    pub opaque_middle_len: usize,
}

/// Shared validated direct-row envelope and per-column presence decisions.
///
/// The tuple is deliberately private because its components are meaningful
/// only to the row decoder's staged entry points.
type RowHeaderAndPresence<'a> = (&'a [u8], usize, u16, &'a [u8], usize, Vec<bool>);

/// A deliberately specific failure from the row decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The caller supplied fewer than two bytes.
    MissingRowHeader,
    /// Header's low-thirteen-bit size is not a complete row in the slice.
    InvalidRowSize {
        /// Size encoded in the row header after flag bits are removed.
        declared: usize,
        /// Bytes available in the caller-supplied row slice.
        available: usize,
    },
    /// A row needing overflow/reference resolution was rejected.
    UnsupportedRowFlags(u16),
    /// A fixed or variable field would read outside its declared row.
    Truncated {
        /// Zero-based schema column being decoded.
        column: usize,
        /// Bytes required for this field.
        needed: usize,
        /// Bytes remaining inside the declared row boundary.
        remaining: usize,
    },
    /// A schema requested an unsupported fixed integer width.
    InvalidIntegerWidth {
        /// Zero-based schema column being decoded.
        column: usize,
        /// Unsupported declared byte width.
        width: u16,
    },
    /// A variable field's `0xff` overflow marker needs a separate resolver.
    OverflowValue {
        /// Zero-based schema column containing the overflow marker.
        column: usize,
    },
    /// An ENUM domain was recognized but its physical scalar representation
    /// has not been independently established.
    UnsupportedEnum {
        /// Zero-based schema column containing the enum value.
        column: usize,
        /// Catalog-declared width, retained to aid a future evidence-backed
        /// implementation.
        width: u16,
    },
    /// An explicitly enabled ENUM layout did not support the catalog width.
    InvalidEnumWidth {
        /// Zero-based schema column being decoded.
        column: usize,
        /// Unsupported declared byte width.
        width: u16,
    },
    /// An overflow-pointer layout used zero bytes.
    InvalidOverflowPointerWidth {
        /// Zero-based schema column being decoded.
        column: usize,
    },
    /// Numeric digit is not a base-100 digit.
    InvalidNumericDigit {
        /// Zero-based schema column being decoded.
        column: usize,
        /// Invalid encoded digit.
        digit: u8,
    },
    /// A byte-per-Boolean layout contained a value other than the proven
    /// `0` (false) or `1` (true) representation.
    InvalidBooleanByte {
        /// Zero-based schema column containing the Boolean.
        column: usize,
        /// Raw byte that was not a Boolean representation.
        value: u8,
    },
    /// A little-endian-u16 Boolean layout contained a value other than the
    /// proven `0` (false) or `1` (true) representation.
    InvalidBooleanU16 {
        /// Zero-based schema column containing the Boolean.
        column: usize,
        /// Raw little-endian u16 that was not a Boolean representation.
        value: u16,
    },
    /// A numeric marker is outside the explicitly selected numeric dialect.
    UnsupportedNumericMarker {
        /// Zero-based schema column being decoded.
        column: usize,
        /// Raw sign/scale marker.
        marker: u8,
    },
    /// More trailing data was required by the boolean-sidecar declaration.
    TruncatedBooleanTail {
        /// Bytes required by the selected boolean-tail layout.
        needed: usize,
        /// Bytes remaining inside the declared row boundary.
        remaining: usize,
    },
    /// A complete-schema decode left bytes inside the declared row boundary.
    ///
    /// This prevents a partial schema from being mistaken for a physical row
    /// decoder when the caller needs exact field locations.
    TrailingData {
        /// Number of bytes not assigned to a schema field or boolean tail.
        remaining: usize,
    },
    /// A materialized-row carrier used continuation semantics that need a
    /// caller-owned resolver before its payload can be decoded.
    ContinuedMaterializedRowCarrier,
    /// A materialized-row carrier used flags other than the proven normal
    /// zero-flag form.
    UnsupportedMaterializedRowCarrierFlags {
        /// Raw carrier flag byte.
        flags: u8,
    },
    /// Bytes followed a materialized row carrier's declared boundary.
    TrailingMaterializedRowCarrier {
        /// Bytes outside the carrier's declared physical record.
        remaining: usize,
    },
    /// The requested one-based prefix ordinal is outside the supplied schema.
    PrefixOrdinalOutOfRange {
        /// Requested one-based ordinal.
        ordinal: u32,
        /// Number of schema columns.
        column_count: usize,
    },
    /// A decoded prefix field crossed into the independently located Boolean tail.
    PrefixOverlapsBooleanTail {
        /// Zero-based schema column that crossed the tail boundary.
        column: usize,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRowHeader => f.write_str("row is shorter than its u16 header"),
            Self::InvalidRowSize {
                declared,
                available,
            } => write!(
                f,
                "row declares {declared} bytes but only {available} are available"
            ),
            Self::UnsupportedRowFlags(flags) => write!(
                f,
                "row flags 0x{flags:04x} require overflow/reference resolution"
            ),
            Self::Truncated {
                column,
                needed,
                remaining,
            } => write!(
                f,
                "column {column} needs {needed} bytes but only {remaining} remain"
            ),
            Self::InvalidIntegerWidth { column, width } => {
                write!(f, "column {column} has unsupported integer width {width}")
            }
            Self::OverflowValue { column } => write!(
                f,
                "column {column} uses an unresolved variable-value overflow pointer"
            ),
            Self::UnsupportedEnum { column, width } => write!(
                f,
                "column {column} uses ENUM domain 19 with unproven physical width {width}"
            ),
            Self::InvalidEnumWidth { column, width } => {
                write!(f, "column {column} has unsupported ENUM width {width}")
            }
            Self::InvalidOverflowPointerWidth { column } => {
                write!(
                    f,
                    "column {column} has a zero-width overflow pointer layout"
                )
            }
            Self::InvalidNumericDigit { column, digit } => {
                write!(f, "column {column} has invalid base-100 digit {digit}")
            }
            Self::InvalidBooleanByte { column, value } => write!(
                f,
                "column {column} has invalid byte-Boolean value {value:#04x}"
            ),
            Self::InvalidBooleanU16 { column, value } => write!(
                f,
                "column {column} has invalid u16-Boolean value {value:#06x}"
            ),
            Self::UnsupportedNumericMarker { column, marker } => write!(
                f,
                "column {column} has unsupported numeric marker {marker:#04x}"
            ),
            Self::TruncatedBooleanTail { needed, remaining } => write!(
                f,
                "boolean tail needs {needed} bytes but only {remaining} remain"
            ),
            Self::TrailingData { remaining } => write!(
                f,
                "row has {remaining} unconsumed bytes after its complete schema decode"
            ),
            Self::ContinuedMaterializedRowCarrier => f.write_str(
                "materialized row carrier is continued and requires caller-owned resolution",
            ),
            Self::UnsupportedMaterializedRowCarrierFlags { flags } => write!(
                f,
                "materialized row carrier has unsupported flags {flags:#04x}",
            ),
            Self::TrailingMaterializedRowCarrier { remaining } => write!(
                f,
                "materialized row carrier has {remaining} bytes after its declared boundary"
            ),
            Self::PrefixOrdinalOutOfRange {
                ordinal,
                column_count,
            } => write!(
                f,
                "requested prefix ordinal {ordinal} is outside a {column_count}-column schema"
            ),
            Self::PrefixOverlapsBooleanTail { column } => write!(
                f,
                "prefix column {column} overlaps the independently located boolean tail"
            ),
        }
    }
}

impl std::error::Error for DecodeError {}

fn decode_boolean_byte(column: usize, value: u8) -> Result<bool, DecodeError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(DecodeError::InvalidBooleanByte { column, value }),
    }
}

fn decode_boolean_u16(column: usize, bytes: &[u8]) -> Result<bool, DecodeError> {
    let value = u16::from_le_bytes([bytes[0], bytes[1]]);
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(DecodeError::InvalidBooleanU16 { column, value }),
    }
}

fn is_inline_boolean_layout(layout: BooleanTailLayout) -> bool {
    matches!(
        layout,
        BooleanTailLayout::InlineBytes
            | BooleanTailLayout::InlinePackedRunsMsbFirst
            | BooleanTailLayout::InlinePackedRunsLsbFirst
            | BooleanTailLayout::InlineU16Le
    )
}

fn inline_boolean_run_end(schema: &RowSchema, present: &[bool], start: usize) -> usize {
    let mut end = start;
    while end < schema.columns.len()
        && schema.columns[end].column_type == ColumnType::Boolean
        && present[end]
    {
        end += 1;
    }
    end
}

fn inline_packed_boolean_bit(layout: BooleanTailLayout, bytes: &[u8], ordinal: usize) -> bool {
    let mask = match layout {
        BooleanTailLayout::InlinePackedRunsMsbFirst => 0x80 >> (ordinal % 8),
        BooleanTailLayout::InlinePackedRunsLsbFirst => 1 << (ordinal % 8),
        _ => unreachable!("layout is checked before reading an inline packed run"),
    };
    bytes[ordinal / 8] & mask != 0
}

/// Decode a self-contained physical row according to `schema`.
pub fn decode_row(input: &[u8], schema: &RowSchema) -> Result<DecodedRow, DecodeError> {
    if input.len() < 2 {
        return Err(DecodeError::MissingRowHeader);
    }
    let (row, declared_size, flags, _null_bitmap, mut cursor, present) =
        row_header_and_presence(input, schema)?;
    let mut bool_values: Vec<usize> = Vec::new();
    let mut values = vec![Value::Null; schema.columns.len()];

    for (column_index, column) in schema.columns.iter().enumerate() {
        if !present[column_index] {
            continue;
        }
        if column.column_type == ColumnType::Boolean {
            match schema.boolean_tail {
                BooleanTailLayout::InlineBytes => {
                    values[column_index] = Value::Boolean(decode_boolean_byte(
                        column_index,
                        take(row, &mut cursor, 1, column_index)?[0],
                    )?);
                }
                BooleanTailLayout::InlineU16Le => {
                    values[column_index] = Value::Boolean(decode_boolean_u16(
                        column_index,
                        take(row, &mut cursor, 2, column_index)?,
                    )?);
                }
                BooleanTailLayout::Bytes | BooleanTailLayout::PackedMsbFirst => {
                    bool_values.push(column_index);
                }
                layout @ (BooleanTailLayout::InlinePackedRunsMsbFirst
                | BooleanTailLayout::InlinePackedRunsLsbFirst) => {
                    if column_index > 0
                        && schema.columns[column_index - 1].column_type == ColumnType::Boolean
                        && present[column_index - 1]
                    {
                        continue;
                    }
                    let run_end = inline_boolean_run_end(schema, &present, column_index);
                    let bytes = take(
                        row,
                        &mut cursor,
                        (run_end - column_index).div_ceil(8),
                        column_index,
                    )?;
                    for (offset, value) in (column_index..run_end).enumerate() {
                        values[value] =
                            Value::Boolean(inline_packed_boolean_bit(layout, bytes, offset));
                    }
                }
            }
            continue;
        }
        values[column_index] = decode_non_boolean(row, &mut cursor, column_index, column, schema)?;
    }

    let remaining = row.len().saturating_sub(cursor);
    let bool_count = bool_values.len();
    let required_tail = match schema.boolean_tail {
        BooleanTailLayout::Bytes => bool_count,
        BooleanTailLayout::PackedMsbFirst => bool_count.div_ceil(8),
        BooleanTailLayout::InlineBytes
        | BooleanTailLayout::InlinePackedRunsMsbFirst
        | BooleanTailLayout::InlinePackedRunsLsbFirst
        | BooleanTailLayout::InlineU16Le => 0,
    };
    if remaining < required_tail {
        return Err(DecodeError::TruncatedBooleanTail {
            needed: required_tail,
            remaining,
        });
    }
    let tail = &row[cursor..cursor + required_tail];
    for (ordinal, column_index) in bool_values.into_iter().enumerate() {
        let value = match schema.boolean_tail {
            BooleanTailLayout::Bytes => decode_boolean_byte(column_index, tail[ordinal])?,
            BooleanTailLayout::PackedMsbFirst => tail[ordinal / 8] & (0x80 >> (ordinal % 8)) != 0,
            BooleanTailLayout::InlineBytes
            | BooleanTailLayout::InlinePackedRunsMsbFirst
            | BooleanTailLayout::InlinePackedRunsLsbFirst
            | BooleanTailLayout::InlineU16Le => {
                unreachable!("inline booleans have no tail")
            }
        };
        values[column_index] = Value::Boolean(value);
    }

    Ok(DecodedRow {
        declared_size,
        consumed_size: cursor + required_tail,
        flags,
        values,
    })
}

fn row_header_and_presence<'a>(
    input: &'a [u8],
    schema: &RowSchema,
) -> Result<RowHeaderAndPresence<'a>, DecodeError> {
    if input.len() < 2 {
        return Err(DecodeError::MissingRowHeader);
    }
    let raw_size = u16::from_le_bytes([input[0], input[1]]);
    let declared_size = usize::from(raw_size & ROW_SIZE_MASK);
    if declared_size < 2 || declared_size > input.len() {
        return Err(DecodeError::InvalidRowSize {
            declared: declared_size,
            available: input.len(),
        });
    }
    let flags = raw_size & !ROW_SIZE_MASK;
    if flags != 0 {
        return Err(DecodeError::UnsupportedRowFlags(flags));
    }
    let row = &input[..declared_size];
    let prefix_len = match schema.row_prefix_layout {
        RowPrefixLayout::None => 0,
        RowPrefixLayout::OneByteCarrier => 1,
        RowPrefixLayout::TwoByteCarrier => 2,
        RowPrefixLayout::ThreeByteCarrier => 3,
    };
    let null_bytes = schema.null_bitmap_bit_count().div_ceil(8);
    if row.len() < 2 + prefix_len + null_bytes {
        return Err(DecodeError::Truncated {
            column: 0,
            needed: prefix_len + null_bytes,
            remaining: row.len().saturating_sub(2),
        });
    }
    let null_bitmap = &row[2 + prefix_len..2 + prefix_len + null_bytes];
    let mut nullable_index = 0usize;
    let mut present = Vec::with_capacity(schema.columns.len());
    for (column_index, column) in schema.columns.iter().enumerate() {
        let bitmap_index = match schema.null_bitmap_coverage {
            NullBitmapCoverage::NullableColumns => {
                let index = nullable_index;
                if column.nullable {
                    nullable_index += 1;
                }
                index
            }
            NullBitmapCoverage::AllColumns => column_index,
        };
        let is_null = if column.nullable {
            let byte = null_bitmap[bitmap_index / 8];
            let bit_index = bitmap_index % 8;
            let mask = match schema.null_bitmap_layout {
                NullBitmapLayout::MsbPresent | NullBitmapLayout::MsbNull => 0x80 >> bit_index,
                NullBitmapLayout::LsbPresent | NullBitmapLayout::LsbNull => 1 << bit_index,
            };
            let set = byte & mask != 0;
            let field_present = match schema.null_bitmap_layout {
                NullBitmapLayout::MsbPresent | NullBitmapLayout::LsbPresent => set,
                NullBitmapLayout::MsbNull | NullBitmapLayout::LsbNull => !set,
            };
            !field_present
        } else {
            false
        };
        present.push(!is_null);
    }
    Ok((
        row,
        declared_size,
        flags,
        null_bitmap,
        2 + prefix_len + null_bytes,
        present,
    ))
}

/// Decode one self-contained physical row and require its schema to consume
/// the complete declared row boundary.
///
/// This is the appropriate entry point only after a caller has independently
/// established that its input is a direct physical-row grammar (leading `u16`
/// size followed by this decoder's null map and field framing). Materialized
/// table carriers must use [`decode_materialized_row_record_exact`] when they
/// have the separately proven `[u16][flag][payload]` envelope.
///
/// The function deliberately does not infer that an arbitrary row segment is
/// a self-contained SQL Anywhere row.  Callers still need table-specific
/// evidence for that carrier relationship and a complete schema.
pub fn decode_row_exact(input: &[u8], schema: &RowSchema) -> Result<DecodedRow, DecodeError> {
    let decoded = decode_row(input, schema)?;
    let remaining = decoded.declared_size - decoded.consumed_size;
    if remaining != 0 {
        return Err(DecodeError::TrailingData { remaining });
    }
    Ok(decoded)
}

/// Decode fields through one schema ordinal while retaining later bytes as
/// opaque.
///
/// This deliberately does not establish a complete row grammar. It is useful
/// only when the caller has separately proven the leading field sequence and
/// needs to avoid treating later variable fields as known. The full schema is
/// still required to locate the null bitmap and, for tail layouts, Boolean
/// sidecar safely. Inline Boolean bytes are consumed and returned only through
/// `through_ordinal`; later inline fields remain opaque with later columns.
pub fn decode_row_prefix_and_boolean_tail(
    input: &[u8],
    schema: &RowSchema,
    through_ordinal: u32,
) -> Result<PartialDecodedRow, DecodeError> {
    let through = usize::try_from(through_ordinal).unwrap_or(usize::MAX);
    if through == 0 || through > schema.columns.len() {
        return Err(DecodeError::PrefixOrdinalOutOfRange {
            ordinal: through_ordinal,
            column_count: schema.columns.len(),
        });
    }
    let (row, declared_size, flags, null_bitmap, cursor_start, present) =
        row_header_and_presence(input, schema)?;
    let boolean_columns: Vec<_> = schema
        .columns
        .iter()
        .enumerate()
        .filter(|(index, column)| column.column_type == ColumnType::Boolean && present[*index])
        .collect();
    let required_tail = match schema.boolean_tail {
        BooleanTailLayout::Bytes => boolean_columns.len(),
        BooleanTailLayout::PackedMsbFirst => boolean_columns.len().div_ceil(8),
        BooleanTailLayout::InlineBytes
        | BooleanTailLayout::InlinePackedRunsMsbFirst
        | BooleanTailLayout::InlinePackedRunsLsbFirst
        | BooleanTailLayout::InlineU16Le => 0,
    };
    // The tail is relative to the physical row body, but the prefix starts
    // after its header and null map.  Checking only `row.len()` would allow a
    // malformed header to place the tail before the prefix, then underflow
    // while computing the opaque middle length below.
    let remaining_after_prefix =
        row.len()
            .checked_sub(cursor_start)
            .ok_or(DecodeError::TruncatedBooleanTail {
                needed: required_tail,
                remaining: 0,
            })?;
    if required_tail > remaining_after_prefix {
        return Err(DecodeError::TruncatedBooleanTail {
            needed: required_tail,
            remaining: remaining_after_prefix,
        });
    }
    let tail_start = row.len() - required_tail;
    let mut cursor = cursor_start;
    let mut prefix_values = Vec::new();
    let mut boolean_values = Vec::new();
    for (index, column) in schema.columns.iter().enumerate().take(through) {
        if column.column_type == ColumnType::Boolean {
            if present[index] {
                match schema.boolean_tail {
                    BooleanTailLayout::InlineBytes => {
                        boolean_values.push(PartialRowValue {
                            column_index: index,
                            column_id: column.id,
                            value: Value::Boolean(decode_boolean_byte(
                                index,
                                take(row, &mut cursor, 1, index)?[0],
                            )?),
                        });
                    }
                    BooleanTailLayout::InlineU16Le => {
                        boolean_values.push(PartialRowValue {
                            column_index: index,
                            column_id: column.id,
                            value: Value::Boolean(decode_boolean_u16(
                                index,
                                take(row, &mut cursor, 2, index)?,
                            )?),
                        });
                    }
                    layout @ (BooleanTailLayout::InlinePackedRunsMsbFirst
                    | BooleanTailLayout::InlinePackedRunsLsbFirst) => {
                        if index > 0
                            && schema.columns[index - 1].column_type == ColumnType::Boolean
                            && present[index - 1]
                        {
                            continue;
                        }
                        let run_end = inline_boolean_run_end(schema, &present, index);
                        let bytes = take(row, &mut cursor, (run_end - index).div_ceil(8), index)?;
                        for (offset, boolean_index) in (index..run_end).enumerate() {
                            if boolean_index >= through {
                                break;
                            }
                            let boolean_column = &schema.columns[boolean_index];
                            boolean_values.push(PartialRowValue {
                                column_index: boolean_index,
                                column_id: boolean_column.id,
                                value: Value::Boolean(inline_packed_boolean_bit(
                                    layout, bytes, offset,
                                )),
                            });
                        }
                    }
                    BooleanTailLayout::Bytes | BooleanTailLayout::PackedMsbFirst => {}
                }
            }
            continue;
        }
        let value = if present[index] {
            let value = decode_non_boolean(row, &mut cursor, index, column, schema)?;
            if !is_inline_boolean_layout(schema.boolean_tail) && cursor > tail_start {
                return Err(DecodeError::PrefixOverlapsBooleanTail { column: index });
            }
            value
        } else {
            Value::Null
        };
        prefix_values.push(PartialRowValue {
            column_index: index,
            column_id: column.id,
            value,
        });
    }
    if !is_inline_boolean_layout(schema.boolean_tail) {
        let tail = &row[tail_start..];
        for (ordinal, (index, column)) in boolean_columns.into_iter().enumerate() {
            let value = match schema.boolean_tail {
                BooleanTailLayout::Bytes => decode_boolean_byte(index, tail[ordinal])?,
                BooleanTailLayout::PackedMsbFirst => {
                    tail[ordinal / 8] & (0x80 >> (ordinal % 8)) != 0
                }
                BooleanTailLayout::InlineBytes
                | BooleanTailLayout::InlinePackedRunsMsbFirst
                | BooleanTailLayout::InlinePackedRunsLsbFirst
                | BooleanTailLayout::InlineU16Le => {
                    unreachable!("inline booleans have no tail")
                }
            };
            boolean_values.push(PartialRowValue {
                column_index: index,
                column_id: column.id,
                value: Value::Boolean(value),
            });
        }
    }
    let _ = null_bitmap;
    Ok(PartialDecodedRow {
        declared_size,
        flags,
        through_ordinal,
        prefix_values,
        boolean_values,
        opaque_middle_len: tail_start.checked_sub(cursor).ok_or(
            DecodeError::PrefixOverlapsBooleanTail {
                column: through - 1,
            },
        )?,
    })
}

/// Decode a normal, non-continued materialized row carrier exactly.
///
/// A materialized application record may use the bounded three-byte SA17
/// carrier `[u16 total_length][flag]`, followed by the physical row payload.
/// This function validates that carrier with [`crate::RowSegment`], requires
/// its normal zero flag and no continuation, then reconstructs the legacy row
/// envelope `[u16 payload_length_plus_two][payload]` for [`decode_row_exact`].
/// It never resolves a continuation target or interprets nonzero flags.
pub fn decode_materialized_row_record_exact(
    input: &[u8],
    schema: &RowSchema,
) -> Result<DecodedRow, DecodeError> {
    let segment = crate::RowSegment::parse(input).map_err(|error| match error {
        crate::RowSegmentError::MissingHeader { .. }
        | crate::RowSegmentError::InvalidLength { .. } => DecodeError::MissingRowHeader,
    })?;
    if segment.declared_len() != input.len() {
        return Err(DecodeError::TrailingMaterializedRowCarrier {
            remaining: input.len() - segment.declared_len(),
        });
    }
    if segment.is_continued() {
        return Err(DecodeError::ContinuedMaterializedRowCarrier);
    }
    if segment.flags() != 0 {
        return Err(DecodeError::UnsupportedMaterializedRowCarrierFlags {
            flags: segment.flags(),
        });
    }
    let size = segment
        .payload()
        .len()
        .checked_add(2)
        .ok_or(DecodeError::InvalidRowSize {
            declared: usize::MAX,
            available: input.len(),
        })?;
    let size = u16::try_from(size).map_err(|_| DecodeError::InvalidRowSize {
        declared: size,
        available: input.len(),
    })?;
    let mut row = Vec::with_capacity(usize::from(size));
    row.extend_from_slice(&size.to_le_bytes());
    row.extend_from_slice(segment.payload());
    decode_row_exact(&row, schema)
}

fn decode_non_boolean(
    row: &[u8],
    cursor: &mut usize,
    column_index: usize,
    column: &ColumnDef,
    schema: &RowSchema,
) -> Result<Value, DecodeError> {
    if column.column_type.is_variable() {
        let (length, overflow) = match schema.variable_length_layout {
            VariableLengthLayout::U8 => {
                let length = usize::from(take(row, cursor, 1, column_index)?[0]);
                (length, length == usize::from(u8::MAX))
            }
            VariableLengthLayout::U16Le => {
                let bytes = take(row, cursor, 2, column_index)?;
                let length = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
                (length, length == usize::from(u16::MAX))
            }
            VariableLengthLayout::DeclaredWidth { wide_at_or_above } => {
                if column.width >= wide_at_or_above {
                    let bytes = take(row, cursor, 2, column_index)?;
                    let length = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
                    (length, length == usize::from(u16::MAX))
                } else {
                    let length = usize::from(take(row, cursor, 1, column_index)?[0]);
                    (length, length == usize::from(u8::MAX))
                }
            }
        };
        if overflow {
            return match schema.variable_overflow_layout {
                VariableOverflowLayout::Unsupported => Err(DecodeError::OverflowValue {
                    column: column_index,
                }),
                VariableOverflowLayout::Pointer { width: 0 } => {
                    Err(DecodeError::InvalidOverflowPointerWidth {
                        column: column_index,
                    })
                }
                VariableOverflowLayout::Pointer { width } => Ok(Value::OverflowPointer(
                    take(row, cursor, usize::from(width), column_index)?.to_vec(),
                )),
            };
        }
        return Ok(Value::Bytes(
            take(row, cursor, length, column_index)?.to_vec(),
        ));
    }
    match column.column_type {
        ColumnType::SmallInt | ColumnType::Integer | ColumnType::Integer2 => Ok(Value::Integer(
            read_signed(row, cursor, column_index, column.width)?,
        )),
        ColumnType::UInt64 | ColumnType::UInt32 => Ok(Value::Unsigned(read_unsigned(
            row,
            cursor,
            column_index,
            column.width,
        )?)),
        ColumnType::Int64 => {
            if column.width != 8 {
                return Err(DecodeError::InvalidIntegerWidth {
                    column: column_index,
                    width: column.width,
                });
            }
            Ok(Value::Integer(i64::from_le_bytes(
                take(row, cursor, 8, column_index)?
                    .try_into()
                    .expect("exact slice"),
            )))
        }
        ColumnType::Numeric => {
            decode_numeric_value(row, cursor, column_index, schema.numeric_layout)
        }
        ColumnType::Enum => {
            decode_enum(row, cursor, column_index, column.width, schema.enum_layout)
        }
        ColumnType::Date => {
            let minutes = i32::from_le_bytes(
                take(row, cursor, 4, column_index)?
                    .try_into()
                    .expect("exact slice"),
            );
            Ok(Value::Date(SaDate {
                raw_minutes: minutes,
            }))
        }
        ColumnType::DateTime => {
            let minutes = i32::from_le_bytes(
                take(row, cursor, 4, column_index)?
                    .try_into()
                    .expect("exact slice"),
            );
            let subminute_raw = i32::from_le_bytes(
                take(row, cursor, 4, column_index)?
                    .try_into()
                    .expect("exact slice"),
            );
            Ok(Value::DateTime(SaDateTime {
                date: SaDate {
                    raw_minutes: minutes,
                },
                minutes_since_sa_epoch: minutes,
                subminute_raw,
            }))
        }
        ColumnType::Boolean => unreachable!("boolean is decoded from the tail"),
        ColumnType::Char | ColumnType::Char2 | ColumnType::Text | ColumnType::Text2 => {
            unreachable!("variable type handled above")
        }
    }
}

fn take<'a>(
    row: &'a [u8],
    cursor: &mut usize,
    count: usize,
    column: usize,
) -> Result<&'a [u8], DecodeError> {
    let remaining = row.len().saturating_sub(*cursor);
    if remaining < count {
        return Err(DecodeError::Truncated {
            column,
            needed: count,
            remaining,
        });
    }
    let result = &row[*cursor..*cursor + count];
    *cursor += count;
    Ok(result)
}

fn read_signed(
    row: &[u8],
    cursor: &mut usize,
    column: usize,
    width: u16,
) -> Result<i64, DecodeError> {
    let value = match width {
        1 => i64::from(i8::from_le_bytes(
            take(row, cursor, 1, column)?
                .try_into()
                .expect("exact slice"),
        )),
        2 => i64::from(i16::from_le_bytes(
            take(row, cursor, 2, column)?
                .try_into()
                .expect("exact slice"),
        )),
        4 => i64::from(i32::from_le_bytes(
            take(row, cursor, 4, column)?
                .try_into()
                .expect("exact slice"),
        )),
        8 => i64::from_le_bytes(
            take(row, cursor, 8, column)?
                .try_into()
                .expect("exact slice"),
        ),
        _ => return Err(DecodeError::InvalidIntegerWidth { column, width }),
    };
    Ok(value)
}

fn read_unsigned(
    row: &[u8],
    cursor: &mut usize,
    column: usize,
    width: u16,
) -> Result<u64, DecodeError> {
    let value = match width {
        1 => u64::from(take(row, cursor, 1, column)?[0]),
        2 => u64::from(u16::from_le_bytes(
            take(row, cursor, 2, column)?
                .try_into()
                .expect("exact slice"),
        )),
        4 => u64::from(u32::from_le_bytes(
            take(row, cursor, 4, column)?
                .try_into()
                .expect("exact slice"),
        )),
        8 => u64::from_le_bytes(
            take(row, cursor, 8, column)?
                .try_into()
                .expect("exact slice"),
        ),
        _ => return Err(DecodeError::InvalidIntegerWidth { column, width }),
    };
    Ok(value)
}

fn decode_enum(
    row: &[u8],
    cursor: &mut usize,
    column: usize,
    width: u16,
    layout: EnumLayout,
) -> Result<Value, DecodeError> {
    if layout == EnumLayout::Unsupported {
        return Err(DecodeError::UnsupportedEnum { column, width });
    }
    let value = match width {
        1 | 2 | 4 | 8 => read_unsigned(row, cursor, column, width)?,
        _ => return Err(DecodeError::InvalidEnumWidth { column, width }),
    };
    Ok(Value::Enum(value))
}

fn decode_numeric_value(
    row: &[u8],
    cursor: &mut usize,
    column: usize,
    layout: NumericLayout,
) -> Result<Value, DecodeError> {
    match layout {
        NumericLayout::LegacyForward => {
            read_numeric_legacy(row, cursor, column).map(Value::Decimal)
        }
        NumericLayout::EnterpriseMaterializedRaw => {
            read_numeric_enterprise_materialized(row, cursor, column)
        }
    }
}

fn read_numeric_legacy(
    row: &[u8],
    cursor: &mut usize,
    column: usize,
) -> Result<Decimal, DecodeError> {
    let count = usize::from(take(row, cursor, 1, column)?[0]);
    let exponent = take(row, cursor, 1, column)?[0];
    if count == 0 {
        // The one-byte short form is biased around 0x80.  The reference
        // reader used `>` here; `>=` is necessary for 0x80 to mean zero.
        let value = i16::from(0x80_u8) - i16::from(exponent);
        return Ok(Decimal {
            negative: value < 0,
            coefficient: value.unsigned_abs().to_string(),
            scale: 0,
        });
    }
    let digits = take(row, cursor, count, column)?;
    let mut coefficient = String::with_capacity(count * 2);
    for &digit in digits {
        if digit > 99 {
            return Err(DecodeError::InvalidNumericDigit { column, digit });
        }
        use std::fmt::Write as _;
        write!(&mut coefficient, "{digit:02}").expect("write to String cannot fail");
    }
    let canonical = coefficient.trim_start_matches('0');
    let mut coefficient = if canonical.is_empty() {
        "0".to_owned()
    } else {
        canonical.to_owned()
    };
    let shift = i16::from(exponent) - i16::from(0xc0_u8);
    if shift >= 0 {
        coefficient.push_str(&"0".repeat(usize::try_from(shift).expect("nonnegative") * 2));
        Ok(Decimal {
            negative: false,
            coefficient,
            scale: 0,
        })
    } else {
        Ok(Decimal {
            negative: false,
            coefficient,
            scale: u32::try_from(-shift).expect("positive") * 2,
        })
    }
}

fn read_numeric_enterprise_materialized(
    row: &[u8],
    cursor: &mut usize,
    column: usize,
) -> Result<Value, DecodeError> {
    let count = usize::from(take(row, cursor, 1, column)?[0]);
    let marker = take(row, cursor, 1, column)?[0];
    if count == 0 {
        return Ok(Value::EnterpriseNumeric(EnterpriseNumericToken {
            marker,
            digits: Vec::new(),
        }));
    }
    let digits = take(row, cursor, count, column)?;
    if let Some(&digit) = digits.iter().find(|digit| **digit > 99) {
        return Err(DecodeError::InvalidNumericDigit { column, digit });
    }
    Ok(Value::EnterpriseNumeric(EnterpriseNumericToken {
        marker,
        digits: digits.to_vec(),
    }))
}

/// Return DBReader's legacy compatibility `SYSTABLE` schema.
///
/// This schema is retained solely for compatibility with the referenced
/// legacy reader.  It is **not** evidence for the physical `ISYSTAB` layout
/// in modern SA17 or QuickBooks Desktop Enterprise 24 files.  Do not apply it
/// to an Enterprise 24 catalog until that physical row layout is independently
/// validated.
pub fn legacy_systable_schema() -> RowSchema {
    use ColumnType::*;
    RowSchema::new(vec![
        ColumnDef::new(1, "table_id", Integer, 4, false),
        ColumnDef::new(2, "file_id", SmallInt, 2, false),
        ColumnDef::new(3, "count", Int64, 8, false),
        ColumnDef::new(4, "first_page", Integer, 4, false),
        ColumnDef::new(5, "last_page", Integer, 4, false),
        ColumnDef::new(6, "primary_root", Integer, 4, false),
        ColumnDef::new(7, "creator", Integer, 4, false),
        ColumnDef::new(8, "first_ext_page", Integer, 4, false),
        ColumnDef::new(9, "last_ext_page", Integer, 4, false),
        ColumnDef::new(10, "table_page_count", Integer, 4, false),
        ColumnDef::new(11, "ext_page_count", Integer, 4, false),
        ColumnDef::new(12, "table_name", Char, 128, false),
        ColumnDef::new(13, "table_type", Text, 0, false),
        ColumnDef::new(14, "view_def", Text, 0, true),
        ColumnDef::new(15, "remarks", Text, 0, true),
        ColumnDef::new(16, "replicate", Integer, 1, false),
        ColumnDef::new(17, "existing_obj", Integer, 1, true),
        ColumnDef::new(18, "remote_location", Text, 0, true),
        ColumnDef::new(19, "remote_objtype", Integer, 1, true),
        ColumnDef::new(20, "srvid", Integer, 4, true),
        ColumnDef::new(21, "server_type", Integer, 4, false),
        ColumnDef::new(22, "primary_hash_limit", SmallInt, 2, false),
        ColumnDef::new(23, "page_map_start", Integer, 4, false),
        ColumnDef::new(24, "source", Text, 0, true),
    ])
}

/// Return DBReader's legacy compatibility `SYSCOLUMN` schema.
///
/// This schema is retained solely for compatibility with the referenced
/// legacy reader.  It is **not** evidence for the physical `ISYSTABCOL`
/// layout in modern SA17 or QuickBooks Desktop Enterprise 24 files.  Do not
/// apply it to an Enterprise 24 catalog until that physical row layout is
/// independently validated.
pub fn legacy_syscolumn_schema() -> RowSchema {
    use ColumnType::*;
    RowSchema::new(vec![
        ColumnDef::new(1, "table_id", Integer, 4, false),
        ColumnDef::new(2, "column_id", Integer, 4, false),
        ColumnDef::new(3, "pkey", Char, 1, false),
        ColumnDef::new(4, "domain_id", SmallInt, 2, false),
        ColumnDef::new(5, "nulls", Char, 1, false),
        ColumnDef::new(6, "width", SmallInt, 2, false),
        ColumnDef::new(7, "scale", SmallInt, 2, false),
        ColumnDef::new(8, "unused", Integer, 4, false),
        ColumnDef::new(9, "max_identity", Int64, 8, false),
        ColumnDef::new(10, "column_name", Char, 128, false),
        ColumnDef::new(11, "remarks", Text, 0, true),
        ColumnDef::new(12, "default", Text, 0, true),
        ColumnDef::new(13, "unused2", Text, 0, true),
        ColumnDef::new(14, "user_type", SmallInt, 2, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(payload.len() + 2);
        out.extend_from_slice(&u16::try_from(payload.len() + 2).unwrap().to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn decodes_nullable_msb_first_and_boolean_tail() {
        let schema = RowSchema::new(vec![
            ColumnDef::new(1, "required", ColumnType::Integer, 4, false),
            ColumnDef::new(2, "missing", ColumnType::Char, 0, true),
            ColumnDef::new(3, "present", ColumnType::Char, 0, true),
            ColumnDef::new(4, "flag", ColumnType::Boolean, 0, false),
        ]);
        // 0b0100_0000: nullable #0 is NULL, nullable #1 is present.
        let bytes = row(&[0x40, 42, 0, 0, 0, 2, b'o', b'k', 1]);
        let decoded = decode_row(&bytes, &schema).unwrap();
        assert_eq!(
            decoded.values,
            vec![
                Value::Integer(42),
                Value::Null,
                Value::Bytes(b"ok".to_vec()),
                Value::Boolean(true)
            ]
        );
    }

    #[test]
    fn exact_decode_uses_complete_row_not_segment_payload() {
        let schema = RowSchema::new(vec![
            ColumnDef::new(1, "target", ColumnType::Integer, 4, false),
            ColumnDef::new(2, "memo", ColumnType::Char2, 0, true),
            ColumnDef::new(3, "amount", ColumnType::Numeric, 20, true),
        ]);
        // The first byte after the u16 is the null map: both nullable
        // columns are present. This models a bounded materialized row rather
        // than a RowSegment payload (which would omit that byte).
        let mut bytes = row(&[0b1100_0000, 7, 0, 0, 0, 2, b'o', b'k', 0, 0x80]);
        let decoded = decode_row_exact(&bytes, &schema).unwrap();
        assert_eq!(decoded.declared_size, decoded.consumed_size);
        assert_eq!(
            decoded.values,
            vec![
                Value::Integer(7),
                Value::Bytes(b"ok".to_vec()),
                Value::Decimal(Decimal {
                    negative: false,
                    coefficient: "0".into(),
                    scale: 0,
                }),
            ]
        );

        // A valid physical row boundary alone does not make trailing bytes
        // part of a complete schema decode.
        bytes.push(0);
        let len = u16::try_from(bytes.len()).unwrap();
        bytes[..2].copy_from_slice(&len.to_le_bytes());
        assert_eq!(
            decode_row_exact(&bytes, &schema),
            Err(DecodeError::TrailingData { remaining: 1 })
        );
    }

    #[test]
    fn materialized_carrier_removes_its_flag_before_exact_row_decode() {
        let schema = RowSchema::new(vec![
            ColumnDef::new(1, "id", ColumnType::Integer, 4, false),
            ColumnDef::new(2, "note", ColumnType::Char2, 0, true),
        ]);
        // Carrier: len=11, flag=0; payload starts with a one-byte null map.
        // The reconstructed direct row is [u16 len=10][0x80][id][len][text].
        let input = [11, 0, 0, 0x80, 7, 0, 0, 0, 2, b'o', b'k'];
        assert_eq!(
            decode_materialized_row_record_exact(&input, &schema)
                .unwrap()
                .values,
            vec![Value::Integer(7), Value::Bytes(b"ok".to_vec())]
        );
        let continued = [9, 0, crate::ROW_SEGMENT_CONTINUED, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            decode_materialized_row_record_exact(&continued, &schema),
            Err(DecodeError::ContinuedMaterializedRowCarrier)
        );
        let flagged = [4, 0, 0x40, 0];
        assert_eq!(
            decode_materialized_row_record_exact(&flagged, &schema),
            Err(DecodeError::UnsupportedMaterializedRowCarrierFlags { flags: 0x40 })
        );
        let mut trailing = input.to_vec();
        trailing.push(0);
        assert_eq!(
            decode_materialized_row_record_exact(&trailing, &schema),
            Err(DecodeError::TrailingMaterializedRowCarrier { remaining: 1 })
        );
    }

    #[test]
    fn partial_decode_rejects_bytes_boolean_tail_truncated_after_null_bitmap() {
        let columns = (0..9)
            .map(|index| ColumnDef::new(index, "flag", ColumnType::Boolean, 0, true))
            .collect();
        let schema = RowSchema::new(columns);
        // Two null-map bytes establish all nine values as present, but only
        // one byte remains for the two-byte Boolean tail.
        assert_eq!(
            decode_row_prefix_and_boolean_tail(&row(&[0xff, 0x80, 1]), &schema, 1),
            Err(DecodeError::TruncatedBooleanTail {
                needed: 9,
                remaining: 1,
            })
        );
    }

    #[test]
    fn partial_decode_rejects_packed_boolean_tail_truncated_after_null_bitmap() {
        let columns = (0..9)
            .map(|index| ColumnDef::new(index, "flag", ColumnType::Boolean, 0, true))
            .collect();
        let mut schema = RowSchema::new(columns);
        schema.boolean_tail = BooleanTailLayout::PackedMsbFirst;
        assert_eq!(
            decode_row_prefix_and_boolean_tail(&row(&[0xff, 0x80, 0x80]), &schema, 1),
            Err(DecodeError::TruncatedBooleanTail {
                needed: 2,
                remaining: 1,
            })
        );
    }

    #[test]
    fn null_bitmap_layout_and_direct_prefix_are_explicit() {
        let mut schema = RowSchema::new(vec![
            ColumnDef::new(1, "first", ColumnType::Char2, 0, true),
            ColumnDef::new(2, "second", ColumnType::Char2, 0, true),
        ]);
        schema.null_bitmap_layout = NullBitmapLayout::LsbNull;
        schema.row_prefix_layout = RowPrefixLayout::OneByteCarrier;
        // Prefix 0xa5; LSB-null map 0b01 means first is null, second present.
        assert_eq!(
            decode_row_exact(&row(&[0xa5, 0b0000_0001, 1, b'x']), &schema)
                .unwrap()
                .values,
            vec![Value::Null, Value::Bytes(b"x".to_vec())]
        );

        let mut all_columns = RowSchema::new(vec![
            ColumnDef::new(1, "required", ColumnType::Integer, 1, false),
            ColumnDef::new(2, "optional", ColumnType::Char2, 0, true),
        ]);
        all_columns.null_bitmap_coverage = NullBitmapCoverage::AllColumns;
        // Bit 0 describes the required column and is ignored; bit 1 marks
        // the optional column present.
        assert_eq!(
            decode_row_exact(&row(&[0b0100_0000, 7, 1, b'x']), &all_columns)
                .unwrap()
                .values,
            vec![Value::Integer(7), Value::Bytes(b"x".to_vec())]
        );
    }

    #[test]
    fn enterprise_materialized_numeric_is_signed_little_endian_base_100() {
        let mut schema = RowSchema::new(vec![ColumnDef::new(
            1,
            "amount",
            ColumnType::Numeric,
            20,
            false,
        )]);
        schema.numeric_layout = NumericLayout::EnterpriseMaterializedRaw;
        let positive = decode_row_exact(&row(&[3, 0xbf, 5, 0, 10]), &schema).unwrap();
        let negative = decode_row_exact(&row(&[2, 0x3f, 41, 37]), &schema).unwrap();
        assert_eq!(
            positive.values,
            vec![Value::EnterpriseNumeric(EnterpriseNumericToken {
                marker: 0xbf,
                digits: vec![5, 0, 10],
            })]
        );
        assert_eq!(
            decode_row_exact(&row(&[0, 0x80]), &schema).unwrap().values,
            vec![Value::EnterpriseNumeric(EnterpriseNumericToken {
                marker: 0x80,
                digits: vec![],
            })]
        );
        assert_eq!(
            negative.values,
            vec![Value::EnterpriseNumeric(EnterpriseNumericToken {
                marker: 0x3f,
                digits: vec![41, 37],
            })]
        );
    }

    #[test]
    fn decodes_packed_boolean_tail_after_variable_values() {
        let mut schema = RowSchema::new(vec![
            ColumnDef::new(1, "name", ColumnType::Text, 0, false),
            ColumnDef::new(2, "a", ColumnType::Boolean, 0, false),
            ColumnDef::new(3, "b", ColumnType::Boolean, 0, false),
        ]);
        schema.boolean_tail = BooleanTailLayout::PackedMsbFirst;
        let decoded = decode_row(&row(&[1, b'x', 0b1000_0000]), &schema).unwrap();
        assert_eq!(
            decoded.values,
            vec![
                Value::Bytes(b"x".to_vec()),
                Value::Boolean(true),
                Value::Boolean(false)
            ]
        );
    }

    #[test]
    fn decodes_inline_boolean_at_its_physical_ordinal() {
        let mut schema = RowSchema::new(vec![
            ColumnDef::new(1, "first", ColumnType::Integer, 1, false),
            ColumnDef::new(2, "flag", ColumnType::Boolean, 0, false),
            ColumnDef::new(3, "second", ColumnType::Integer, 2, false),
        ]);
        schema.boolean_tail = BooleanTailLayout::InlineBytes;
        assert_eq!(
            decode_row_exact(&row(&[7, 1, 0x34, 0x12]), &schema)
                .unwrap()
                .values,
            vec![
                Value::Integer(7),
                Value::Boolean(true),
                Value::Integer(0x1234),
            ]
        );
    }

    #[test]
    fn partial_decode_returns_inline_boolean_with_schema_provenance() {
        let mut schema = RowSchema::new(vec![
            ColumnDef::new(11, "first", ColumnType::Integer, 1, false),
            ColumnDef::new(22, "flag", ColumnType::Boolean, 0, false),
            ColumnDef::new(33, "second", ColumnType::Integer, 2, false),
        ]);
        schema.boolean_tail = BooleanTailLayout::InlineBytes;
        let decoded =
            decode_row_prefix_and_boolean_tail(&row(&[7, 1, 0x34, 0x12]), &schema, 2).unwrap();
        assert_eq!(
            decoded.prefix_values,
            vec![PartialRowValue {
                column_index: 0,
                column_id: 11,
                value: Value::Integer(7),
            }]
        );
        assert_eq!(
            decoded.boolean_values,
            vec![PartialRowValue {
                column_index: 1,
                column_id: 22,
                value: Value::Boolean(true),
            }]
        );
        assert_eq!(decoded.opaque_middle_len, 2);
    }

    #[test]
    fn decodes_inline_u16_boolean_at_its_physical_ordinal() {
        let mut schema = RowSchema::new(vec![
            ColumnDef::new(11, "first", ColumnType::Integer, 1, false),
            ColumnDef::new(22, "flag", ColumnType::Boolean, 0, false),
            ColumnDef::new(33, "second", ColumnType::Integer, 1, false),
        ]);
        schema.boolean_tail = BooleanTailLayout::InlineU16Le;
        let payload = [7, 1, 0, 9];
        assert_eq!(
            decode_row_exact(&row(&payload), &schema).unwrap().values,
            vec![Value::Integer(7), Value::Boolean(true), Value::Integer(9)]
        );
        let partial = decode_row_prefix_and_boolean_tail(&row(&payload), &schema, 2).unwrap();
        assert_eq!(
            partial.boolean_values,
            vec![PartialRowValue {
                column_index: 1,
                column_id: 22,
                value: Value::Boolean(true),
            }]
        );
        assert_eq!(partial.opaque_middle_len, 1);
        assert_eq!(
            decode_row(&row(&[7, 2, 0, 9]), &schema),
            Err(DecodeError::InvalidBooleanU16 {
                column: 1,
                value: 2,
            })
        );
    }

    #[test]
    fn decodes_separated_inline_packed_boolean_runs_in_both_bit_orders() {
        let columns = vec![
            ColumnDef::new(1, "first", ColumnType::Integer, 1, false),
            ColumnDef::new(2, "a", ColumnType::Boolean, 0, false),
            ColumnDef::new(3, "b", ColumnType::Boolean, 0, false),
            ColumnDef::new(4, "second", ColumnType::Integer, 1, false),
            ColumnDef::new(5, "c", ColumnType::Boolean, 0, false),
            ColumnDef::new(6, "d", ColumnType::Boolean, 0, false),
            ColumnDef::new(7, "e", ColumnType::Boolean, 0, false),
        ];
        for (layout, payload) in [
            (
                BooleanTailLayout::InlinePackedRunsMsbFirst,
                [7, 0b1000_0000, 9, 0b0110_0000],
            ),
            (
                BooleanTailLayout::InlinePackedRunsLsbFirst,
                [7, 0b0000_0001, 9, 0b0000_0110],
            ),
        ] {
            let mut schema = RowSchema::new(columns.clone());
            schema.boolean_tail = layout;
            assert_eq!(
                decode_row_exact(&row(&payload), &schema).unwrap().values,
                vec![
                    Value::Integer(7),
                    Value::Boolean(true),
                    Value::Boolean(false),
                    Value::Integer(9),
                    Value::Boolean(false),
                    Value::Boolean(true),
                    Value::Boolean(true),
                ]
            );
        }
    }

    #[test]
    fn partial_decode_returns_only_requested_inline_packed_run_booleans() {
        let mut schema = RowSchema::new(vec![
            ColumnDef::new(11, "first", ColumnType::Integer, 1, false),
            ColumnDef::new(22, "a", ColumnType::Boolean, 0, false),
            ColumnDef::new(33, "b", ColumnType::Boolean, 0, false),
            ColumnDef::new(44, "second", ColumnType::Integer, 1, false),
            ColumnDef::new(55, "c", ColumnType::Boolean, 0, false),
            ColumnDef::new(66, "d", ColumnType::Boolean, 0, false),
            ColumnDef::new(77, "e", ColumnType::Boolean, 0, false),
        ]);
        schema.boolean_tail = BooleanTailLayout::InlinePackedRunsMsbFirst;
        let decoded =
            decode_row_prefix_and_boolean_tail(&row(&[7, 0b1000_0000, 9, 0b0110_0000]), &schema, 5)
                .unwrap();
        assert_eq!(
            decoded.boolean_values,
            vec![
                PartialRowValue {
                    column_index: 1,
                    column_id: 22,
                    value: Value::Boolean(true),
                },
                PartialRowValue {
                    column_index: 2,
                    column_id: 33,
                    value: Value::Boolean(false),
                },
                PartialRowValue {
                    column_index: 4,
                    column_id: 55,
                    value: Value::Boolean(false),
                },
            ]
        );
        assert_eq!(decoded.opaque_middle_len, 0);
    }

    #[test]
    fn byte_boolean_layouts_reject_noncanonical_values() {
        let schema = RowSchema::new(vec![ColumnDef::new(
            1,
            "flag",
            ColumnType::Boolean,
            0,
            false,
        )]);
        assert_eq!(
            decode_row(&row(&[2]), &schema),
            Err(DecodeError::InvalidBooleanByte {
                column: 0,
                value: 2,
            })
        );

        let mut inline = schema;
        inline.boolean_tail = BooleanTailLayout::InlineBytes;
        assert_eq!(
            decode_row(&row(&[0xff]), &inline),
            Err(DecodeError::InvalidBooleanByte {
                column: 0,
                value: 0xff,
            })
        );
    }

    #[test]
    fn domain_ids_distinguish_enum_from_boolean() {
        assert_eq!(ColumnType::from_domain_id(19), Some(ColumnType::Enum));
        assert_eq!(ColumnType::from_domain_id(24), Some(ColumnType::Boolean));
    }

    #[test]
    fn enum_is_recognized_but_rejected_without_a_proven_scalar_layout() {
        let schema = RowSchema::new(vec![ColumnDef::new(1, "kind", ColumnType::Enum, 2, false)]);
        assert_eq!(
            decode_row(&row(&[1, 0]), &schema),
            Err(DecodeError::UnsupportedEnum {
                column: 0,
                width: 2,
            })
        );
    }

    #[test]
    fn explicit_enum_layout_preserves_only_proven_fixed_width_scalar() {
        let mut schema =
            RowSchema::new(vec![ColumnDef::new(1, "kind", ColumnType::Enum, 2, false)]);
        schema.enum_layout = EnumLayout::FixedWidthUnsigned;
        assert_eq!(
            decode_row_exact(&row(&[0x34, 0x12]), &schema)
                .unwrap()
                .values,
            vec![Value::Enum(0x1234)]
        );
        schema.columns[0].width = 3;
        assert_eq!(
            decode_row_exact(&row(&[0, 0, 0]), &schema),
            Err(DecodeError::InvalidEnumWidth {
                column: 0,
                width: 3,
            })
        );
    }

    #[test]
    fn domain_24_boolean_uses_the_boolean_tail() {
        let boolean = ColumnType::from_domain_id(24).expect("known BOOLEAN domain");
        let schema = RowSchema::new(vec![ColumnDef::new(1, "flag", boolean, 0, false)]);
        assert_eq!(
            decode_row(&row(&[1]), &schema).unwrap().values,
            vec![Value::Boolean(true)]
        );
    }

    #[test]
    fn rejects_overflow_marker_without_consuming_255_bytes() {
        let schema = RowSchema::new(vec![ColumnDef::new(1, "text", ColumnType::Text, 0, false)]);
        assert_eq!(
            decode_row(&row(&[0xff]), &schema),
            Err(DecodeError::OverflowValue { column: 0 })
        );
    }

    #[test]
    fn explicit_overflow_pointer_layout_preserves_pointer_without_resolving() {
        let mut schema = RowSchema::new(vec![
            ColumnDef::new(1, "text", ColumnType::Text, 0, false),
            ColumnDef::new(2, "tail", ColumnType::Integer, 2, false),
        ]);
        schema.variable_overflow_layout = VariableOverflowLayout::Pointer { width: 4 };
        assert_eq!(
            decode_row_exact(&row(&[0xff, 1, 2, 3, 4, 9, 0]), &schema)
                .unwrap()
                .values,
            vec![Value::OverflowPointer(vec![1, 2, 3, 4]), Value::Integer(9)]
        );
        schema.variable_overflow_layout = VariableOverflowLayout::Pointer { width: 0 };
        assert_eq!(
            decode_row_exact(&row(&[0xff, 9, 0]), &schema),
            Err(DecodeError::InvalidOverflowPointerWidth { column: 0 })
        );
    }

    #[test]
    fn variable_length_layout_can_use_u16_or_declared_width() {
        let mut schema = RowSchema::new(vec![ColumnDef::new(
            1,
            "memo",
            ColumnType::Text2,
            4096,
            false,
        )]);
        schema.variable_length_layout = VariableLengthLayout::U16Le;
        assert_eq!(
            decode_row_exact(&row(&[2, 0, b'o', b'k']), &schema)
                .unwrap()
                .values,
            vec![Value::Bytes(b"ok".to_vec())]
        );
        schema.variable_length_layout = VariableLengthLayout::DeclaredWidth {
            wide_at_or_above: 255,
        };
        assert_eq!(
            decode_row_exact(&row(&[2, 0, b'o', b'k']), &schema)
                .unwrap()
                .values,
            vec![Value::Bytes(b"ok".to_vec())]
        );
        schema.variable_overflow_layout = VariableOverflowLayout::Pointer { width: 4 };
        assert_eq!(
            decode_row_exact(&row(&[0xff, 0xff, 1, 2, 3, 4]), &schema)
                .unwrap()
                .values,
            vec![Value::OverflowPointer(vec![1, 2, 3, 4])]
        );
    }

    #[test]
    fn numeric_base_100_keeps_exact_decimal_scale() {
        let schema = RowSchema::new(vec![ColumnDef::new(
            1,
            "amount",
            ColumnType::Numeric,
            0,
            false,
        )]);
        // 05,14,32 = 51432; 0xbf moves the radix two decimal places left.
        let decoded = decode_row(&row(&[3, 0xbf, 5, 14, 32]), &schema).unwrap();
        assert_eq!(
            decoded.values,
            vec![Value::Decimal(Decimal {
                negative: false,
                coefficient: "51432".into(),
                scale: 2
            })]
        );
        match &decoded.values[0] {
            Value::Decimal(value) => assert_eq!(value.to_string(), "514.32"),
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn short_numeric_uses_zero_bias_at_80() {
        let schema = RowSchema::new(vec![ColumnDef::new(
            1,
            "amount",
            ColumnType::Numeric,
            0,
            false,
        )]);
        let zero = decode_row(&row(&[0, 0x80]), &schema).unwrap();
        let minus_one = decode_row(&row(&[0, 0x81]), &schema).unwrap();
        assert_eq!(
            zero.values,
            vec![Value::Decimal(Decimal {
                negative: false,
                coefficient: "0".into(),
                scale: 0
            })]
        );
        assert_eq!(
            minus_one.values,
            vec![Value::Decimal(Decimal {
                negative: true,
                coefficient: "1".into(),
                scale: 0
            })]
        );
    }

    #[test]
    fn decimal_rendering_never_emits_negative_zero_at_any_scale() {
        for scale in [0, 1, 2, 5] {
            assert_eq!(
                Decimal {
                    negative: true,
                    coefficient: "0".into(),
                    scale,
                }
                .to_plain_string(),
                match scale {
                    0 => "0".to_owned(),
                    _ => format!("0.{}", "0".repeat(scale as usize)),
                }
            );
        }
    }

    #[test]
    fn date_epoch_and_datetime_are_lossless() {
        let schema = RowSchema::new(vec![
            ColumnDef::new(1, "date", ColumnType::Date, 0, false),
            ColumnDef::new(2, "datetime", ColumnType::DateTime, 0, false),
        ]);
        let mut payload = Vec::new();
        payload.extend_from_slice(&0_i32.to_le_bytes());
        payload.extend_from_slice(&1_440_i32.to_le_bytes());
        payload.extend_from_slice(&123_i32.to_le_bytes());
        let decoded = decode_row(&row(&payload), &schema).unwrap();
        assert_eq!(
            match decoded.values[0] {
                Value::Date(date) => (date.ymd(), date.raw_minutes),
                _ => panic!("wrong type"),
            },
            ((1600, 2, 29), 0)
        );
        assert_eq!(
            match decoded.values[1] {
                Value::DateTime(dt) =>
                    (dt.date.ymd(), dt.minutes_since_sa_epoch, dt.subminute_raw,),
                _ => panic!("wrong type"),
            },
            ((1600, 3, 1), 1_440, 123)
        );
    }

    #[test]
    fn fails_closed_on_flags_truncation_and_invalid_digits() {
        let schema = RowSchema::new(vec![ColumnDef::new(1, "n", ColumnType::Numeric, 0, false)]);
        assert!(matches!(
            decode_row(&[0x02, 0x20], &schema),
            Err(DecodeError::UnsupportedRowFlags(ROW_FLAG_OVERFLOW))
        ));
        assert!(matches!(
            decode_row(&row(&[1, 0xc0]), &schema),
            Err(DecodeError::Truncated { .. })
        ));
        assert_eq!(
            decode_row(&row(&[1, 0xc0, 100]), &schema),
            Err(DecodeError::InvalidNumericDigit {
                column: 0,
                digit: 100
            })
        );
    }
}
