//! Bounded in-place sector permutation primitive recovered from SA17 code.
//!
//! This is only the generic byte primitive. It does not recover a QBW key,
//! select a transform direction, swap headers, or establish a raw-file use.

use core::fmt;

/// Sector length used by the observed SA17 callers.
pub const PAGE_PERMUTATION_SECTOR_LEN: usize = 512;

/// Apply the exact primitive to one 512-byte sector.
///
/// `start` is inclusive and `tail` excludes bytes from the sector's end. The
/// active range is therefore `start..=511-tail`. A zero key leaves bytes
/// unchanged after the arguments have been validated.
pub fn permute_sector_in_place(
    sector: &mut [u8],
    start: usize,
    tail: usize,
    signed_key: i32,
) -> Result<(), PagePermutationError> {
    if sector.len() != PAGE_PERMUTATION_SECTOR_LEN {
        return Err(PagePermutationError::InvalidSectorLength { len: sector.len() });
    }
    permute_power_of_two_in_place(sector, start, tail, signed_key)
}

/// Apply the exact primitive to a power-of-two byte buffer.
///
/// This general form exists to make the modulus and bounds explicit in tests.
/// Production callers of the recovered SA17 path use
/// [`permute_sector_in_place`] with 512 bytes.
pub fn permute_power_of_two_in_place(
    bytes: &mut [u8],
    start: usize,
    tail: usize,
    signed_key: i32,
) -> Result<(), PagePermutationError> {
    let len = bytes.len();
    validate_bounds(len, start, tail)?;
    if signed_key == 0 {
        return Ok(());
    }

    let magnitude = signed_key.unsigned_abs();
    let low8 = magnitude as u8;
    let increment = ((magnitude >> 8) as u8) | 1;
    let raw_stride = ((magnitude >> 16) as u16).wrapping_add(u16::from(low8)) | 1;
    let stride = if signed_key < 0 {
        (raw_stride as i16).wrapping_neg()
    } else {
        raw_stride as i16
    };
    let mut seed = if signed_key < 0 {
        negative_seed(len, start, tail, increment, low8)
    } else {
        low8
    };

    let end = len - 1 - tail;
    let first = bytes[start];
    let mut current = start;
    loop {
        let next = next_in_active_range(current, stride, len, start, end)?;
        if next == start {
            bytes[current] = first.wrapping_add(seed);
            return Ok(());
        }
        bytes[current] = bytes[next].wrapping_add(seed);
        seed = seed.wrapping_add(increment);
        current = next;
    }
}

fn validate_bounds(len: usize, start: usize, tail: usize) -> Result<(), PagePermutationError> {
    if len == 0 || !len.is_power_of_two() {
        return Err(PagePermutationError::NonPowerOfTwoLength { len });
    }
    let Some(active_start_plus_tail) = start.checked_add(tail) else {
        return Err(PagePermutationError::InvalidActiveRange { len, start, tail });
    };
    if start >= len || tail >= len || active_start_plus_tail >= len {
        return Err(PagePermutationError::InvalidActiveRange { len, start, tail });
    }
    Ok(())
}

fn negative_seed(len: usize, start: usize, tail: usize, increment: u8, low8: u8) -> u8 {
    // This follows the distinct negative-key branch literally. It is not
    // modeled as a generic arithmetic subtraction inverse.
    let boundary = start + tail;
    let factor = if len < 256 {
        let base = if boundary == 0 { 0 } else { boundary as u8 };
        base.wrapping_add(1).wrapping_add(len as u8)
    } else {
        (boundary + 1) as u8
    };
    increment.wrapping_mul(factor).wrapping_sub(low8)
}

fn next_in_active_range(
    current: usize,
    stride: i16,
    len: usize,
    start: usize,
    end: usize,
) -> Result<usize, PagePermutationError> {
    let mask = len - 1;
    let mut candidate = current.wrapping_add_signed(isize::from(stride)) & mask;
    for _ in 0..len {
        if (start..=end).contains(&candidate) {
            return Ok(candidate);
        }
        candidate = candidate.wrapping_add_signed(isize::from(stride)) & mask;
    }
    // Power-of-two length and odd stride make this unreachable for a valid
    // active range, but preserve a fail-closed result if that invariant ever
    // changes in a future caller.
    Err(PagePermutationError::NoActiveCycle {
        len,
        start,
        tail: len - 1 - end,
    })
}

/// Failure while validating a permutation sector or active range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PagePermutationError {
    /// The generic primitive needs a nonzero power-of-two buffer length.
    NonPowerOfTwoLength {
        /// Bytes supplied by the caller.
        len: usize,
    },
    /// The sector-specific wrapper requires exactly 512 bytes.
    InvalidSectorLength {
        /// Bytes supplied by the caller.
        len: usize,
    },
    /// `start..=len-1-tail` cannot be represented as a nonempty active range.
    InvalidActiveRange {
        /// Buffer length.
        len: usize,
        /// Requested inclusive start offset.
        start: usize,
        /// Requested excluded-byte count at the end.
        tail: usize,
    },
    /// No active-cycle member was found within one complete modulus cycle.
    NoActiveCycle {
        /// Buffer length.
        len: usize,
        /// Requested inclusive start offset.
        start: usize,
        /// Requested excluded-byte count at the end.
        tail: usize,
    },
}

impl fmt::Display for PagePermutationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonPowerOfTwoLength { len } => {
                write!(
                    f,
                    "permutation buffer length {len} is not a nonzero power of two"
                )
            }
            Self::InvalidSectorLength { len } => write!(
                f,
                "sector permutation needs exactly {PAGE_PERMUTATION_SECTOR_LEN} bytes, got {len}"
            ),
            Self::InvalidActiveRange { len, start, tail } => write!(
                f,
                "permutation range start={start}, tail={tail} is invalid for {len} bytes"
            ),
            Self::NoActiveCycle { len, start, tail } => write!(
                f,
                "permutation found no active cycle for start={start}, tail={tail} in {len} bytes"
            ),
        }
    }
}

impl std::error::Error for PagePermutationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positive_synthetic_vector_matches_the_transcribed_cycle() {
        let mut bytes = [0_u8, 1, 2, 3, 4, 5, 6, 7];
        permute_power_of_two_in_place(&mut bytes, 0, 0, 0x0001_0203).expect("positive");
        assert_eq!(bytes, [8, 24, 16, 24, 16, 8, 24, 16]);
    }

    #[test]
    fn negative_synthetic_vector_uses_its_distinct_seed_branch() {
        let mut bytes = [0_u8, 1, 2, 3, 4, 5, 6, 7];
        permute_power_of_two_in_place(&mut bytes, 0, 0, -0x0001_0203).expect("negative");
        assert_eq!(bytes, [27, 37, 47, 33, 43, 45, 31, 41]);
    }

    #[test]
    fn positive_then_negative_key_round_trips_a_512_byte_sector() {
        let original: [u8; PAGE_PERMUTATION_SECTOR_LEN] =
            core::array::from_fn(|index| (index as u8).wrapping_mul(37).wrapping_add(11));
        let mut bytes = original;
        let key = 0x1234_5678_i32;

        permute_sector_in_place(&mut bytes, 0, 0, key).expect("forward");
        permute_sector_in_place(&mut bytes, 0, 0, -key).expect("reverse");
        assert_eq!(bytes, original);
    }

    #[test]
    fn final_sixteen_bytes_are_preserved_when_tail_is_sixteen() {
        let mut bytes: [u8; PAGE_PERMUTATION_SECTOR_LEN] =
            core::array::from_fn(|index| index as u8);
        let tail = bytes[496..].to_vec();

        permute_sector_in_place(&mut bytes, 0, 16, 0x1234_5678).expect("sector");
        assert_eq!(&bytes[496..], tail.as_slice());
    }

    #[test]
    fn validates_power_of_two_sector_length_and_active_bounds() {
        let mut non_power_of_two = [0_u8; 500];
        assert_eq!(
            permute_power_of_two_in_place(&mut non_power_of_two, 0, 0, 1),
            Err(PagePermutationError::NonPowerOfTwoLength { len: 500 })
        );
        let mut sector = [0_u8; PAGE_PERMUTATION_SECTOR_LEN];
        assert_eq!(
            permute_sector_in_place(&mut sector[..511], 0, 0, 1),
            Err(PagePermutationError::InvalidSectorLength { len: 511 })
        );
        assert_eq!(
            permute_sector_in_place(&mut sector, 500, 12, 1),
            Err(PagePermutationError::InvalidActiveRange {
                len: 512,
                start: 500,
                tail: 12,
            })
        );
    }

    #[test]
    fn zero_key_preserves_a_valid_active_range() {
        let mut bytes = [0xA5_u8; PAGE_PERMUTATION_SECTOR_LEN];
        let original = bytes;
        permute_sector_in_place(&mut bytes, 5, 16, 0).expect("zero key");
        assert_eq!(bytes, original);
    }
}
