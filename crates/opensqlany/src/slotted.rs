//! Slotted-page directory parser.
//!
//! SA17 catalog and data pages use the classic slotted-page layout: a
//! header region at the start of the page, row bodies growing down from
//! near the page end, and a descending array of u16 row offsets that points
//! at each row body. Both little-endian and big-endian arrays occur in
//! QuickBooks Enterprise 24 files.
//!
//! Observed quirks (see `SPECIFICATION.md §6`):
//!
//! * the slot array may start on either byte alignment,
//! * a leading `0x0000` word may precede the first live offset,
//! * deleted slots appear as interior zero words,
//! * the bytes immediately before the array contain the minimum row
//!   offset and the slot count, but other fields are per-type.

use crate::page::Page;

const TRAILER_START: usize = 0xFF0;
const SEARCH_LIMIT: usize = 0x300;
const SLOT_OFFSET_MIN: u16 = 0x20;
const SLOT_OFFSET_MAX: u16 = TRAILER_START as u16;
const MIN_LIVE_SLOTS: usize = 8;

/// Decoded slot directory.
#[derive(Debug, Clone)]
pub struct SlotDirectory {
    /// Byte offset at which scanning started (may be a sentinel).
    pub scan_start: usize,
    /// Byte offset of the first actual slot entry.
    pub array_start: usize,
    /// Byte offset immediately after the last slot entry.
    pub end: usize,
    /// All u16 slot entries, in array order. Zero entries represent
    /// deleted slots.
    pub slots: Vec<u16>,
    /// `true` iff a `0x0000` sentinel word preceded the array.
    pub leading_zero: bool,
    /// `true` when the slot words were stored in big-endian byte order.
    pub big_endian: bool,
}

impl SlotDirectory {
    /// Live (non-deleted) row offsets.
    pub fn live_slots(&self) -> impl Iterator<Item = u16> + '_ {
        self.slots.iter().copied().filter(|&s| s != 0)
    }

    /// Number of live slots.
    pub fn live_count(&self) -> usize {
        self.slots.iter().filter(|&&s| s != 0).count()
    }

    /// Number of deleted (zero) slots between live entries.
    pub fn deleted_count(&self) -> usize {
        self.slots.len() - self.live_count()
    }

    /// Minimum live row offset, if any.
    pub fn min_offset(&self) -> Option<u16> {
        self.live_slots().min()
    }
}

/// A page that has been parsed for its slotted-directory layout.
#[derive(Debug, Clone)]
pub struct SlottedPage<'a> {
    /// The underlying page.
    pub page: Page<'a>,
    /// The directory, if one was found.
    pub directory: Option<SlotDirectory>,
}

impl<'a> SlottedPage<'a> {
    /// Scan `page` for a plausible descending slot directory. The page
    /// contents must already be plaintext (any QBW-style obfuscation must
    /// be removed by the caller).
    pub fn parse(page: Page<'a>) -> Self {
        let directory = find_slot_directory(page.bytes());
        SlottedPage { page, directory }
    }

    /// Return the raw row bytes for each live slot, in array order.
    ///
    /// Row boundaries are inferred from the (descending) offsets of the
    /// neighbouring slot and the start of the trailer. This is a
    /// best-effort slicing - it does not yet decode any row header.
    pub fn row_bytes(&self) -> Vec<(u16, &'a [u8])> {
        self.row_slots()
            .into_iter()
            .map(|(_, offset, bytes)| (offset, bytes))
            .collect()
    }

    /// Return each live row with its original zero-based directory index,
    /// offset, and bytes in slot-array order.
    ///
    /// This is the diagnostic-safe variant of [`Self::row_bytes`]: deleted
    /// zero entries are omitted from its results but still count toward later
    /// `slot_index` values.
    pub fn row_slots(&self) -> Vec<(usize, u16, &'a [u8])> {
        let Some(dir) = &self.directory else {
            return Vec::new();
        };
        let bytes = self.page.bytes();

        // Collect live offsets in ascending order so each row ends at the
        // next-higher live offset (or the trailer start).
        let mut live: Vec<u16> = dir.live_slots().collect();
        live.sort_unstable();

        // Derive each distinct offset's bounds from physical address order,
        // then emit them in the original slot-array order.  Directory index
        // is an identity used by diagnostics; sorting the output silently
        // relabelled physical slots.
        let mut bounds = Vec::with_capacity(live.len());
        for (i, &off) in live.iter().enumerate() {
            let start = off as usize;
            let end = live
                .get(i + 1)
                .map(|n| *n as usize)
                .unwrap_or(TRAILER_START);
            if start < end && end <= TRAILER_START {
                bounds.push((off, start, end));
            }
        }
        dir.slots
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(slot_index, off)| {
                (off != 0).then_some(())?;
                bounds
                    .iter()
                    .find(|(bound_offset, _, _)| *bound_offset == off)
                    .map(|(_, start, end)| (slot_index, off, &bytes[*start..*end]))
            })
            .collect()
    }

    /// Return the non-zero page prefix before the slot directory, if present.
    ///
    /// This region can contain ordinary page header or prelude metadata. The
    /// presence of non-zero bytes alone is not evidence of a row continuation,
    /// and callers must retain it as unclassified physical structure unless an
    /// independent format witness establishes stronger semantics. No slot
    /// points to this region, so it is invisible to [`SlottedPage::row_bytes`].
    ///
    /// Returns `Some(bytes)` when the bytes before the slot directory are
    /// non-zero. Returns `None` when there is no slot directory or the prefix
    /// region is all zeros.
    pub fn unclassified_prefix(&self) -> Option<&'a [u8]> {
        let dir = self.directory.as_ref()?;
        let end = dir.array_start;
        if end == 0 {
            return None;
        }
        let bytes = self.page.bytes();
        let prefix = &bytes[..end];
        if prefix.iter().all(|&b| b == 0) {
            None
        } else {
            Some(prefix)
        }
    }

    /// Historical name for [`Self::unclassified_prefix`].
    ///
    /// Non-zero prefix bytes are not, by themselves, continuation evidence.
    #[deprecated(
        since = "0.1.2",
        note = "use unclassified_prefix; the bytes do not prove row continuation"
    )]
    pub fn overflow_prefix(&self) -> Option<&'a [u8]> {
        self.unclassified_prefix()
    }
}

fn u16le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn u16be(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off], buf[off + 1]])
}

fn is_slot_offset(value: u16) -> bool {
    (SLOT_OFFSET_MIN..SLOT_OFFSET_MAX).contains(&value)
}

fn scan_from(plain: &[u8], start: usize, big_endian: bool) -> Option<SlotDirectory> {
    let mut pos = start;
    let mut leading_zero = false;
    let mut slots: Vec<u16> = Vec::new();
    let mut prev: u32 = 0x10000;

    let read_u16 = if big_endian { u16be } else { u16le };

    if pos + 3 < SEARCH_LIMIT
        && read_u16(plain, pos) == 0
        && is_slot_offset(read_u16(plain, pos + 2))
    {
        leading_zero = true;
        pos += 2;
    }

    let array_start = pos;
    let mut seen_live = false;

    while pos + 1 < SEARCH_LIMIT {
        let value = read_u16(plain, pos);
        if value == 0 && seen_live {
            slots.push(0);
            pos += 2;
            continue;
        }
        if is_slot_offset(value) && (value as u32) < prev {
            slots.push(value);
            prev = value as u32;
            seen_live = true;
            pos += 2;
            continue;
        }
        break;
    }

    let live_count = slots.iter().filter(|&&s| s != 0).count();
    if live_count < MIN_LIVE_SLOTS {
        return None;
    }

    // A slot directory lives before the row bodies it describes.  Without
    // this check, arbitrary low-valued u16 sequences can look like a valid
    // descending directory even though the directory itself overwrites the
    // first purported row.
    let min_offset = slots.iter().copied().filter(|&slot| slot != 0).min()? as usize;
    if pos > min_offset {
        return None;
    }

    Some(SlotDirectory {
        scan_start: start,
        array_start,
        end: pos,
        slots,
        leading_zero,
        big_endian,
    })
}

fn find_slot_directory(plain: &[u8]) -> Option<SlotDirectory> {
    let mut best: Option<SlotDirectory> = None;
    for start in 0..SEARCH_LIMIT {
        // Try little-endian first to preserve the parser's established tie
        // breaking behavior on pages where both interpretations are plausible.
        for big_endian in [false, true] {
            let Some(cand) = scan_from(plain, start, big_endian) else {
                continue;
            };
            let better = match &best {
                None => true,
                Some(b) => {
                    let cand_live = cand.slots.iter().filter(|&&s| s != 0).count();
                    let best_live = b.slots.iter().filter(|&&s| s != 0).count();
                    cand_live > best_live
                        || (cand_live == best_live && cand.slots.len() > b.slots.len())
                }
            };
            if better {
                best = Some(cand);
            }
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_slots(page: &mut [u8], start: usize, slots: &[u16], big_endian: bool) {
        for (index, slot) in slots.iter().enumerate() {
            let offset = start + index * 2;
            let bytes = if big_endian {
                slot.to_be_bytes()
            } else {
                slot.to_le_bytes()
            };
            page[offset..offset + 2].copy_from_slice(&bytes);
        }
    }

    #[test]
    fn rejects_directory_that_overlaps_its_first_live_row() {
        let mut page = vec![0_u8; 4096];
        // The directory occupies 20..36, but its smallest claimed row starts
        // at 33, inside the directory itself.
        put_slots(&mut page, 20, &[40, 39, 38, 37, 36, 35, 34, 33], false);

        assert!(scan_from(&page, 20, false).is_none());
    }

    #[test]
    fn keeps_valid_directory_when_an_overlapping_false_one_precedes_it() {
        let mut page = vec![0_u8; 4096];
        put_slots(&mut page, 20, &[40, 39, 38, 37, 36, 35, 34, 33], false);
        put_slots(
            &mut page,
            200,
            &[1000, 950, 900, 850, 800, 750, 700, 650],
            false,
        );
        // A non-slot metadata word terminates the otherwise-zero-filled
        // synthetic directory.
        page[216..218].copy_from_slice(&u16::MAX.to_le_bytes());

        let directory = find_slot_directory(&page).expect("valid directory");
        assert_eq!(directory.array_start, 200);
        assert_eq!(directory.end, 216);
        assert_eq!(directory.min_offset(), Some(650));
        assert!(!directory.big_endian);
    }

    #[test]
    fn parses_big_endian_directory_and_preserves_its_byte_order() {
        let mut page = vec![0_u8; 4096];
        put_slots(
            &mut page,
            0,
            &[
                0x0ea1, 0x0e84, 0x0e67, 0x0e4a, 0x0e2d, 0x0e10, 0x0df3, 0x0dd6,
            ],
            true,
        );
        page[16..18].copy_from_slice(&u16::MAX.to_be_bytes());

        let directory = find_slot_directory(&page).expect("big-endian directory");
        assert_eq!(directory.array_start, 0);
        assert_eq!(directory.slots[0], 0x0ea1);
        assert_eq!(directory.min_offset(), Some(0x0dd6));
        assert!(directory.big_endian);
    }

    #[test]
    fn rejects_big_endian_directory_that_overlaps_its_first_live_row() {
        let mut page = vec![0_u8; 4096];
        put_slots(&mut page, 20, &[40, 39, 38, 37, 36, 35, 34, 33], true);

        assert!(scan_from(&page, 20, true).is_none());
    }

    #[test]
    fn row_bytes_preserves_slot_array_order_while_using_address_order_for_bounds() {
        let mut page = vec![0_u8; 4096];
        let slots = [400_u16, 300, 200, 100, 90, 80, 70, 60];
        put_slots(&mut page, 0, &slots, false);
        page[16..18].copy_from_slice(&u16::MAX.to_le_bytes());
        page[60..70].fill(1);
        page[70..80].fill(2);
        page[80..90].fill(3);
        page[90..100].fill(4);
        page[100..200].fill(5);
        page[200..300].fill(6);
        page[300..400].fill(7);
        page[400..TRAILER_START].fill(8);

        let parsed = SlottedPage::parse(Page::from_bytes(0, &page));
        let rows = parsed.row_bytes();
        assert_eq!(
            rows.iter().map(|(offset, _)| *offset).collect::<Vec<_>>(),
            slots
        );
        assert_eq!(rows[0].1, &page[400..TRAILER_START]);
        assert_eq!(rows[7].1, &page[60..70]);
        assert_eq!(
            parsed
                .row_slots()
                .iter()
                .map(|(slot_index, _, _)| *slot_index)
                .collect::<Vec<_>>(),
            (0..slots.len()).collect::<Vec<_>>(),
        );
    }

    #[test]
    fn row_slots_retains_indices_after_deleted_entries() {
        let mut page = vec![0_u8; 4096];
        put_slots(
            &mut page,
            0,
            &[400, 300, 0, 200, 100, 90, 80, 70, 60],
            false,
        );
        page[18..20].copy_from_slice(&u16::MAX.to_le_bytes());
        let parsed = SlottedPage::parse(Page::from_bytes(0, &page));
        assert_eq!(
            parsed
                .row_slots()
                .iter()
                .map(|(slot_index, _, _)| *slot_index)
                .collect::<Vec<_>>(),
            vec![0, 1, 3, 4, 5, 6, 7, 8],
        );
    }
}
