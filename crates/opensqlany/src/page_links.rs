//! Conservative parsing and traversal of the observed SA17 page-link block.
//!
//! This module deliberately does **not** call the link a B-tree sibling or
//! child pointer.  In the Enterprise 24 QBW examined during development the
//! block occurs on allocation and extent pages, but neither its ownership nor
//! its relationship to a `SYSINDEX` entry has been established.  It is useful
//! nevertheless as a bounded, independently verifiable page-chain primitive.
//!
//! The currently observed block is:
//!
//! ```text
//! +00  u32_le  page's own page number
//! +04  00 00
//! +08  f32_le(1.0)
//! ...
//! +24  d5 0b
//! +26  link flag
//! +27  00 00 00
//! +30  u32_le  link target when the flag is one
//! ```
//!
//! All other bytes remain intentionally opaque.  A target is never followed
//! unless it is a non-zero in-range page number and it differs from the page
//! containing the block.

/// The fixed `f32_le(1.0)` bytes in the observed page-link block.
const F32_ONE: [u8; 4] = [0x00, 0x00, 0x80, 0x3f];
const LINK_MARKER: [u8; 2] = [0xd5, 0x0b];
const BLOCK_MIN_LEN: usize = 34;

/// Target state decoded from a page-link block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageLinkTarget {
    /// The block's link flag was not set.
    Absent,
    /// A non-zero in-range target, safe for a caller to consider following.
    InRange(u32),
    /// The link flag was set, but the raw target is not safe to follow.
    ///
    /// This includes page zero, a target outside the supplied store size, and
    /// a self link.  Keeping the raw value makes diagnostics possible without
    /// turning a malformed reference into a traversal edge.
    Invalid(u32),
}

/// A verified occurrence of the observed page-link metadata block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageLinkMetadata {
    /// Byte offset at which the block begins in the plaintext page body.
    pub offset: usize,
    /// Raw flag byte immediately after the `d5 0b` marker.
    pub link_flag: u8,
    /// Validated link state.
    pub target: PageLinkTarget,
}

/// Find the first strictly validated page-link block in `plain`.
///
/// `page_number` is the zero-based number of the containing page and
/// `page_count` is the number of pages in the store.  The function is purely
/// byte-oriented: callers are responsible for deobfuscating the page first.
/// It returns `None` for malformed, short, or unrelated byte sequences.
pub fn find_page_link_metadata(
    plain: &[u8],
    page_number: u64,
    page_count: u64,
) -> Option<PageLinkMetadata> {
    if page_count == 0 || page_number >= page_count || plain.len() < BLOCK_MIN_LEN {
        return None;
    }
    let page_number = u32::try_from(page_number).ok()?;
    let scan_end = plain.len().saturating_sub(BLOCK_MIN_LEN);

    for offset in 0..=scan_end {
        if plain[offset..offset + 4] != page_number.to_le_bytes()
            || plain[offset + 4] != 0
            || plain[offset + 5] != 0
            || plain[offset + 8..offset + 12] != F32_ONE
            || plain[offset + 24..offset + 26] != LINK_MARKER
            || plain[offset + 27..offset + 30] != [0, 0, 0]
        {
            continue;
        }

        let link_flag = plain[offset + 26];
        let raw_target = u32::from_le_bytes(
            plain[offset + 30..offset + 34]
                .try_into()
                .expect("fixed-length slice"),
        );
        let target = if link_flag != 1 {
            PageLinkTarget::Absent
        } else if raw_target == 0
            || u64::from(raw_target) >= page_count
            || raw_target == page_number
        {
            PageLinkTarget::Invalid(raw_target)
        } else {
            PageLinkTarget::InRange(raw_target)
        };
        return Some(PageLinkMetadata {
            offset,
            link_flag,
            target,
        });
    }
    None
}

/// Why a bounded page-link walk stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageLinkWalkStop {
    /// The current page did not have a recognized metadata block.
    MissingMetadata,
    /// The current block had no link flag.
    NoLink,
    /// The current block's target was malformed and was not followed.
    InvalidTarget(u32),
    /// The next page was already visited.
    Cycle(u32),
    /// The caller's explicit page bound was reached.
    LimitReached,
}

/// Result of following observed page links from one starting page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageLinkWalk {
    /// Every visited page, including the starting page when `max_pages > 0`.
    pub pages: Vec<u32>,
    /// The reason traversal stopped.
    pub stop: PageLinkWalkStop,
}

/// Follow a caller-supplied sequence of parsed page-link blocks safely.
///
/// The `lookup` closure must return already-validated metadata for the given
/// page, or `None` when that page cannot be decoded or has no block.  This
/// separation prevents the low-level primitive from guessing deobfuscation or
/// physical index semantics.  At most `max_pages` pages are visited.
pub fn walk_page_links(
    start: u32,
    max_pages: usize,
    mut lookup: impl FnMut(u32) -> Option<PageLinkMetadata>,
) -> PageLinkWalk {
    let mut pages = Vec::new();
    let mut current = start;

    while pages.len() < max_pages {
        if pages.contains(&current) {
            return PageLinkWalk {
                pages,
                stop: PageLinkWalkStop::Cycle(current),
            };
        }
        pages.push(current);
        let Some(metadata) = lookup(current) else {
            return PageLinkWalk {
                pages,
                stop: PageLinkWalkStop::MissingMetadata,
            };
        };
        match metadata.target {
            PageLinkTarget::Absent => {
                return PageLinkWalk {
                    pages,
                    stop: PageLinkWalkStop::NoLink,
                };
            }
            PageLinkTarget::Invalid(raw) => {
                return PageLinkWalk {
                    pages,
                    stop: PageLinkWalkStop::InvalidTarget(raw),
                };
            }
            PageLinkTarget::InRange(next) => current = next,
        }
    }

    PageLinkWalk {
        pages,
        stop: PageLinkWalkStop::LimitReached,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(page: u32, flag: u8, target: u32) -> Vec<u8> {
        let mut bytes = vec![0_u8; BLOCK_MIN_LEN];
        bytes[0..4].copy_from_slice(&page.to_le_bytes());
        bytes[8..12].copy_from_slice(&F32_ONE);
        bytes[24..26].copy_from_slice(&LINK_MARKER);
        bytes[26] = flag;
        bytes[30..34].copy_from_slice(&target.to_le_bytes());
        bytes
    }

    #[test]
    fn parses_only_strictly_shaped_in_range_link() {
        let mut page = vec![0_u8; 96];
        let b = block(7, 1, 11);
        page[13..13 + b.len()].copy_from_slice(&b);

        assert_eq!(
            find_page_link_metadata(&page, 7, 12),
            Some(PageLinkMetadata {
                offset: 13,
                link_flag: 1,
                target: PageLinkTarget::InRange(11),
            })
        );
    }

    #[test]
    fn rejects_near_miss_and_short_pages() {
        let mut b = block(7, 1, 11);
        b[24] = 0;
        assert_eq!(find_page_link_metadata(&b, 7, 12), None);
        assert_eq!(find_page_link_metadata(&b[..20], 7, 12), None);
    }

    #[test]
    fn preserves_but_does_not_accept_unsafe_targets() {
        for raw in [0, 7, 12] {
            let b = block(7, 1, raw);
            assert_eq!(
                find_page_link_metadata(&b, 7, 12).unwrap().target,
                PageLinkTarget::Invalid(raw)
            );
        }
    }

    #[test]
    fn non_link_flag_has_no_target_even_when_bytes_are_nonzero() {
        let b = block(7, 2, 11);
        assert_eq!(
            find_page_link_metadata(&b, 7, 12).unwrap().target,
            PageLinkTarget::Absent
        );
    }

    fn metadata(target: PageLinkTarget) -> PageLinkMetadata {
        PageLinkMetadata {
            offset: 0,
            link_flag: matches!(
                target,
                PageLinkTarget::InRange(_) | PageLinkTarget::Invalid(_)
            ) as u8,
            target,
        }
    }

    #[test]
    fn walk_stops_on_missing_metadata_and_never_guesses() {
        let walked = walk_page_links(3, 5, |page| match page {
            3 => Some(metadata(PageLinkTarget::InRange(4))),
            _ => None,
        });
        assert_eq!(walked.pages, vec![3, 4]);
        assert_eq!(walked.stop, PageLinkWalkStop::MissingMetadata);
    }

    #[test]
    fn walk_detects_cycle_before_revisiting_page() {
        let walked = walk_page_links(3, 5, |page| match page {
            3 => Some(metadata(PageLinkTarget::InRange(4))),
            4 => Some(metadata(PageLinkTarget::InRange(3))),
            _ => None,
        });
        assert_eq!(walked.pages, vec![3, 4]);
        assert_eq!(walked.stop, PageLinkWalkStop::Cycle(3));
    }

    #[test]
    fn walk_obeys_hard_page_bound() {
        let walked = walk_page_links(3, 2, |page| {
            Some(metadata(PageLinkTarget::InRange(page + 1)))
        });
        assert_eq!(walked.pages, vec![3, 4]);
        assert_eq!(walked.stop, PageLinkWalkStop::LimitReached);
    }
}
