use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::{Error, Result};
use crate::page::{PAGE_SIZE, Page};
use crate::superblock::Superblock;

/// An SA17 page-store opened from disk.
///
/// The whole file is read into memory on [`PageStore::open`]. This is
/// appropriate for the file sizes the format typically produces
/// (13-45 MiB in the QBW corpus) and keeps the API zero-copy at the
/// per-page level.
#[derive(Debug)]
pub struct PageStore {
    bytes: Vec<u8>,
}

impl PageStore {
    /// Open a page store by path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let mut f = File::open(path)?;
        Ok(PageStore {
            bytes: read_size_stable_snapshot(&mut f)?,
        })
    }

    /// Wrap an already-materialised byte buffer as a page store.
    ///
    /// The buffer length must be a positive multiple of [`PAGE_SIZE`].
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let size = bytes.len() as u64;
        if size < PAGE_SIZE as u64 {
            return Err(Error::TooSmall { size });
        }
        if !size.is_multiple_of(PAGE_SIZE as u64) {
            return Err(Error::NotPageAligned {
                size,
                page_size: PAGE_SIZE,
            });
        }
        Ok(PageStore { bytes })
    }

    /// Total number of pages in the store.
    #[inline]
    pub fn page_count(&self) -> u64 {
        (self.bytes.len() / PAGE_SIZE) as u64
    }

    /// Total file size in bytes.
    #[inline]
    pub fn size_bytes(&self) -> u64 {
        self.bytes.len() as u64
    }

    /// Borrow a single page by zero-based index.
    pub fn page(&self, index: u64) -> Result<Page<'_>> {
        let total = self.page_count();
        if index >= total {
            return Err(Error::PageOutOfRange { page: index, total });
        }
        let start = index as usize * PAGE_SIZE;
        Ok(Page {
            index,
            bytes: &self.bytes[start..start + PAGE_SIZE],
        })
    }

    /// Iterate over every page in order, starting at page 0.
    pub fn pages(&self) -> Pages<'_> {
        Pages {
            store: self,
            next: 0,
        }
    }

    /// Parse and return the page-0 superblock. This also verifies the
    /// superblock magic; use [`PageStore::try_superblock`] for a
    /// non-failing variant.
    pub fn superblock(&self) -> Result<Superblock> {
        let sb = self.try_superblock()?;
        if !sb.magic_ok() {
            return Err(Error::BadMagic {
                got: sb.magic,
                want: crate::superblock::SA_MAGIC,
            });
        }
        Ok(sb)
    }

    /// Parse the page-0 superblock without validating the magic. Useful
    /// when inspecting files that might not be SA17.
    pub fn try_superblock(&self) -> Result<Superblock> {
        let page0 = self.page(0)?;
        Ok(Superblock::parse(page0.bytes()))
    }
}

/// Read exactly one size-stable, page-aligned file snapshot.
///
/// Keeping this generic allows deterministic tests for growth/truncation
/// without using corpus files.  The reader is bounded to its initial length;
/// a later length check rejects growth or truncation while it was read. This
/// cannot detect same-length in-place rewrites; callers that need an atomic
/// content snapshot must supply an immutable copy or external file locking.
fn read_size_stable_snapshot<R: Read + Seek>(reader: &mut R) -> Result<Vec<u8>> {
    let initial_size = reader.seek(SeekFrom::End(0))?;
    validate_store_size(initial_size)?;
    let capacity = usize::try_from(initial_size).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "page-store size does not fit this platform's address space",
        )
    })?;
    reader.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity).map_err(|_| {
        io::Error::new(
            io::ErrorKind::OutOfMemory,
            "unable to allocate page-store snapshot",
        )
    })?;
    bytes.resize(capacity, 0);
    reader.read_exact(&mut bytes)?;

    let final_size = reader.seek(SeekFrom::End(0))?;
    if final_size != initial_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "page-store changed while its snapshot was read",
        )
        .into());
    }
    // This is redundant for an unchanged file, but makes the size-stable
    // contract explicit if validation rules evolve.
    validate_store_size(final_size)?;
    Ok(bytes)
}

fn validate_store_size(size: u64) -> Result<()> {
    if size < PAGE_SIZE as u64 {
        return Err(Error::TooSmall { size });
    }
    if !size.is_multiple_of(PAGE_SIZE as u64) {
        return Err(Error::NotPageAligned {
            size,
            page_size: PAGE_SIZE,
        });
    }
    Ok(())
}

/// Iterator returned by [`PageStore::pages`].
#[derive(Debug)]
pub struct Pages<'a> {
    store: &'a PageStore,
    next: u64,
}

impl<'a> Iterator for Pages<'a> {
    type Item = Page<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next >= self.store.page_count() {
            return None;
        }
        let page = self.store.page(self.next).ok()?;
        self.next += 1;
        Some(page)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.store.page_count() - self.next) as usize;
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for Pages<'a> {}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Result as IoResult, Seek, SeekFrom};

    use super::*;

    #[test]
    fn size_stable_snapshot_reads_exactly_one_page() {
        let mut input = Cursor::new(vec![0_u8; PAGE_SIZE]);
        assert_eq!(
            read_size_stable_snapshot(&mut input).unwrap().len(),
            PAGE_SIZE
        );
    }

    #[test]
    fn size_stable_snapshot_rejects_unaligned_initial_size() {
        let mut input = Cursor::new(vec![0_u8; PAGE_SIZE + 1]);
        assert!(matches!(
            read_size_stable_snapshot(&mut input),
            Err(Error::NotPageAligned { .. })
        ));
    }

    struct GrowingReader {
        inner: Cursor<Vec<u8>>,
        read_started: bool,
    }

    impl Read for GrowingReader {
        fn read(&mut self, buffer: &mut [u8]) -> IoResult<usize> {
            self.read_started = true;
            self.inner.read(buffer)
        }
    }

    impl Seek for GrowingReader {
        fn seek(&mut self, position: SeekFrom) -> IoResult<u64> {
            if matches!(position, SeekFrom::End(0)) && self.read_started {
                return Ok((PAGE_SIZE * 2) as u64);
            }
            self.inner.seek(position)
        }
    }

    #[test]
    fn size_stable_snapshot_rejects_growth_after_the_bounded_read() {
        let mut input = GrowingReader {
            inner: Cursor::new(vec![0_u8; PAGE_SIZE]),
            read_started: false,
        };
        assert!(matches!(
            read_size_stable_snapshot(&mut input),
            Err(Error::Io(_))
        ));
    }
}
