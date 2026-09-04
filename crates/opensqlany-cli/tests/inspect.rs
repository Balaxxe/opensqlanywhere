//! Black-box CLI integrity tests using only synthetic page stores.

use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_TEMP_FILE: AtomicUsize = AtomicUsize::new(0);

fn stamped_page(page_type: u8) -> [u8; 4096] {
    let mut page = [0_u8; 4096];
    page[0xFF2] = page_type;
    let crc = crc32fast::hash(&page[..0xFFC]);
    page[0xFFC..].copy_from_slice(&crc.to_le_bytes());
    page
}

fn temporary_store(pages: &[[u8; 4096]]) -> std::path::PathBuf {
    let sequence = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "opensqlany-cli-integration-{}-{sequence}.db",
        std::process::id()
    ));
    let mut bytes = Vec::with_capacity(pages.len() * 4096);
    for page in pages {
        bytes.extend_from_slice(page);
    }
    fs::write(&path, bytes).expect("write synthetic page store");
    path
}

#[test]
fn inspect_reports_and_fails_for_a_bad_page_zero_crc() {
    let mut superblock = stamped_page(0);
    superblock[0xFFC] ^= 1;
    let path = temporary_store(&[superblock, stamped_page(b'E')]);

    let output = Command::new(env!("CARGO_BIN_EXE_opensqlany"))
        .args([
            "inspect",
            path.to_str().expect("UTF-8 temporary path"),
            "--verify-crc",
        ])
        .output()
        .expect("run opensqlany inspect");

    assert!(!output.status.success(), "corrupt input must fail");
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 stdout");
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    assert!(stdout.contains("pages inspected   : 2 (including superblock)"));
    assert!(stdout.contains("crc failures      : 1"));
    assert!(stdout.contains("  - page 0"));
    assert!(stderr.contains("integrity verification found 1 failure"));

    fs::remove_file(path).expect("remove synthetic page store");
}

#[test]
fn inspect_verify_crc_reports_and_fails_for_a_bad_body_page_crc() {
    let superblock = stamped_page(0);
    let mut body_page = stamped_page(b'E');
    body_page[0xFFC] ^= 1;
    let path = temporary_store(&[superblock, body_page]);

    let output = Command::new(env!("CARGO_BIN_EXE_opensqlany"))
        .args([
            "inspect",
            path.to_str().expect("UTF-8 temporary path"),
            "--verify-crc",
        ])
        .output()
        .expect("run opensqlany inspect");

    assert!(!output.status.success(), "corrupt input must fail");
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 stdout");
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    assert!(stdout.contains("crc failures      : 1"));
    assert!(stdout.contains("  - page 1"));
    assert!(stderr.contains("integrity verification found 1 failure"));

    fs::remove_file(path).expect("remove synthetic page store");
}

#[test]
fn inspect_reports_and_fails_for_an_invalid_body_trailer_without_crc_verification() {
    let superblock = stamped_page(0);
    let mut body_page = stamped_page(b'E');
    body_page[0xFF3] = 1;
    let crc = crc32fast::hash(&body_page[..0xFFC]);
    body_page[0xFFC..].copy_from_slice(&crc.to_le_bytes());
    let path = temporary_store(&[superblock, body_page]);

    let output = Command::new(env!("CARGO_BIN_EXE_opensqlany"))
        .args(["inspect", path.to_str().expect("UTF-8 temporary path")])
        .output()
        .expect("run opensqlany inspect");

    assert!(!output.status.success(), "invalid trailer must fail");
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 stdout");
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    assert!(stdout.contains("crc verification  : skipped"));
    assert!(stdout.contains("trailer failures  : 1"));
    assert!(stdout.contains("  - page 1"));
    assert!(stderr.contains("integrity verification found 1 failure"));

    fs::remove_file(path).expect("remove synthetic page store");
}
