//! Tier-1 tests: the unlock pipeline over self-minted containers.
//!
//! The mint helper builds a real LUKS2 on-disk container — binary
//! header with a valid checksum, JSON metadata, AF-split keyslot area,
//! XTS-encrypted data segment — using the same audited RustCrypto
//! primitives the unlock path uses (`aes` + `xts-mode` in reverse),
//! so a failure here is a wiring failure, not a crypto failure.
//!
//! The *independent* oracle (cryptsetup-minted fixtures + SHA256
//! manifest) lives in `tests/luks_oracle.rs` and runs in CI with real
//! fixtures; this file is the fast, always-available half.

use std::sync::Arc;

use zeroize::Zeroizing;

use winfsp_fs_skeleton::device::BlockSource;

use super::error::LuksError;
use super::header::{self, Detect};
use super::source::LuksSource;
use mint::{geometry_4096, mint, mint_kdf, Kdf, Minted, VecSource, DEFAULT_GEOMETRY};

mod mint {
    include!("tests/mint.rs");
}
/// Unlock a minted container through the real seam and hand back the
/// source, so each test compares what it cares about.
fn open(minted: &Minted) -> Result<LuksSource, LuksError> {
    let src: Arc<dyn BlockSource> = Arc::new(VecSource {
        data: minted.image.clone(),
    });
    let passphrase = Zeroizing::new(b"testpass".to_vec());
    LuksSource::open(src, 0, &passphrase)
}

#[test]
fn unlock_reads_what_was_encrypted() {
    let m = mint(DEFAULT_GEOMETRY);
    let src = open(&m).unwrap();
    assert_eq!(src.size(), m.plaintext.len() as u64);
    let mut got = vec![0u8; m.plaintext.len()];
    src.read_at(0, &mut got).unwrap();
    assert_eq!(got, m.plaintext);
}

#[test]
fn wrong_passphrase_is_a_named_refusal() {
    let m = mint(DEFAULT_GEOMETRY);
    let src: Arc<dyn BlockSource> = Arc::new(VecSource { data: m.image });
    let bad = Zeroizing::new(b"not-the-passphrase".to_vec());
    let err = LuksSource::open(src, 0, &bad).err().expect("must refuse");
    assert!(matches!(err, LuksError::WrongPassphrase), "{err}");
}

#[test]
fn a_destroyed_primary_header_recovers_through_the_secondary() {
    let mut m = mint(DEFAULT_GEOMETRY);
    m.image[..0x4000].fill(0);
    let src = open(&m).unwrap();
    let mut got = vec![0u8; m.plaintext.len()];
    src.read_at(0, &mut got).unwrap();
    assert_eq!(got, m.plaintext);
}

#[test]
fn sector_size_4096_unlocks() {
    let m = mint(geometry_4096(DEFAULT_GEOMETRY));
    let src = open(&m).unwrap();
    assert_eq!(src.size(), m.plaintext.len() as u64);
    let mut got = vec![0u8; m.plaintext.len()];
    src.read_at(0, &mut got).unwrap();
    assert_eq!(got, m.plaintext);
}

#[test]
fn argon2id_keyslot_unlocks() {
    let m = mint_kdf(DEFAULT_GEOMETRY, Kdf::Argon2id);
    let src = open(&m).unwrap();
    let mut got = vec![0u8; m.plaintext.len()];
    src.read_at(0, &mut got).unwrap();
    assert_eq!(got, m.plaintext);
}

#[test]
fn detection_reads_the_primary_magic() {
    let m = mint(DEFAULT_GEOMETRY);
    let src: Arc<dyn BlockSource> = Arc::new(VecSource { data: m.image });
    let mut reader = super::source::BlockReader::new(src, 0);
    assert_eq!(header::detect(&mut reader).unwrap(), Detect::Luks2);
}
