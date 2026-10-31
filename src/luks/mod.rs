//! LUKS2 read-only support: detection, unlock, and a decrypting
//! `BlockSource` over the encrypted payload.
//!
//! The on-disk format is the cryptsetup LUKS2 specification (binary
//! header at sector 0, JSON metadata, secondary header for recovery).
//! The unlock pipeline itself — KDF, keyslot-area decrypt, AF-merge,
//! digest verification, sector decryption — lives in the `luks-core`
//! crate (Apache-2.0, pure Rust, validated sector-for-sector against
//! cryptsetup 2.7). This module owns what that crate deliberately
//! leaves to the consumer:
//!
//! - policy: which ciphers, KDFs, segment types and keyslot types this
//!   driver will attempt, each refusal a named error, never a guess;
//! - recovery: the secondary header, when the primary is corrupt;
//! - the seam: a [`winfsp_fs_skeleton::device::BlockSource`] whose
//!   reads decrypt the segment's sectors, so the ext4 parser never
//!   learns LUKS exists.
//!
//! A LUKS volume is mounted read-only, always; `Mount::open_rw`
//! refuses a LUKS source before anything is unlocked.

#[cfg(test)]
mod tests;

pub mod error;
pub mod header;
pub mod passphrase;
pub mod source;

pub use error::LuksError;
pub use source::LuksSource;
