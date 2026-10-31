//! LUKS2 header detection, binary-header parsing and this driver's
//! format policy, on top of [`luks_core`]'s parsed metadata.
//!
//! [`luks_core`] reads the bytes; this module decides what this driver
//! is willing to attempt, and refuses everything else with a named
//! error. All inputs are untrusted: no panics, no unwraps, and every
//! read is bounds-checked.
//!
//! The secondary header is the recovery path when the primary is
//! corrupt: the LUKS2 spec places it at one of a fixed set of offsets
//! (0x4000 .. 0x400000), mirrored (`SKUL\xba\xbe` magic) with its own
//! checksum. Nothing is ever written back — recovery here means
//! *reading* the backup copy, not repairing the device.

use std::io::{Read, Seek, SeekFrom};

use luks::{Luks2Header, Luks2Kdf, Luks2Keyslot, Luks2Segment};

use super::error::LuksError;

/// `LUKS\xba\xbe` — LUKS magic, primary header.
pub(crate) const MAGIC_1ST: [u8; 6] = [b'L', b'U', b'K', b'S', 0xba, 0xbe];
/// `SKUL\xba\xbe` — LUKS magic, secondary (backup) header.
pub(crate) const MAGIC_2ND: [u8; 6] = [b'S', b'K', b'U', b'L', 0xba, 0xbe];

/// The binary header occupies one 4096-byte sector (512 used).
pub(crate) const BIN_HDR_LEN: usize = 4096;

/// Byte offsets of the fields of the spec's `luks2_hdr_disk` struct,
/// in the binary header sector. The struct is packed and
/// big-endian; the offsets are the running sums of its members:
/// magic 6, version 2, hdr_size 8, seqid 8, label 48, csum_alg 32,
/// salt 64, uuid 40, subsystem 48, hdr_offset 8, _padding 184,
/// csum 64 — filling the 512 used bytes of the 4096-byte sector.
///
/// The table mirrors the whole struct so the layout reads in one
/// place; production reads a subset of the fields and the fixtures
/// write more of them, so the not-yet-read constants are allowed to
/// sit.
#[allow(dead_code)]
mod spec {
    pub const MAGIC_OFF: usize = 0;
    pub const MAGIC_LEN: usize = 6;
    pub const VERSION_OFF: usize = 6;
    pub const HDR_SIZE_OFF: usize = 8;
    pub const SEQID_OFF: usize = 16;
    pub const LABEL_OFF: usize = 24;
    pub const LABEL_LEN: usize = 48;
    pub const CSUM_ALG_OFF: usize = 72;
    pub const SALT_OFF: usize = 104;
    pub const UUID_OFF: usize = 168;
    pub const SUBSYSTEM_OFF: usize = 208;
    pub const HDR_OFFSET_OFF: usize = 256;
    pub const PADDING_OFF: usize = 264;
    pub const PADDING_LEN: usize = 184;
    pub const CSUM_OFF: usize = 448;
    pub const CSUM_LEN: usize = 64;
    /// The used bytes of the binary header's 4096-byte sector.
    pub const BIN_USED_LEN: usize = 512;
}

/// The fixed offsets the LUKS2 spec allows for the secondary header
/// (its Table 1: 16 KiB .. 4 MiB, one row each power of two). The
/// primary header's `hdr_size` names which one is in use.
const SECONDARY_OFFSETS: [u64; 9] = [
    0x4000, 0x8000, 0x10000, 0x20000, 0x40000, 0x80000, 0x100000, 0x200000, 0x400000,
];

/// Big-endian u64 at `off`, or 0 past the end. Never panics.
fn be_u64(data: &[u8], off: usize) -> u64 {
    data.get(off..off + 8)
        .map(|s| u64::from_be_bytes(s.try_into().unwrap_or([0; 8])))
        .unwrap_or(0)
}

/// The first 6 bytes of `bytes` against the LUKS magics. This is the
/// auto-detect predicate: a device or partition slice whose first
/// bytes carry either magic is treated as LUKS.
pub fn is_luks(bytes: &[u8]) -> bool {
    bytes.get(..6) == Some(&MAGIC_1ST[..]) || bytes.get(..6) == Some(&MAGIC_2ND[..])
}

/// What the first bytes say the volume is, for the CLI's detection
/// line and error messages. Examines the primary header's magic and
/// version only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detect {
    /// LUKS1: refused, with a clear message.
    Luks1,
    /// LUKS2: proceed to unlock.
    Luks2,
    /// No LUKS magic at all.
    NotLuks,
}

/// Read the first 512 bytes of the volume and say what they carry.
pub fn detect<R: Read + Seek>(reader: &mut R) -> std::io::Result<Detect> {
    let mut first = [0u8; 512];
    reader.seek(SeekFrom::Start(0))?;
    // A target smaller than 512 bytes cannot carry a LUKS2 header;
    // read_exact's UnexpectedEof names that cleanly.
    reader.read_exact(&mut first)?;
    let bytes = &first;
    if bytes.get(..6) == Some(&MAGIC_1ST[..]) || bytes.get(..6) == Some(&MAGIC_2ND[..]) {
        let version = u16::from_be_bytes(
            bytes
                .get(6..8)
                .and_then(|s| s.try_into().ok())
                .unwrap_or([0; 2]),
        );
        return Ok(match version {
            1 => Detect::Luks1,
            2 => Detect::Luks2,
            _ => Detect::NotLuks,
        });
    }
    Ok(Detect::NotLuks)
}

/// Facts about a LUKS2 volume the CLI can print without unlocking:
/// the detection line's cipher and sector size, taken from the crypt
/// segment after policy validation.
#[derive(Debug, Clone)]
pub struct VolumeFacts {
    /// The segment's `encryption` string, e.g. `aes-xts-plain64`.
    pub encryption: String,
    /// The segment's `sector_size` (512 or 4096).
    pub sector_size: u64,
    /// The data segment's byte offset (where ciphertext starts).
    pub data_offset: u64,
}

/// A policy-validated LUKS2 header: the parsed metadata plus the
/// crypt segment this driver will decrypt.
#[derive(Debug)]
pub struct HeaderPolicy {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) header: Luks2Header,
    pub(crate) segment: Luks2Segment,
    /// The byte offset this header's bytes were read at (0 for the
    /// primary, one of [`SECONDARY_OFFSETS`] for the backup). Used to
    /// locate the keyslot areas relative to the *device*, not the
    /// header.
    pub(crate) base_offset: u64,
}

impl HeaderPolicy {
    /// The header area this policy validated, re-read from the
    /// device at this header's base offset. Serves the unlock as its
    /// offset-0 header copy (magic-fixed there) so the metadata the
    /// unlock re-reads is the metadata that was validated.
    pub(crate) fn area_bytes<R: Read + Seek>(&self, reader: &mut R) -> std::io::Result<Vec<u8>> {
        read_header_area(reader, self.base_offset)
    }

    /// Facts for the detection line, before any unlock.
    pub fn facts(&self) -> VolumeFacts {
        VolumeFacts {
            encryption: self.segment.encryption.clone(),
            sector_size: self.segment.sector_size as u64,
            data_offset: self.segment.offset,
        }
    }

    /// The passphrase-capable keyslots this driver will attempt, in
    /// header order: `type == "luks2"` with a passphrase KDF. TPM,
    /// FIDO2, PKCS#11 and other token keyslots are simply not in this
    /// list — they are ignored, never refused, so a volume that also
    /// carries a passphrase slot still opens.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn passphrase_slots(&self) -> Vec<&Luks2Keyslot> {
        self.header
            .keyslots
            .iter()
            .filter(|k| matches!(k.kdf, Luks2Kdf::Pbkdf2 { .. } | Luks2Kdf::Argon2 { .. }))
            .collect()
    }
}

/// Read exactly `len` bytes at `offset`, or an I/O error naming the
/// shortfall.
fn read_at<R: Read + Seek>(reader: &mut R, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    reader.seek(SeekFrom::Start(offset))?;
    reader.read_exact(&mut buf).map_err(|e| {
        std::io::Error::new(e.kind(), format!("short read at offset {offset}: {e}"))
    })?;
    Ok(buf)
}

/// The header area (binary header + JSON) one of the two headers
/// occupies: `hdr_size` bytes starting at `base`.
fn read_header_area<R: Read + Seek>(reader: &mut R, base: u64) -> std::io::Result<Vec<u8>> {
    let bin = read_at(reader, base, spec::BIN_USED_LEN)?;
    let hdr_size = be_u64(&bin, spec::HDR_SIZE_OFF);
    if !(BIN_HDR_LEN as u64..=0x400000).contains(&hdr_size) || !hdr_size.is_multiple_of(4096) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("implausible hdr_size {hdr_size} at offset {base}"),
        ));
    }
    let mut area = read_at(reader, base, hdr_size as usize)?;
    area[..spec::BIN_USED_LEN].copy_from_slice(&bin);
    Ok(area)
}

/// Verify a header area's SHA-256 checksum the way the spec defines
/// it: over the binary header with the `csum` field zeroed (offset
/// 512..576 in the sector) concatenated with the JSON area. This is a
/// digest comparison using `sha2` — no crypto of ours.
fn checksum_matches(area: &[u8]) -> bool {
    use sha2::{Digest, Sha256};
    let Some(stored) = area.get(spec::CSUM_OFF..spec::CSUM_OFF + spec::CSUM_LEN) else {
        return false;
    };
    let mut hasher = Sha256::new();
    hasher.update(&area[..spec::CSUM_OFF]);
    hasher.update([0u8; spec::CSUM_LEN]);
    // The rest of the binary sector (padding past the checksum) plus
    // the JSON area are all covered too.
    hasher.update(&area[spec::CSUM_OFF + spec::CSUM_LEN..]);
    let computed = hasher.finalize();
    stored[..32] == computed[..]
}

/// Validate one header area's metadata against this driver's policy.
/// Every refusal is a named [`LuksError`]; nothing is guessed.
fn validate(area: &mut [u8], base: u64) -> Result<HeaderPolicy, LuksError> {
    // The secondary header carries the mirrored SKUL magic, which the
    // parser (rightly) does not accept: rewrite it to the primary
    // magic in the in-memory copy the parser and the unlock read.
    if area.get(..6) == Some(&MAGIC_2ND[..]) {
        area[..6].copy_from_slice(&MAGIC_1ST);
    }
    let header = Luks2Header::parse(area).map_err(|e| LuksError::CorruptHeader {
        detail: e.to_string(),
    })?;

    // Exactly the segments this driver understands: `crypt`, encrypted
    // aes-xts-plain64, without integrity protection. A reencryption
    // segment (type "reencrypt") or an offline-reencryption segment is
    // refused: those volumes are mid-rewrite, not ours to read.
    let segment = header
        .crypt_segment()
        .cloned()
        .ok_or(LuksError::Unsupported {
            what: "segment layout",
            found: "no crypt segment".into(),
        })?;
    if segment.encryption != "aes-xts-plain64" {
        return Err(LuksError::Unsupported {
            what: "segment encryption",
            found: segment.encryption.clone(),
        });
    }
    if !matches!(segment.sector_size, 512 | 4096) {
        return Err(LuksError::Unsupported {
            what: "sector size",
            found: segment.sector_size.to_string(),
        });
    }
    // The `integrity` object inside the crypt segment is what the JSON
    // metadata calls the dm-integrity configuration; `luks-core`'s
    // segment struct has no such field, so re-read the raw JSON to
    // refuse it explicitly rather than silently dropping it.
    if segment_json_has_integrity(area) {
        return Err(LuksError::IntegrityUnsupported);
    }

    if header.keyslots.is_empty() {
        return Err(LuksError::NoPassphraseKeyslot);
    }

    Ok(HeaderPolicy {
        header,
        segment,
        base_offset: base,
    })
}

/// Does the JSON area's first crypt segment carry an `integrity`
/// object? Parses just enough of the raw JSON to look; any parse
/// failure counts as "absent" because [`Luks2Header::parse`] has
/// already validated the JSON as a whole.
fn segment_json_has_integrity(area: &[u8]) -> bool {
    let Some(json_start) = area.get(BIN_HDR_LEN..) else {
        return false;
    };
    let json_end = json_start
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(json_start.len());
    let Ok(root) = serde_json::from_slice::<serde_json::Value>(&json_start[..json_end]) else {
        return false;
    };
    root.get("segments")
        .and_then(|s| s.as_object())
        .map(|segs| segs.values().any(|s| s.get("integrity").is_some()))
        .unwrap_or(false)
}

/// Read and validate the primary header; on any corruption, fall back
/// to the secondary header at the offset the primary's `hdr_size`
/// names (and, if that fails, each fixed spec offset in turn).
///
/// The primary header's own `hdr_size` is read from the first 512
/// bytes even when the rest of the primary area is unreadable, so the
/// backup is looked up exactly where this volume keeps it.
pub fn read_header<R: Read + Seek>(reader: &mut R) -> Result<HeaderPolicy, LuksError> {
    // Primary first, checksum and all.
    if let Ok(mut area) = read_header_area(reader, 0) {
        if checksum_matches(&area) {
            // Policy refusals are about the *volume*, not the header
            // copy: a backup header carries the same metadata, so
            // retrying it cannot help. Propagate the refusal.
            return validate(&mut area, 0);
        }
    }

    // The primary is unusable. Where its hdr_size says the backup
    // lives — read from the first 512 bytes, which may still be
    // intact even when the JSON area is not — then every fixed
    // offset the spec allows.
    let mut candidates: Vec<u64> = Vec::new();
    if let Ok(bin) = read_at(reader, 0, spec::BIN_USED_LEN) {
        let hdr_size = be_u64(&bin, spec::HDR_SIZE_OFF);
        if (BIN_HDR_LEN as u64..=0x400000).contains(&hdr_size) && hdr_size.is_multiple_of(4096) {
            candidates.push(hdr_size);
        }
    }
    for off in SECONDARY_OFFSETS {
        if !candidates.contains(&off) {
            candidates.push(off);
        }
    }

    let mut last_detail = String::from("no readable header copy found");
    for base in candidates {
        let mut area = match read_header_area(reader, base) {
            Ok(a) => a,
            Err(e) => {
                last_detail = format!("secondary header at offset {base}: {e}");
                continue;
            }
        };
        // The backup header's magic is SKUL, not LUKS; the parse takes
        // either. hdr_offset inside it must name its own base.
        if be_u64(&area, spec::HDR_OFFSET_OFF) != base {
            last_detail = format!(
                "secondary header at offset {base} claims offset {}",
                be_u64(&area, spec::HDR_OFFSET_OFF)
            );
            continue;
        }
        if !checksum_matches(&area) {
            last_detail = format!("secondary header at offset {base} fails its checksum");
            continue;
        }
        return validate(&mut area, base);
    }
    Err(LuksError::CorruptHeader {
        detail: last_detail,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal valid LUKS2 header area: binary header with correct
    /// magic/version/hdr_size and a checksum, over JSON with one
    /// argon2id keyslot and one aes-xts-plain64 512-byte crypt
    /// segment. Modelled on the on-disk spec's own example.
    fn build_area(json: &str, base: u64, magic: [u8; 6]) -> Vec<u8> {
        let hdr_size = 0x4000u64;
        let mut area = vec![0u8; hdr_size as usize];
        use super::spec;
        area[spec::MAGIC_OFF..spec::MAGIC_OFF + spec::MAGIC_LEN].copy_from_slice(&magic);
        area[spec::VERSION_OFF..spec::VERSION_OFF + 2].copy_from_slice(&2u16.to_be_bytes());
        area[spec::HDR_SIZE_OFF..spec::HDR_SIZE_OFF + 8].copy_from_slice(&hdr_size.to_be_bytes());
        area[spec::SEQID_OFF..spec::SEQID_OFF + 8].copy_from_slice(&1u64.to_be_bytes());
        area[spec::CSUM_ALG_OFF..spec::CSUM_ALG_OFF + 6].copy_from_slice(b"sha256");
        area[spec::UUID_OFF..spec::UUID_OFF + 36]
            .copy_from_slice(b"12345678-1234-1234-1234-123456789012");
        area[spec::HDR_OFFSET_OFF..spec::HDR_OFFSET_OFF + 8].copy_from_slice(&base.to_be_bytes());
        area[BIN_HDR_LEN..BIN_HDR_LEN + json.len()].copy_from_slice(json.as_bytes());
        // Checksum over everything with csum zeroed.
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&area[..spec::CSUM_OFF]);
        hasher.update([0u8; spec::CSUM_LEN]);
        hasher.update(&area[spec::BIN_USED_LEN..]);
        let csum = hasher.finalize();
        area[spec::CSUM_OFF..spec::CSUM_OFF + 32].copy_from_slice(&csum);
        area
    }

    const JSON_512: &str = r#"{
      "keyslots":{"0":{"type":"luks2","key_size":64,
        "af":{"type":"luks1","stripes":4000,"hash":"sha256"},
        "area":{"type":"raw","offset":"32768","size":"258048","encryption":"aes-xts-plain64","key_size":64},
        "kdf":{"type":"argon2id","time":4,"memory":32,"cpus":1,"salt":"pUcL4RKUCh+iGgNoo6PW95eKTZm6RsS4Ds7Kn4gCdVs="}}},
      "segments":{"0":{"type":"crypt","offset":"16777216","size":"dynamic","iv_tweak":"0","encryption":"aes-xts-plain64","sector_size":512}},
      "digests":{"0":{"type":"pbkdf2","keyslots":["0"],"segments":["0"],"hash":"sha256","iterations":1000,
        "salt":"IUaJeXA4vB2CruGetgh6GOlfgvB2WoD2UzWGb2K6KLc=","digest":"yqVonIxK8BFwHFIsUaacNsXcz65r6EnYBVgF2fDPgps="}}}"#;

    #[test]
    fn detects_luks2() {
        let area = build_area(JSON_512, 0, MAGIC_1ST);
        let mut c = std::io::Cursor::new(area);
        assert_eq!(detect(&mut c).unwrap(), Detect::Luks2);
    }

    #[test]
    fn detects_luks1() {
        let mut buf = vec![0u8; 512];
        buf[..spec::MAGIC_LEN].copy_from_slice(&MAGIC_1ST);
        buf[spec::VERSION_OFF..spec::VERSION_OFF + 2].copy_from_slice(&1u16.to_be_bytes());
        let mut c = std::io::Cursor::new(buf);
        assert_eq!(detect(&mut c).unwrap(), Detect::Luks1);
    }

    #[test]
    fn detects_not_luks() {
        let mut c = std::io::Cursor::new(vec![0u8; 512]);
        assert_eq!(detect(&mut c).unwrap(), Detect::NotLuks);
    }

    #[test]
    fn validates_a_default_volume() {
        let area = build_area(JSON_512, 0, MAGIC_1ST);
        let mut c = std::io::Cursor::new(area);
        let p = read_header(&mut c).unwrap();
        assert_eq!(p.facts().encryption, "aes-xts-plain64");
        assert_eq!(p.facts().sector_size, 512);
        assert_eq!(p.passphrase_slots().len(), 1);
    }

    #[test]
    fn refuses_unknown_segment_encryption() {
        let json = JSON_512.replace("aes-xts-plain64", "aes-cbc-essiv:sha256");
        let area = build_area(&json, 0, MAGIC_1ST);
        let mut c = std::io::Cursor::new(area);
        assert!(matches!(
            read_header(&mut c),
            Err(LuksError::Unsupported {
                what: "segment encryption",
                ..
            })
        ));
    }

    #[test]
    fn refuses_integrity_segment() {
        let json = JSON_512.replace(
            "\"sector_size\":512",
            "\"sector_size\":512,\"integrity\":{\"type\":\"hmac(sha256)\",\"journal_integrity\":\"none\",\"journal_encryption\":\"none\",\"key_size\":32}",
        );
        let area = build_area(&json, 0, MAGIC_1ST);
        let mut c = std::io::Cursor::new(area);
        assert!(matches!(
            read_header(&mut c),
            Err(LuksError::IntegrityUnsupported)
        ));
    }

    #[test]
    fn refuses_1024_byte_sectors() {
        let json = JSON_512.replace("\"sector_size\":512", "\"sector_size\":1024");
        let area = build_area(&json, 0, MAGIC_1ST);
        let mut c = std::io::Cursor::new(area);
        assert!(matches!(
            read_header(&mut c),
            Err(LuksError::Unsupported {
                what: "sector size",
                ..
            })
        ));
    }

    #[test]
    fn recovers_through_the_secondary_header() {
        // A volume whose primary area is zeroed, with a valid
        // secondary header at 0x4000 (the hdr_size of both).
        let mut vol = vec![0u8; 0x8000];
        let sec = build_area(JSON_512, 0x4000, MAGIC_2ND);
        vol[0x4000..0x8000].copy_from_slice(&sec);
        let mut c = std::io::Cursor::new(vol);
        let p = read_header(&mut c).unwrap();
        assert_eq!(p.base_offset, 0x4000);
        assert_eq!(p.facts().encryption, "aes-xts-plain64");
    }

    #[test]
    fn corrupt_primary_and_secondary_is_a_named_error() {
        let mut c = std::io::Cursor::new(vec![0u8; 0x8000]);
        assert!(matches!(
            read_header(&mut c),
            Err(LuksError::CorruptHeader { .. })
        ));
    }

    #[test]
    fn a_checksum_failure_in_the_primary_falls_back() {
        let mut area = build_area(JSON_512, 0, MAGIC_1ST);
        area[40] ^= 0xff; // corrupt inside the JSON area
        let mut vol = vec![0u8; 0x8000];
        vol[..0x4000].copy_from_slice(&area);
        let sec = build_area(JSON_512, 0x4000, MAGIC_2ND);
        vol[0x4000..0x8000].copy_from_slice(&sec);
        let mut c = std::io::Cursor::new(vol);
        let p = read_header(&mut c).unwrap();
        assert_eq!(p.base_offset, 0x4000);
    }

    #[test]
    fn token_keyslots_are_ignored_not_refused() {
        // A volume whose only passphrase slot sits beside a token
        // slot: the token is skipped by `luks-core`'s parser (unknown
        // keyslot kdf type), and the passphrase slot still counts.
        let json = r#"{
      "keyslots":{
        "0":{"type":"luks2","key_size":64,
          "af":{"type":"luks1","stripes":4000,"hash":"sha256"},
          "area":{"type":"raw","offset":"32768","size":"258048","encryption":"aes-xts-plain64","key_size":64},
          "kdf":{"type":"argon2id","time":4,"memory":32,"cpus":1,"salt":"pUcL4RKUCh+iGgNoo6PW95eKTZm6RsS4Ds7Kn4gCdVs="}},
        "1":{"type":"reencrypt","key_size":32}},
      "segments":{"0":{"type":"crypt","offset":"16777216","size":"dynamic","iv_tweak":"0","encryption":"aes-xts-plain64","sector_size":512}},
      "digests":{"0":{"type":"pbkdf2","keyslots":["0"],"segments":["0"],"hash":"sha256","iterations":1000,
        "salt":"IUaJeXA4vB2CruGetgh6GOlfgvB2WoD2UzWGb2K6KLc=","digest":"yqVonIxK8BFwHFIsUaacNsXcz65r6EnYBVgF2fDPgps="}}}"#;
        let area = build_area(json, 0, MAGIC_1ST);
        let mut c = std::io::Cursor::new(area);
        let p = read_header(&mut c).unwrap();
        assert_eq!(p.passphrase_slots().len(), 1);
    }

    #[test]
    fn a_pbkdf2_keyslot_volume_validates() {
        let json = r#"{
      "keyslots":{"0":{"type":"luks2","key_size":64,
        "af":{"type":"luks1","stripes":4000,"hash":"sha256"},
        "area":{"type":"raw","offset":"32768","size":"258048","encryption":"aes-xts-plain64","key_size":64},
        "kdf":{"type":"pbkdf2","hash":"sha256","iterations":1000,"salt":"pUcL4RKUCh+iGgNoo6PW95eKTZm6RsS4Ds7Kn4gCdVs="}}},
      "segments":{"0":{"type":"crypt","offset":"16777216","size":"dynamic","iv_tweak":"0","encryption":"aes-xts-plain64","sector_size":4096}},
      "digests":{"0":{"type":"pbkdf2","keyslots":["0"],"segments":["0"],"hash":"sha256","iterations":1000,
        "salt":"IUaJeXA4vB2CruGetgh6GOlfgvB2WoD2UzWGb2K6KLc=","digest":"yqVonIxK8BFwHFIsUaacNsXcz65r6EnYBVgF2fDPgps="}}}"#;
        let area = build_area(json, 0, MAGIC_1ST);
        let mut c = std::io::Cursor::new(area);
        let p = read_header(&mut c).unwrap();
        assert_eq!(p.facts().sector_size, 4096);
    }
}
