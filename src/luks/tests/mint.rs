// The test-only LUKS2 container mint. Shared by the unit tests
// (`super`) and the end-to-end integration test (include!).
//
// It reuses the same audited RustCrypto primitives the unlock path
// uses, in reverse, so a mint failure is a wiring failure, not a
// crypto failure. The independent cryptsetup oracle validates the
// crypto itself.

use aes::Aes256;
use sha2::{Digest, Sha256};
use xts_mode::Xts128;
use zeroize::Zeroizing;

use winfsp_fs_skeleton::device::BlockSource;

// The on-disk constants the mint writes. Same values the driver's
// header module holds; duplicated here so the mint can be included
// by an integration test without reaching into the crate's modules.
const MAGIC_1ST: [u8; 6] = [b'L', b'U', b'K', b'S', 0xba, 0xbe];
const MAGIC_2ND: [u8; 6] = [b'S', b'K', b'U', b'L', 0xba, 0xbe];
const BIN_HDR_LEN: usize = 4096;

/// An in-memory read-only block source over a byte vector.
pub struct VecSource {
    pub data: Vec<u8>,
}

impl BlockSource for VecSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        let off = offset as usize;
        let end = off
            .checked_add(buf.len())
            .ok_or_else(|| std::io::Error::other("read past end"))?;
        let Some(slice) = self.data.get(off..end) else {
            return Err(std::io::Error::other("read past end"));
        };
        buf.copy_from_slice(slice);
        Ok(())
    }
    fn size(&self) -> u64 {
        self.data.len() as u64
    }
}

/// Where the minted container keeps things.
#[derive(Clone, Copy)]
pub struct Geometry {
    hdr_size: u64,
    keyslot_area_offset: u64,
    data_offset: u64,
    sector_size: usize,
    payload_sectors: usize,
    stripes: usize,
}

pub const DEFAULT_GEOMETRY: Geometry = Geometry {
    hdr_size: 0x4000,
    keyslot_area_offset: 0x8000,
    data_offset: 16 * 1024 * 1024,
    sector_size: 512,
    payload_sectors: 32,
    stripes: 8,
    // 8 stripes keeps the AF material at 8 * key_size bytes: small
    // enough to mint fast, real enough that the merge runs.
};

pub fn geometry_4096(g: Geometry) -> Geometry {
    Geometry {
        sector_size: 4096,
        payload_sectors: 8,
        ..g
    }
}

/// A minted container and the plaintext it hides.
pub struct Minted {
    pub image: Vec<u8>,
    pub plaintext: Vec<u8>,
}

/// Round the payload length up to a whole number of sectors.
pub fn sector_pad(payload: &[u8], sector_size: usize) -> Vec<u8> {
    let pad = payload.len().next_multiple_of(sector_size);
    let mut out = payload.to_vec();
    out.resize(pad, 0);
    out
}

/// AF-split (the inverse of the merge the unlock runs): the TKS1
/// splitter from the LUKS1 spec, written forward. `stripes` blocks
/// where the last XOR-diffuses back to the key.
pub fn af_split(key: &[u8], stripes: usize) -> Vec<u8> {
    // diffuse: hash each digest-sized chunk with its big-endian
    // block index, exactly as the unlock's merge does.
    fn diffuse(data: &[u8]) -> Vec<u8> {
        let digest = 32usize; // sha256
        let mut out = vec![0u8; data.len()];
        let mut i = 0u32;
        let mut off = 0usize;
        while off < data.len() {
            let take = digest.min(data.len() - off);
            let mut h = Sha256::new();
            h.update(i.to_be_bytes());
            h.update(&data[off..off + take]);
            let d = h.finalize();
            out[off..off + take].copy_from_slice(&d[..take]);
            off += take;
            i += 1;
        }
        out
    }

    let block = key.len();
    let mut material = vec![0u8; block * stripes];
    // cryptsetup's splitter: random blocks; the last is the key XOR
    // the running diffused accumulation.
    let mut acc = vec![0u8; block];
    for s in 0..stripes - 1 {
        let chunk = &mut material[s * block..(s + 1) * block];
        // Deterministic "random": bytes from a counter, so the test is
        // reproducible. The splitter's security is not under test.
        for (i, b) in chunk.iter_mut().enumerate() {
            *b = (s as u32 * 31 + i as u32) as u8;
        }
        for (a, b) in acc.iter_mut().zip(chunk.iter()) {
            *a ^= *b;
        }
        acc = diffuse(&acc);
    }
    let last = &mut material[(stripes - 1) * block..stripes * block];
    for (l, a) in last.iter_mut().zip(acc.iter()) {
        *l = *a;
    }
    for i in 0..block {
        last[i] ^= key[i];
    }
    material
}

/// Mint a LUKS2 container with one argon2id passphrase keyslot and a
/// distinctive per-sector plaintext.
#[derive(Clone, Copy, PartialEq)]
pub enum Kdf {
    Pbkdf2,
    Argon2id,
}

pub fn mint(g: Geometry) -> Minted {
    mint_payload(g, Kdf::Pbkdf2, &default_payload(g))
}

pub fn mint_kdf(g: Geometry, kdf: Kdf) -> Minted {
    mint_payload(g, kdf, &default_payload(g))
}

/// The synthetic payload the fast tests use: one byte per sector.
pub fn default_payload(g: Geometry) -> Vec<u8> {
    (0..g.payload_sectors * g.sector_size)
        .map(|i| (i / g.sector_size) as u8)
        .collect()
}

pub fn mint_payload(g: Geometry, kdf: Kdf, raw_payload: &[u8]) -> Minted {
    mint_with_passphrase(g, kdf, raw_payload, b"testpass")
}

pub fn mint_with_passphrase(
    g: Geometry,
    kdf: Kdf,
    raw_payload: &[u8],
    passphrase_bytes: &[u8],
) -> Minted {
    let payload = sector_pad(raw_payload, g.sector_size);
    let plaintext = payload.clone();
    let master_key: [u8; 64] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));
    let passphrase: Zeroizing<Vec<u8>> = Zeroizing::new(passphrase_bytes.to_vec());

    // KDF at a fixed small cost (the test's budget, not a security
    // claim). The JSON describes whichever KDF minted the slot key.
    let kdf_salt = [0x11u8; 32];
    let slot_key = match kdf {
        Kdf::Pbkdf2 => pbkdf2_hmac_sha256(&passphrase, &kdf_salt, 100, 64),
        Kdf::Argon2id => argon2id_key(&passphrase, &kdf_salt, 64),
    };
    let digest_salt = [0x22u8; 32];
    let digest = pbkdf2_hmac_sha256(&master_key, &digest_salt, 100, 32);

    let mut image = vec![0u8; g.data_offset as usize + plaintext.len()];

    // ---- JSON metadata -------------------------------------------------
    let area_size = g.stripes * 64; // key_size 64
    let json = format!(
        r#"{{
      "keyslots":{{"0":{{"type":"luks2","key_size":64,
        "af":{{"type":"luks1","stripes":{stripes},"hash":"sha256"}},
        "area":{{"type":"raw","offset":"{area_off}","size":"{area_size}","encryption":"aes-xts-plain64","key_size":64}},
        "kdf":{kdf_json}}}}},
      "tokens":{{}},
      "segments":{{"0":{{"type":"crypt","offset":"{data_off}","size":"dynamic","iv_tweak":"0","encryption":"aes-xts-plain64","sector_size":{ss}}}}},
      "digests":{{"0":{{"type":"pbkdf2","keyslots":["0"],"segments":["0"],"hash":"sha256","iterations":100,
        "salt":"{dig_salt_b64}","digest":"{dig_b64}"}}}}}}"#,
        stripes = g.stripes,
        area_off = g.keyslot_area_offset,
        area_size = area_size,
        kdf_json = match kdf {
            Kdf::Pbkdf2 => format!(
                r#"{{"type":"pbkdf2","hash":"sha256","iterations":100,"salt":"{}"}}"#,
                b64(&kdf_salt)
            ),
            Kdf::Argon2id => format!(
                r#"{{"type":"argon2id","time":2,"memory":32,"cpus":1,"salt":"{}"}}"#,
                b64(&kdf_salt)
            ),
        },
        data_off = g.data_offset,
        ss = g.sector_size,
        dig_salt_b64 = b64(&digest_salt),
        dig_b64 = b64(&digest),
    );
    assert!(json.len() < g.hdr_size as usize - BIN_HDR_LEN);

    // ---- AF-split the master key, XTS-encrypt into the keyslot area --
    // The keyslot area uses 512-byte units with base tweak 0, exactly
    // as luks-core decrypts it (xts_decrypt_area with unit 512).
    let material = af_split(&master_key, g.stripes);
    let xts_slot = xts256(&slot_key);
    let mut area_ct = material.clone();
    let step = 1u128; // 512-byte units: step = 512/512
    for (u, chunk) in area_ct.chunks_mut(512).enumerate() {
        let tweak = (u as u128 * step).to_le_bytes();
        xts_slot.encrypt_sector(chunk, tweak);
    }
    let off = g.keyslot_area_offset as usize;
    image[off..off + area_ct.len()].copy_from_slice(&area_ct);

    // ---- Plaintext payload, XTS-encrypted per segment sector ---------
    // The payload (here: a whole ext4 image) is encrypted with the
    // MASTER key, at the segment's sector size, tweak = sector
    // index * (ss/512).
    let plaintext: Vec<u8> = payload;
    let xts_data = xts256(master_key.as_ref());
    let step_d = (g.sector_size / 512) as u128;
    let mut encrypted = plaintext.clone();
    for (u, chunk) in encrypted.chunks_mut(g.sector_size).enumerate() {
        let tweak = ((u as u128) * step_d).to_le_bytes();
        xts_data.encrypt_sector(chunk, tweak);
    }
    let base = g.data_offset as usize;
    image[base..base + encrypted.len()].copy_from_slice(&encrypted);

    // ---- Headers (primary + secondary), with checksums ----------------
    write_header(&mut image, &json, 0, MAGIC_1ST, g);
    write_header(&mut image, &json, g.hdr_size, MAGIC_2ND, g);

    Minted { image, plaintext }
}

// -- helpers ---------------------------------------------------------------

pub fn xts256(key: &[u8]) -> Xts128<Aes256> {
    // Same split luks-core decrypts with: first half for cipher_1
    // (data), second half for cipher_2 (tweak).
    let (k1, k2) = key.split_at(32);
    Xts128::<Aes256>::new(
        aes::cipher::KeyInit::new(aes::cipher::generic_array::GenericArray::from_slice(k1)),
        aes::cipher::KeyInit::new(aes::cipher::generic_array::GenericArray::from_slice(k2)),
    )
}

pub fn b64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub fn argon2id_key(password: &[u8], salt: &[u8], len: usize) -> Vec<u8> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(32, 2, 1, Some(len)).expect("test params");
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = vec![0u8; len];
    argon
        .hash_password_into(password, salt, &mut out)
        .expect("argon2id derives");
    out
}

pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], rounds: u32, len: usize) -> Vec<u8> {
    // The same RustCrypto pbkdf2 the unlock uses, via luks-core's
    // dependency: pulled through the normal dependency graph.
    use pbkdf2::pbkdf2_hmac;
    let mut out = vec![0u8; len];
    pbkdf2_hmac::<Sha256>(password, salt, rounds, &mut out);
    out
}

/// Write one header (binary + JSON + checksum) at `base`.
pub fn write_header(image: &mut [u8], json: &str, base: u64, magic: [u8; 6], g: Geometry) {
    let hdr_size = g.hdr_size as usize;
    let b = base as usize;
    image[b..b + 6].copy_from_slice(&magic);
    image[b + 6..b + 8].copy_from_slice(&2u16.to_be_bytes());
    image[b + 8..b + 16].copy_from_slice(&(hdr_size as u64).to_be_bytes());
    image[b + 16..b + 24].copy_from_slice(&1u64.to_be_bytes()); // seqid
    image[b + 72..b + 78].copy_from_slice(b"sha256");
    image[b + 256..b + 264].copy_from_slice(&base.to_be_bytes()); // hdr_offset
    let j = b + BIN_HDR_LEN;
    image[j..j + json.len()].copy_from_slice(json.as_bytes());

    let mut hasher = Sha256::new();
    hasher.update(&image[b..b + 448]);
    hasher.update([0u8; 64]);
    hasher.update(&image[b + 512..b + hdr_size]);
    let csum = hasher.finalize();
    image[b + 448..b + 480].copy_from_slice(&csum);
}


/// The end-to-end container build: a whole plaintext payload (a real
/// ext4 image) encrypted with an explicit passphrase, at 512-byte
/// sectors. Used by tests/luks_ext4_e2e.rs.
#[allow(dead_code)]
pub fn mint_container_with_passphrase(payload: &[u8], passphrase: &[u8]) -> Vec<u8> {
    let g = DEFAULT_GEOMETRY;
    mint_with_passphrase(g, Kdf::Pbkdf2, payload, passphrase).image
}
