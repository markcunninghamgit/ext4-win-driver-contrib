//! The decrypting seam: turn a LUKS2 container into a
//! [`BlockSource`] whose reads return plaintext sectors.
//!
//! ext4 sees only this source; it never learns LUKS exists. All
//! crypto is [`luks_core`]'s (RustCrypto underneath): this module only
//! wires it, and refuses formats the policy in [`super::header`]
//! does not accept.
//!
//! ## Secondary-header recovery and the fixup reader
//!
//! [`luks_core`]'s unlock reads the header from offset 0, but when the
//! primary header is corrupt the valid copy lives at a nonzero offset
//! (and carries the mirrored `SKUL\xba\xbe` magic). The unlock is
//! therefore handed a [`FixupReader`]: a `Read + Seek` view whose
//! first `hdr_size` bytes are the *chosen* header copy, rewritten to
//! the primary magic, while every read past it — keyslot areas, the
//! data segment — goes to the device at its real offsets. Nothing is
//! written back; the rewrite happens in the in-memory copy only.

use std::io::{Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex};

use zeroize::Zeroizing;

use winfsp_fs_skeleton::device::BlockSource;

use super::error::LuksError;
use super::header::{self, HeaderPolicy, MAGIC_1ST};

/// A `Read + Seek` over a [`BlockSource`] at a fixed base offset,
/// tracking position itself. The BlockSource is `&self`-shared, so
/// reads through clones of this reader stay coherent.
pub(crate) struct BlockReader {
    src: Arc<dyn BlockSource>,
    base: u64,
    pos: u64,
}

impl BlockReader {
    pub(crate) fn new(src: Arc<dyn BlockSource>, base: u64) -> Self {
        Self { src, base, pos: 0 }
    }
}

impl Read for BlockReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let pos = self.base.checked_add(self.pos).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "read past device end")
        })?;
        self.src.read_at(pos, buf)?;
        let n = buf.len() as u64;
        self.pos += n;
        Ok(buf.len())
    }
}

impl Seek for BlockReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let size = self.src.size().saturating_sub(self.base);
        self.pos = match pos {
            SeekFrom::Start(p) => p,
            SeekFrom::Current(d) => self.pos.checked_add_signed(d).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "seek before start")
            })?,
            SeekFrom::End(d) => size.checked_add_signed(d).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "seek before start")
            })?,
        };
        Ok(self.pos)
    }
}

/// Serves the header area from an in-memory (magic-fixed) copy and
/// delegates everything past it to the inner reader.
struct FixupReader<R: Read + Seek> {
    inner: R,
    header: Vec<u8>,
    pos: u64,
}

impl<R: Read + Seek> FixupReader<R> {
    fn new(inner: R, mut header: Vec<u8>) -> Self {
        // The chosen copy may be the secondary header (SKUL magic);
        // the unlock parses it at offset 0 as a primary.
        if header.len() >= 6 {
            header[..6].copy_from_slice(&MAGIC_1ST);
        }
        Self {
            inner,
            header,
            pos: 0,
        }
    }
}

impl<R: Read + Seek> Read for FixupReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let hdr_len = self.header.len() as u64;
        if self.pos >= hdr_len {
            // Past the header area: the device at the same offset,
            // because the in-memory copy is exactly as long as the
            // area it stands in for.
            self.inner.seek(SeekFrom::Start(self.pos))?;
            let n = self.inner.read(buf)?;
            self.pos += n as u64;
            return Ok(n);
        }
        // Inside the header area (a read can straddle its end).
        let start = self.pos as usize;
        let take = buf.len().min(self.header.len().saturating_sub(start));
        if let Some(slice) = self.header.get(start..start + take) {
            buf[..take].copy_from_slice(slice);
        }
        self.pos += take as u64;
        if take == buf.len() {
            return Ok(take);
        }
        let n = self.read(&mut buf[take..])?;
        Ok(take + n)
    }
}

impl<R: Read + Seek> Seek for FixupReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match pos {
            SeekFrom::Start(p) => self.pos = p,
            SeekFrom::Current(d) => {
                self.pos = self.pos.checked_add_signed(d).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "seek before start")
                })?;
            }
            SeekFrom::End(d) => {
                // The virtual stream is the in-memory header area plus
                // the device past it, so its end is the device's end.
                let end = self.inner.seek(SeekFrom::End(0))?;
                self.pos = end.checked_add_signed(d).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "seek before start")
                })?;
            }
        }
        Ok(self.pos)
    }
}

/// A decrypted LUKS2 payload as a read-only [`BlockSource`]. The
/// unlock holds the volume key; every `read_at` decrypts whole
/// sectors. `size` is the plaintext payload size.
pub struct LuksSource {
    payload: Mutex<luks::DecryptedPayload<Box<dyn ReadSeekSend>>>,
    size: u64,
}

/// Object-safe `Read + Seek + Send` the payload can own.
trait ReadSeekSend: Read + Seek + Send {}
impl<T: Read + Seek + Send> ReadSeekSend for T {}

impl LuksSource {
    /// Detection: do the first bytes of the slice at `base` carry a
    /// LUKS magic?
    pub fn detect_at(src: &dyn BlockSource, base: u64) -> std::io::Result<bool> {
        let mut first = [0u8; 512];
        src.read_at(base, &mut first)?;
        Ok(header::is_luks(&first))
    }

    /// Detect, read and policy-validate the header, unlock with
    /// `passphrase`, and return the decrypting source.
    ///
    /// # Errors
    /// Every refusal is a named [`LuksError`]: LUKS1, unsupported
    /// cipher or integrity, corrupt header, no passphrase keyslot,
    /// wrong passphrase, or I/O failure.
    pub fn open(
        src: Arc<dyn BlockSource>,
        base: u64,
        passphrase: &Zeroizing<Vec<u8>>,
    ) -> Result<Self, LuksError> {
        let mut reader = BlockReader::new(Arc::clone(&src), base);
        let policy: HeaderPolicy = header::read_header(&mut reader)?;
        let facts = policy.facts();

        // The header copy the policy chose, re-read and magic-fixed,
        // served at offset 0 so the unlock re-reads the same metadata
        // it validated.
        let area = policy.area_bytes(&mut reader)?;
        let fixup = FixupReader::new(reader, area);

        let boxed = Box::new(fixup) as Box<dyn ReadSeekSend>;
        let payload = luks::LuksVolume::unlock2_with_passphrase(boxed, passphrase)
            .map_err(map_unlock_error)?;
        let size = payload.payload_size();
        let need = facts.data_offset;
        let have = src.size().saturating_sub(base);
        if need > have {
            return Err(LuksError::TruncatedVolume { need, have });
        }
        Ok(Self {
            payload: Mutex::new(payload),
            size,
        })
    }
}

/// Translate [`luks`] unlock failures into this module's named errors.
/// Anything the policy already refused surfaces as that refusal; a
/// failed digest check is a wrong passphrase.
fn map_unlock_error(e: luks::LuksError) -> LuksError {
    match e {
        luks::LuksError::AuthenticationFailed => LuksError::WrongPassphrase,
        luks::LuksError::NoActiveKeyslot => LuksError::NoPassphraseKeyslot,
        other => LuksError::CorruptHeader {
            detail: other.to_string(),
        },
    }
}

impl BlockSource for LuksSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
        if offset
            .checked_add(buf.len() as u64)
            .is_none_or(|end| end > self.size)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "read past end of LUKS payload: {offset}+{} > {}",
                    buf.len(),
                    self.size
                ),
            ));
        }
        let mut payload = self
            .payload
            .lock()
            .map_err(|_| std::io::Error::other("payload lock poisoned"))?;
        payload
            .read_at(offset, buf)
            .map_err(|e| std::io::Error::other(format!("decrypt: {e}")))
    }

    fn size(&self) -> u64 {
        self.size
    }
}
