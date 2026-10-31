//! Named errors for every way a LUKS volume can be refused.
//!
//! Each variant names what was seen and (where relevant) what this
//! driver supports, so the CLI can print a non-technical message
//! without re-parsing anything. Nothing here guesses: an unknown
//! value is refused, never interpreted as a default.

use std::fmt;

/// One clear refusal for one clear reason.
#[derive(Debug)]
pub enum LuksError {
    /// LUKS1. Deliberately unsupported: this driver opens LUKS2 only.
    Luks1Unsupported,
    /// Neither the primary nor the secondary header survived.
    CorruptHeader { detail: String },
    /// A header parsed but violated this driver's format policy.
    Unsupported { what: &'static str, found: String },
    /// A segment carries data-integrity protection (dm-integrity),
    /// which this driver does not implement.
    IntegrityUnsupported,
    /// No keyslot this driver can attempt (no `luks2`-type slot with
    /// a passphrase KDF).
    NoPassphraseKeyslot,
    /// Every passphrase-capable keyslot was tried; none verified
    /// against the digest. The passphrase was wrong (or the volume
    /// uses a token we do not attempt).
    WrongPassphrase,
    /// The encrypted payload is shorter than the segment claims.
    TruncatedVolume { need: u64, have: u64 },
    /// Reading the underlying device or image failed.
    Io(std::io::Error),
}

impl fmt::Display for LuksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Luks1Unsupported => write!(
                f,
                "this disk uses LUKS1, an older encryption format this \
                 tool cannot open (LUKS2 only)"
            ),
            Self::CorruptHeader { detail } => write!(
                f,
                "the LUKS2 header is damaged and its backup copy could \
                 not be read either: {detail}"
            ),
            Self::Unsupported { what, found } => write!(
                f,
                "the LUKS2 volume uses {what} {found:?}, which this tool \
                 does not support"
            ),
            Self::IntegrityUnsupported => write!(
                f,
                "this LUKS2 volume uses data-integrity protection, which \
                 this tool does not support"
            ),
            Self::NoPassphraseKeyslot => write!(
                f,
                "no passphrase keyslot: the volume may unlock only through \
                 a security key or TPM this tool cannot use"
            ),
            Self::WrongPassphrase => {
                write!(
                    f,
                    "wrong passphrase, or the volume unlocks only through a security key"
                )
            }
            Self::TruncatedVolume { need, have } => write!(
                f,
                "the encrypted data area is smaller than the header \
                 describes ({need} bytes needed, {have} present)"
            ),
            Self::Io(e) => write!(f, "reading the LUKS2 volume failed: {e}"),
        }
    }
}

impl std::error::Error for LuksError {}

impl From<std::io::Error> for LuksError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
