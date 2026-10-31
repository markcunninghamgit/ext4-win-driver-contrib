### Added

- **Encrypted (LUKS2) volumes open read-only with a passphrase.** A
  disk or image whose volume starts with a LUKS2 header is detected
  automatically, prompts for its passphrase (hidden input), and mounts
  the ext4 filesystem inside read-only — the same mount as a plain
  ext4 volume, over a decrypting block layer. Passphrase keyslots
  only (`luks2` slots with an argon2 or pbkdf2 KDF): TPM, FIDO2 and
  other token keyslots are ignored, never attempted. LUKS1,
  data-integrity (dm-integrity) volumes and unknown ciphers are
  refused with a clear message, and a LUKS volume is never mounted
  writable — `--rw` on one is an error. The unlock itself is the
  `luks-core` crate (Apache-2.0): pure Rust, no unsafe, validated
  sector-for-sector against cryptsetup, one-way license-compatible
  with this repository's GPL-3.0-or-later. Passphrases and derived key
  material are zeroized and never logged; `--passphrase-file` (or
  piped stdin) is available for non-interactive use, with the caveat
  that a file's blocks are not wiped after reading.
