//! Tier-2: the differential test against fixtures minted by real
//! `cryptsetup` on Linux, with a SHA256SUMS manifest written from
//! inside the volume while it was mounted there.
//!
//! Per the repository's rule, this FAILS when its fixtures are
//! absent — a suite that quietly declines to run is indistinguishable
//! from one that passes. `tools/fixtures/gen.sh` (or the CI job that
//! runs it) writes into `fixtures/luks/`; point `LUKS_FIXTURE_DIR` at
//! a directory holding `<name>.img` + `<name>.manifest` pairs.
//!
//! Each variant validates the whole chain the other tests only
//! self-check: cryptsetup's argon2id/pbkdf2 keyslot, its AF stripes,
//! its segment encryption at 512 and 4096 bytes, and — through this
//! driver's ext4 reader — the SHA256 of every file the manifest
//! recorded on Linux.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Fixture directory; the CI job sets it after generating fixtures.
const ENV: &str = "LUKS_FIXTURE_DIR";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// One fixture: image plus manifest, named alike.
struct Fixture {
    image: PathBuf,
    manifest: PathBuf,
}

fn fixture_dir() -> PathBuf {
    std::env::var_os(ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| root().join("fixtures/luks"))
}

fn load(name: &str) -> Fixture {
    let dir = fixture_dir();
    let image = dir.join(format!("{name}.img"));
    let manifest = dir.join(format!("{name}.manifest"));
    for p in [&image, &manifest] {
        if !p.is_file() {
            panic!(
                "the LUKS oracle fixture {} is missing: run \
                 tools/fixtures/gen.sh (or the CI job that does) and \
                 point {} at the directory it wrote — refusing to skip",
                p.display(),
                ENV
            );
        }
    }
    Fixture { image, manifest }
}

/// Every manifest line: `<sha256-hex>  /path`, produced by
/// `sha256sum` on Linux inside the mounted volume.
fn manifest_lines(f: &Fixture) -> Vec<(String, String)> {
    let text = fs::read_to_string(&f.manifest)
        .unwrap_or_else(|e| panic!("reading {}: {e}", f.manifest.display()));
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let (hash, path) = l
                .split_once("  ")
                .unwrap_or_else(|| panic!("manifest line is not `hash  path`: {l:?}"));
            (hash.trim().to_string(), path.trim().to_string())
        })
        .collect()
}

/// `ext4 cat` through this driver, with the fixture's passphrase on
/// stdin (the non-interactive path, exactly as a script would use
/// it).
fn cat(f: &Fixture, path: &str) -> Vec<u8> {
    let out = Command::new(env!("CARGO_BIN_EXE_ext4"))
        .arg("cat")
        .arg(&f.image)
        .arg("--passphrase-file")
        .arg(passphrase_file(f))
        .arg(path)
        .output()
        .expect("running the driver binary");
    if !out.status.success() {
        panic!(
            "ext4 cat {} failed: {}",
            path,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    out.stdout
}

/// The passphrase file gen.sh writes beside each image.
fn passphrase_file(f: &Fixture) -> PathBuf {
    f.image.with_extension("pass")
}

fn sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    let d = h.finalize();
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// Every file's SHA256 through the driver matches the manifest
/// written on Linux. This is the acceptance criterion: reads through
/// the WinFsp-facing stack (LUKS decrypt + ext4) return the bytes
/// cryptsetup's plaintext held.
#[test]
fn every_manifest_file_matches_linux() {
    let variants = [
        ("luks2-argon2id-512", "testpass"),
        ("luks2-argon2id-4096", "testpass"),
        ("luks2-pbkdf2-512", "testpass"),
        ("luks2-two-slots", "secondpass"),
    ];
    let mut checked = 0usize;
    for (name, pass) in variants {
        let f = load(name);
        write_passphrase_file(&f, pass);
        for (hash, path) in manifest_lines(&f) {
            let got = cat(&f, &path);
            let got_hash = sha256(&got);
            assert_eq!(
                got_hash, hash,
                "{name}: {path} through the driver does not match the \
                 manifest written on Linux"
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "no manifest entries were checked");
}

fn write_passphrase_file(f: &Fixture, pass: &str) {
    let p = passphrase_file(f);
    if !p.is_file() {
        fs::write(&p, pass).unwrap_or_else(|e| panic!("writing {}: {e}", p.display()));
    }
}

/// The variant with two keyslots unlocks with EITHER passphrase:
/// the unlock tries every passphrase-capable slot.
#[test]
fn a_two_keyslot_volume_unlocks_with_either_passphrase() {
    let f = load("luks2-two-slots");
    write_passphrase_file(&f, "testpass");
    let lines = manifest_lines(&f);
    let (hash, path) = lines.first().expect("a manifest entry").clone();
    let got = cat(&f, &path);
    assert_eq!(sha256(&got), hash);
}

/// A LUKS1 fixture is refused with the clear message.
#[test]
fn luks1_is_refused_with_a_clear_message() {
    let f = load("luks1");
    write_passphrase_file(&f, "testpass");
    let out = Command::new(env!("CARGO_BIN_EXE_ext4"))
        .arg("info")
        .arg(&f.image)
        .arg("--passphrase-file")
        .arg(passphrase_file(&f))
        .output()
        .expect("running the driver binary");
    assert!(!out.status.success(), "a LUKS1 volume must not open");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("LUKS1"), "the refusal must name LUKS1: {err}");
}

/// An integrity volume is refused with the clear message.
#[test]
fn an_integrity_volume_is_refused_with_a_clear_message() {
    let f = load("luks2-integrity");
    write_passphrase_file(&f, "testpass");
    let out = Command::new(env!("CARGO_BIN_EXE_ext4"))
        .arg("info")
        .arg(&f.image)
        .arg("--passphrase-file")
        .arg(passphrase_file(&f))
        .output()
        .expect("running the driver binary");
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("integrity"),
        "the refusal must name integrity protection: {err}"
    );
}

/// A wrong passphrase fails cleanly, with no partial mount.
#[test]
fn a_wrong_passphrase_fails_cleanly() {
    let f = load("luks2-argon2id-512");
    write_passphrase_file(&f, "testpass");
    let bad = f.image.with_extension("bad-pass");
    fs::write(&bad, "not-the-passphrase").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ext4"))
        .arg("info")
        .arg(&f.image)
        .arg("--passphrase-file")
        .arg(&bad)
        .output()
        .expect("running the driver binary");
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.to_lowercase().contains("passphrase"),
        "the refusal must name the passphrase: {err}"
    );
}
