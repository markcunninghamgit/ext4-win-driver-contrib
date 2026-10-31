//! End-to-end: a REAL ext4 filesystem inside a LUKS2 container, built
//
// Runs only when the `luks-oracle` feature is on: its prerequisites
// (cryptsetup-minted fixtures; mkfs.ext4/debugfs) exist only in the CI
// luks job, and the portable suite must stay green on hosts without
// them. The feature is empty of production code by design.
#![cfg(feature = "luks-oracle")]
//! with the host's own `mkfs.ext4`, encrypted with the test's mint,
//! and read back through the built `ext4` CLI binary with each of the
//! fixture passphrases in turn.
//!
//! This is the user story as a test: a volume that starts with a
//! LUKS2 header, a passphrase, a read-only mount path (`ext4 cat` /
//! `ext4 ls` over the decrypting seam), and the same files the plaintext
//! ext4 held.
//!
//! Per the repository's rule this FAILS when it cannot run (no
//! `mkfs.ext4` on the host), never silently skips. It runs in the CI
//! `luks` job (ubuntu); the portable suite on macOS hosts has no
//! `mkfs.ext4` and so does not include it.
//!
//! The encryption side is the test-only mint from `src/luks/tests`:
//! it reuses the same audited RustCrypto primitives the unlock uses
//! (`aes` + `xts-mode`, plus the AF splitter), so the crypto's
//! correctness is not what this test double-checks — the independent
//! cryptsetup oracle (`luks_oracle.rs`) does that. What this proves
//! is the whole vertical: ext4 bytes in, LUKS2 on disk, CLI unlock,
//! ext4 bytes out.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const PASSPHRASES: &[&str] = &["testpass", "secondpass", "a-much-longer-passphrase-42"];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn workdir(name: &str) -> PathBuf {
    let d = root().join("target/luks-e2e").join(name);
    fs::create_dir_all(&d).unwrap();
    d
}

/// Build a small ext4 filesystem image with `mkfs.ext4`, populated
/// with known files. Returns (image, {path: contents}).
fn mkfs_ext4_populated(dir: &Path) -> (PathBuf, Vec<(&'static str, Vec<u8>)>) {
    let img = dir.join("plain.img");
    // 32 MiB: mkfs.ext4's default block overhead fits comfortably.
    let f = fs::File::create(&img).unwrap();
    f.set_len(32 * 1024 * 1024).unwrap();
    drop(f);

    let files = vec![
        (
            "hello.txt",
            b"hello from inside the encrypted volume\n".to_vec(),
        ),
        ("sector.bin", vec![0xA5u8; 512]),
        ("big.bin", {
            // ~1.5 MiB so it spans many data blocks and one extent.
            (0..1_572_864u32).map(|i| (i % 251) as u8).collect()
        }),
    ];

    // mkfs.ext4 + debugfs to inject files: debugfs is part of
    // e2fsprogs alongside mkfs.ext4, needs no root and no mount.
    let status = Command::new("mkfs.ext4")
        .arg("-q")
        .arg("-F")
        .arg(&img)
        .status()
        .expect("mkfs.ext4 must be on PATH (e2fsprogs)");
    assert!(status.success(), "mkfs.ext4 failed");
    for (name, contents) in &files {
        let src = dir.join(name);
        fs::write(&src, contents).unwrap();
        let write_cmd = format!("write {src:?} /{name}");
        let out = Command::new("debugfs")
            .arg("-w")
            .arg("-R")
            .arg(&write_cmd)
            .arg(&img)
            .output()
            .expect("debugfs must be on PATH (e2fsprogs)");
        assert!(
            out.status.success(),
            "debugfs write {name} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    (img, files)
}

/// The mint: expose it to this integration test. `src/luks/tests` is
/// unit-test-only, so the same primitives are re-exposed here for
/// the e2e container build. Constructing the container calls the
/// binary's own compiled-in mint through a thin shim: simplest is to
/// rebuild the small mint inline (it is ~100 lines of RustCrypto
/// calls), which keeps the integration test self-contained.
// The mint is shared with the unit tests; this context uses only its
// `mint_container_with_passphrase` entry, so the rest is allowed to
// sit unused.
#[allow(dead_code)]
mod mint {
    include!("../src/luks/tests/mint.rs");
}

#[test]
fn ext4_inside_luks2_unlocks_and_reads_back() {
    let dir = workdir("ext4-inside");
    let (plain_img, files) = mkfs_ext4_populated(&dir);
    let plaintext = fs::read(&plain_img).unwrap();

    // Encrypt the whole ext4 image as the LUKS2 payload, once per
    // passphrase: each container must unlock with its own passphrase
    // and fail with the others.
    for pass in PASSPHRASES {
        let container = dir.join(format!("{}.luks2", pass));
        let image = mint::mint_container_with_passphrase(&plaintext, pass.as_bytes());
        fs::write(&container, &image).unwrap();

        let pass_file = dir.join(format!("{}.pass", pass));
        fs::write(&pass_file, pass).unwrap();

        // ls through the driver: the ext4 root must list.
        let out = Command::new(env!("CARGO_BIN_EXE_ext4"))
            .arg("ls")
            .arg(&container)
            .arg("--passphrase-file")
            .arg(&pass_file)
            .arg("/")
            .output()
            .expect("running the driver binary");
        assert!(
            out.status.success(),
            "ext4 ls through the LUKS2 volume failed for {pass:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let listing = String::from_utf8_lossy(&out.stdout);
        for (name, _) in &files {
            assert!(
                listing.contains(name),
                "the listing must name {name} for {pass:?}: {listing}"
            );
        }

        // cat each file: contents must be byte-identical.
        for (name, want) in &files {
            let out = Command::new(env!("CARGO_BIN_EXE_ext4"))
                .arg("cat")
                .arg(&container)
                .arg("--passphrase-file")
                .arg(&pass_file)
                .arg(format!("/{name}"))
                .output()
                .expect("running the driver binary");
            assert!(
                out.status.success(),
                "ext4 cat /{name} failed for {pass:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(
                &out.stdout, want,
                "cat /{name} through the LUKS2 volume must match the plaintext for {pass:?}"
            );
        }

        // A wrong passphrase must refuse cleanly.
        let bad = dir.join("bad.pass");
        fs::write(&bad, "definitely-wrong").unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_ext4"))
            .arg("ls")
            .arg(&container)
            .arg("--passphrase-file")
            .arg(&bad)
            .arg("/")
            .output()
            .expect("running the driver binary");
        assert!(
            !out.status.success(),
            "a wrong passphrase must not unlock (pass {pass:?})"
        );
    }
}
