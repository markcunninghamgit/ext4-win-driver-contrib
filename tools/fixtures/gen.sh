#!/usr/bin/env bash
# Mint the LUKS2 oracle fixtures: real cryptsetup volumes, each with
# an ext4 filesystem inside and a SHA256SUMS manifest written from
# inside the volume while it was mounted on Linux.
#
# Runs on Linux with cryptsetup + mkfs.ext4 available (the CI ubuntu
# job). The differential test (tests/luks_oracle.rs) refuses to run
# without these fixtures, so CI generates them before cargo test.
#
# Variants:
#   luks2-argon2id-512  the cryptsetup default: argon2id, 512-byte sectors
#   luks2-argon2id-4096 --sector-size 4096
#   luks2-pbkdf2-512    --pbkdf pbkdf2 keyslot
#   luks2-two-slots     two keyslots with different passphrases
#   luks1               LUKS1 (refused by the driver; error path fixture)
#   luks2-integrity     dm-integrity volume (refused; error path fixture)
#
# Usage: gen.sh [outdir]   (default: fixtures/luks next to the script)

set -euo pipefail

OUT="${1:-$(cd "$(dirname "$0")/../.." && pwd)/fixtures/luks}"
mkdir -p "$OUT"
TMP=$(mktemp -d)
trap 'cleanup' EXIT
cleanup() {
    umount "$TMP/mnt" 2>/dev/null || true
    cryptsetup close "$TMP_MAP" 2>/dev/null || true
    rm -rf "$TMP"
}
TMP_MAP="luksfx$$"

# Fixed KDF cost so CI is fast and deterministic; the passphrases are
# public test values.
readonly PASS1="testpass"
readonly PASS2="secondpass"
size=256  # MiB, enough for ext4 + files

mk_volume() {  # name, extra luksFormat args..., then passphrase args handled below
    local name=$1; shift
    local img="$OUT/$name.img"
    truncate -s "${size}M" "$img"
    printf '%s' "$PASS1" | cryptsetup luksFormat --type luks2 \
        --pbkdf-force-iterations 4 --batch-mode "$img" -d /dev/stdin "$@"
}

populate() {  # name, passphrase
    local name=$1 pass=$2
    local img="$OUT/$name.img"
    mkdir -p "$TMP/mnt"
    printf '%s' "$pass" | cryptsetup open "$img" "$TMP_MAP" --key-file /dev/stdin -d /dev/stdin 2>/dev/null ||
        printf '%s' "$pass" | cryptsetup open "$img" "$TMP_MAP" -d /dev/stdin
    mkfs.ext4 -F "/dev/mapper/$TMP_MAP" >/dev/null 2>&1
    mount "/dev/mapper/$TMP_MAP" "$TMP/mnt"
    # A spread of sizes, including one larger than a sector and one
    # exactly a sector.
    dd if=/dev/urandom of="$TMP/mnt/small.txt" bs=1k count=4 2>/dev/null
    dd if=/dev/urandom of="$TMP/mnt/sector.bin" bs=512 count=1 2>/dev/null
    dd if=/dev/urandom of="$TMP/mnt/large.bin" bs=1M count=3 2>/dev/null
    mkdir -p "$TMP/mnt/sub"
    dd if=/dev/urandom of="$TMP/mnt/sub/nested.dat" bs=1k count=17 2>/dev/null
    ( cd "$TMP/mnt" && find . -type f -print0 | sort -z | xargs -0 sha256sum > "$OUT/$name.manifest" )
    umount "$TMP/mnt"
    cryptsetup close "$TMP_MAP"
    printf '%s' "$pass" > "$OUT/$name.pass"
}

echo "minting LUKS fixtures into $OUT"

mk_volume luks2-argon2id-512 --pbkdf argon2id
populate luks2-argon2id-512 "$PASS1"

mk_volume luks2-argon2id-4096 --pbkdf argon2id --sector-size 4096
populate luks2-argon2id-4096 "$PASS1"

mk_volume luks2-pbkdf2-512 --pbkdf pbkdf2
populate luks2-pbkdf2-512 "$PASS1"

mk_volume luks2-two-slots --pbkdf argon2id
printf '%s' "$PASS2" | cryptsetup luksAddKey --batch-mode "$OUT/luks2-two-slots.img" \
    --key-file /dev/stdin --pbkdf argon2id -d /dev/stdin 2>/dev/null || \
    printf '%s' "$PASS1" | cryptsetup luksAddKey "$OUT/luks2-two-slots.img" \
    --key-slot 1 --pbkdf argon2id --key-file /dev/stdin <<< "$PASS2"
populate luks2-two-slots "$PASS1"

# LUKS1: the refusal fixture.
truncate -s "${size}M" "$OUT/luks1.img"
printf '%s' "$PASS1" | cryptsetup luksFormat --type luks1 --batch-mode \
    "$OUT/luks1.img" -d /dev/stdin
printf '%s' "$PASS1" > "$OUT/luks1.pass"
echo "hello" > "$OUT/luks1.manifest"  # unused by the assert; the refusal is the test

# Integrity volume: the refusal fixture.
truncate -s "${size}M" "$OUT/luks2-integrity.img"
printf '%s' "$PASS1" | cryptsetup luksFormat --type luks2 --integrity hmac-sha256 \
    --batch-mode "$OUT/luks2-integrity.img" -d /dev/stdin
printf '%s' "$PASS1" > "$OUT/luks2-integrity.pass"
echo "hello" > "$OUT/luks2-integrity.manifest"

echo "done: $(ls "$OUT" | wc -l) files"
