//! Passphrase acquisition, with zeroization.
//!
//! Three sources, in this order:
//!   1. `--passphrase-file` — a file read into a zeroized buffer.
//!      Caveat (documented in the README): the passphrase transits the
//!      filesystem and the file's contents remain until the OS
//!      reuses the blocks; use it only where no interactive prompt can
//!      run (services, CI).
//!   2. stdin, when it is not a terminal (piped), for scripts.
//!   3. hidden interactive prompt, for a human at a console.
//!
//! The passphrase is never logged and never written anywhere by this
//! driver; the buffer is zeroized on drop.
//!
//! The prompt and file paths read the passphrase as raw bytes (no
//! UTF-8 requirement — cryptsetup accepts arbitrary bytes). One
//! trailing newline is stripped, as cryptsetup's own `--key-file`
//! and prompt do for a line-oriented input.

use std::fs;
use std::io::{self, IsTerminal, Read};

use zeroize::Zeroizing;

/// Read a passphrase from a file, zeroized. One trailing newline is
/// stripped.
pub fn from_file(path: &std::path::Path) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut file = fs::File::open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    strip_one_newline(&mut buf);
    Ok(Zeroizing::new(buf))
}

/// Read a passphrase from stdin (non-interactive), zeroized. One
/// trailing newline is stripped.
pub fn from_stdin() -> io::Result<Zeroizing<Vec<u8>>> {
    let mut buf = Vec::new();
    io::stdin().read_to_end(&mut buf)?;
    strip_one_newline(&mut buf);
    Ok(Zeroizing::new(buf))
}

/// Prompt a human with a hidden prompt, zeroized. One trailing
/// newline is stripped.
pub fn prompt() -> io::Result<Zeroizing<Vec<u8>>> {
    let s = rpassword::prompt_password("Passphrase for the encrypted volume: ")?;
    let mut buf = s.into_bytes();
    strip_one_newline(&mut buf);
    Ok(Zeroizing::new(buf))
}

/// Acquire the passphrase by the CLI's resolved choice.
pub fn acquire(file: Option<&std::path::Path>, stdin_ok: bool) -> io::Result<Zeroizing<Vec<u8>>> {
    if let Some(p) = file {
        return from_file(p);
    }
    if stdin_ok && !io::stdin().is_terminal() {
        return from_stdin();
    }
    prompt()
}

fn strip_one_newline(buf: &mut Vec<u8>) {
    if buf.last() == Some(&b'\n') {
        buf.pop();
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_single_trailing_newline_is_stripped() {
        let mut b = b"testpass\n".to_vec();
        strip_one_newline(&mut b);
        assert_eq!(b, b"testpass");
    }

    #[test]
    fn a_crlf_newline_is_stripped_too() {
        let mut b = b"testpass\r\n".to_vec();
        strip_one_newline(&mut b);
        assert_eq!(b, b"testpass");
    }

    #[test]
    fn interior_newlines_survive() {
        let mut b = b"a\nb\n".to_vec();
        strip_one_newline(&mut b);
        assert_eq!(b, b"a\nb");
    }

    #[test]
    fn no_newline_is_left_alone() {
        let mut b = b"testpass".to_vec();
        strip_one_newline(&mut b);
        assert_eq!(b, b"testpass");
    }
}
