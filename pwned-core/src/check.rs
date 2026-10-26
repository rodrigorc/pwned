use std::{fmt::Write, path::Path};
use sha1::Digest;
use anyhow::{bail, Result};

/// The outcome of checking one password: whether it shows up in the corpus,
/// and the SHA-1 hash it was looked up by.
///
/// Presenting a result is the front-end's business, so this type has no
/// `Display` nor JSON methods: what the output looks like is a decision for
/// whoever writes to a terminal, and `pwned-core` never writes anywhere.
#[derive(Debug)]
pub struct CheckResult {
    /// Times the password appears in the corpus, `None` when it never does.
    pub pwned: Option<u32>,
    /// Uppercase hex SHA-1 of the password.
    pub hash: String,
}

impl CheckResult {
    pub fn is_pwned(&self) -> bool {
        self.pwned.is_some()
    }
}

pub async fn check(pwd: &[u8], cache_dir: Option<&Path>) -> Result<CheckResult> {
    let mut hasher = sha1::Sha1::default();
    hasher.update(pwd);
    let hash = hasher.finalize();
    let mut target = String::new();
    for c in hash {
        let _ = write!(&mut target, "{:02X}", c);
    }

    lookup(target, cache_dir).await
}

/// Checks a password that is already hashed against the corpus.
///
/// `hash` must be the 40 hexadecimal digits of a SHA-1 digest. Upper- and
/// lowercase digits are both accepted; the result reports the hash in
/// uppercase, the same as [`check`] does.
pub async fn check_hash(hash: &str, cache_dir: Option<&Path>) -> Result<CheckResult> {
    let target = normalize_hash(hash)?;
    lookup(target, cache_dir).await
}

/// Validates `hash` and returns it in the uppercase form the corpus uses.
fn normalize_hash(hash: &str) -> Result<String> {
    let hash = hash.trim();
    if hash.len() != 40 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("not a SHA-1 hash (expected 40 hexadecimal digits): {hash:?}");
    }
    Ok(hash.to_ascii_uppercase())
}

/// Looks `hash` up in the corpus. `hash` must be uppercase hexadecimal.
async fn lookup(hash: String, cache_dir: Option<&Path>) -> Result<CheckResult> {
    let head = &hash[..5];
    let tail = &hash[5..];
    let id = usize::from_str_radix(head, 16).unwrap();

    let piece = crate::download::obtain_piece(id, cache_dir).await?;

    for line in piece.data.split(|&c| c == b'\n') {
        let mut ws = line.split(|&c| c == b':');
        let line_hash = ws.next().unwrap();
        if line_hash == tail.as_bytes() {
            let count = ws.next().unwrap().trim_ascii_end(); // beware of the \r
            let count: u32 = str::from_utf8(count).unwrap().parse().unwrap();
            return Ok(CheckResult {
                pwned: Some(count),
                hash,
            });
        }
    }
    Ok(CheckResult {
        pwned: None,
        hash,
    })
}

