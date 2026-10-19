use std::{fmt::Write, path::Path};
use sha1::Digest;
use anyhow::Result;

pub struct CheckResult {
    pub pwned: Option<u32>,
    pub hash: String,
}

impl std::fmt::Display for CheckResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self.pwned {
            Some(x) => write!(f, "XXX {} is pwned {} times", self.hash, x)?,
            None => write!(f, "    {} is not pwned!", self.hash)?,
        }
        Ok(())
    }
}

impl CheckResult {
    pub fn is_pwned(&self) -> bool {
        self.pwned.is_some()
    }

    /// Renders this result as a single JSON object.
    ///
    /// `count` is the number of times the password appears in the corpus, or
    /// null when it does not appear at all.
    ///
    /// Written by hand rather than via `serde_json`: the only field holding
    /// user-derived data is the hash, which is uppercase hex and so always safe
    /// to embed. If that stops being true, this needs a real serializer.
    pub fn to_json(&self) -> String {
        match self.pwned {
            Some(count) => format!(r#"{{"hash":"{}","pwned":true,"count":{count}}}"#, self.hash),
            None => format!(r#"{{"hash":"{}","pwned":false,"count":null}}"#, self.hash),
        }
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

    let head = &target[..5];
    let tail = &target[5..];
    let id = usize::from_str_radix(head, 16).unwrap();

    let piece = crate::download::obtain_piece(id, cache_dir).await?;

    for line in piece.data.split(|&c| c == b'\n') {
        let mut ws = line.split(|&c| c == b':');
        let hash = ws.next().unwrap();
        if hash == tail.as_bytes() {
            let count = ws.next().unwrap().trim_ascii_end(); // beware of the \r
            let count: u32 = str::from_utf8(count).unwrap().parse().unwrap();
            return Ok(CheckResult {
                pwned: Some(count),
                hash: target,
            });
        }
    }
    Ok(CheckResult {
        pwned: None,
        hash: target,
    })
}

