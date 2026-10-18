use std::fmt::Write;
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
}

pub async fn check(pwd: &str) -> Result<CheckResult> {
    let mut hasher = sha1::Sha1::default();
    hasher.update(pwd.as_bytes());
    let hash = hasher.finalize();
    let mut target = String::new();
    for c in hash {
        let _ = write!(&mut target, "{:02X}", c);
    }

    let head = &target[..5];
    let tail = &target[5..];
    let id = usize::from_str_radix(head, 16).unwrap();

    let piece = crate::download::obtain_piece(id).await?;

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

