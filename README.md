# pwned

A command-line client for [HaveIBeenPwned's Pwned Passwords](https://haveibeenpwned.com/Passwords): it
downloads the corpus and checks passwords against it.

Checks are anonymous by design. Each password is hashed with SHA-1, and only the first five hex digits
of that hash are sent to the range API; the full hash never leaves the machine. The API answers with
the ~2000 hashes that share that prefix, and the real hash is looked up among them locally. That is the
k-anonymity scheme the service is built around.

## Install

```sh
cargo install --path .

# or, straight from the repository
cargo install --git https://github.com/rodrigorc/pwned
```

For development builds outside the PATH:

```sh
cargo build --release
./target/release/pwned --help
```

## Quick start

```sh
pwned download        # fetch the whole corpus; large, and only needed once
pwned check hunter2
```

`download` is optional. Any shard a check needs and does not have is fetched on demand, so a fresh
install can check a password right away — it just makes a network round trip for it.

## Checking passwords

```sh
pwned check hunter2                 # one password as an argument
pwned check hunter2 correcthorse    # several at once
pwned check                         # prompt on the terminal, with no echo
pwned check --file passwords.txt    # one password per line
pwned check --file -                # ...read from stdin
pwned check --file0 passwords.bin   # NUL-separated, for passwords containing newlines
pwned check --file passwords.txt --json
```

```
XXX 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8 is pwned 52372427 times
    2692E3EAAADD5F7F35A5673433ADAF95C555AA1A is not pwned!
```

With `--json`, stdout is a single array with one object per password instead:

```json
[{"hash":"5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8","pwned":true,"count":52372427},
 {"hash":"F24F3089CB0F051020133DFAA7D4267AA3384DDA","pwned":false,"count":null}]
```

`count` is how many times the password appears in the corpus, or `null` if it does not appear at all.
The JSON array is buffered and printed in one go at the end, so a check that fails partway writes
nothing to stdout rather than leaving a half-finished array behind; plain output is streamed as each
password is checked. Errors and log messages always go to stderr.

## Downloading the corpus

```sh
pwned download        # default concurrency
pwned download -j 32  # 32 shards in flight
```

The full corpus is on the order of 40 GB of gzipped shards, so give it disk space and time. It is
resumable in the crudest possible way: shards already on disk are skipped, so re-running `download`
picks up where the last run stopped. Timed out or interrupted shards are incomplete files, and they
are re-fetched automatically.

## Cache directory

Shards live in a per-user cache directory:

| platform | default |
|---|---|
| Linux | `$XDG_CACHE_HOME/pwned`, normally `~/.cache/pwned` |
| macOS | `~/Library/Caches/pwned` |
| Windows | `%LOCALAPPDATA%\pwned\cache` |

The global `-d`/`--cache-dir` option overrides it, and works on every subcommand:

```sh
pwned -d /mnt/big/pwned download
pwned -d /mnt/big/pwned check hunter2
```

Within that directory, a shard is stored as `AB/CDE.gz`, named after the five hash digits it holds —
256 directories of 4096 files, rather than one directory of a million. A cache that cannot be written
to is not fatal: the check still answers from the data it just fetched, it is only not reused later.

## Exit codes

| code | meaning |
|------|---------|
| 0 | success; nothing was pwned |
| 1 | at least one password was pwned |
| 2 | usage error, printed by the argument parser |
| 3 | operational failure, including a panic |

The point of the split is that `pwned` can be used as a condition in a script:

```sh
pwned check --file - < candidates.txt
case $? in
    0) echo "none of them are pwned" ;;
    1) echo "at least one is pwned" ;;
    *) echo "the check did not run" >&2 ;;
esac
```

## Encodings

The corpus contains hashes of whatever bytes leaked, so passwords are never decoded: a file is hashed
byte-for-byte exactly as it is. That means any encoding works, as long as the bytes match the ones that
were leaked. Transcoding on the way in is enough:

```sh
printf 'пароль' | iconv -t CP1251     | pwned check --file -
printf 'こんにちは' | iconv -t SHIFT-JIS | pwned check --file -
```

Two things to keep in mind:

* `--file` splits on newline (`0x0A`) and strips a trailing carriage return; `--file0` splits on NUL
  and leaves everything else alone. Use `--file0` when a password may contain a newline, or when the
  encoding itself can produce a `0x0A` byte inside a character (UTF-16, for example).
* Passwords given as arguments or typed at the prompt are text and are therefore treated as UTF-8;
  only file input is byte-for-byte.

## Library

The engine is published as a separate crate, `pwned-core`, which has no CLI dependencies — no argument
parser, no terminal handling:

```toml
[dependencies]
pwned-core = { path = "pwned-core" }
```

```rust
use pwned_core::{check, download};
use pwned_core::download::Progress;

// Look one password up. Pass `None` instead of a cache to fetch and forget,
// without reading or writing any file.
let result = check::check(password_bytes, Some(cache_dir)).await?;
if result.is_pwned() {
    println!("seen {} times", result.pwned.unwrap());
}

// Fetch every missing shard, drawing progress however you like.
download::download(cache_dir, None, |event| match event {
    Progress::Shard => { /* one more shard is available */ }
    Progress::Error(msg) => eprintln!("{msg}"),
})
.await?;
```

Rendering progress is the caller's business, which is why the library never writes to your stdout.

## License

Licensed under either of Apache License, Version 2.0 or MIT license, at your option.
