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

If the passwords are already hashed, `--hash` checks them directly instead of hashing them a
second time:

```sh
pwned check --hash 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
pwned check --hash 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8  # case does not matter
pwned check --hash --file hashes.txt
```

The values must be complete 40-digit SHA-1 hashes, in upper- or lowercase; results report them in
uppercase. Since there is nothing useful to type at a prompt, `--hash` requires a hash as an
argument or from `--file`/`--file0` and never falls back to interactive input.

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

## Checking a CSV export

Most password managers can export the whole vault as CSV. `check-csv` checks one of those exports
straight from the pipe, so the clear passwords never reach the disk:

```sh
keepassxc-cli export -f csv passwords.kdbx | pwned check-csv
pwned check-csv < test.csv               # an export already on hand works too
pwned check-csv --json < test.csv
```

The first record must be a header naming the `Group`, `Title` and `Password` columns. Matching is
case-insensitive and every other column is ignored, so a straight export works as it comes out of the
manager — KeePassXC writes all three, and the rest of its columns are skipped. Quoting, commas and
newlines inside a field follow the usual CSV rules.

Each result is reported under the entry's `Group/Title` instead of the password hash:

```
XXX Root/lwn is pwned 52372427 times
    Root/Netflix is not pwned!
```

And with `--json`, `id` takes the place `hash` has in `check`:

```json
[{"id":"Root/lwn","pwned":true,"count":52372427},
 {"id":"Root/Netflix","pwned":false,"count":null}]
```

Records with an empty password are skipped, and the exit codes are the ones listed below.

## KeePassXC Okon compatibility

KeePassXC can use `pwned` through its Okon interface:

```sh
touch /tmp/dummy.okon
keepassxc-cli analyze --hibp /tmp/dummy.okon --okon pwned Passwords.kdbx
```

The `.okon` file only signals that `pwned` should use the Okon protocol; KeePassXC calls it once per
password and reads back `1` (pwned) or `0` (not pwned). Empty passwords are treated as not pwned, so
entries without a password do not show up as leaks.

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
* `check-csv` reads the `Password` column byte-for-byte too, modulo the usual CSV quoting. Only the
  `Group/Title` label is decoded — and it is decoded lossily, since all it does is get printed.

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

// Or look up a password that is already hashed. Either hex case works.
let result = check::check_hash("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8", Some(cache_dir)).await?;

// Fetch every missing shard, drawing progress however you like.
download::download(cache_dir, None, |event| match event {
    Progress::Shard => { /* one more shard is available */ }
    Progress::Error(msg) => eprintln!("{msg}"),
})
.await?;
```

Rendering is the caller's business, which is why the library never writes to your stdout: progress
from `download` as in the second example, and the format of a `CheckResult` in the first — the type
is plain data, `pwned` and `hash`, and how to print it is a decision left to whoever has the terminal.

## License

Licensed under either of Apache License, Version 2.0 or MIT license, at your option.
