use std::sync::Arc;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;
use anyhow::Result;
use bytes::Bytes;
use http::Uri;

const URL: &str = "https://api.pwnedpasswords.com/range/";

/// Path of the gzipped shard `id` inside `cache_dir`.
///
/// Shards are named after the 5-hex-digit prefix of the hashes they contain,
/// which is also the k-anonymity prefix used by the range API.
pub fn shard_path(cache_dir: &Path, id: usize) -> PathBuf {
    cache_dir.join(format!("{id:05X}.gz"))
}

struct MyProgress {
    count: usize,
    pb: progress_bar::pb::ProgressBar,
}

enum ProgressEvent {
    Block,
    Error(String),
}

pub async fn download(cache_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(cache_dir)?;


    let num_tasks = std::thread::available_parallelism().map(|x| x.into()).unwrap_or(1);

    let (tx, mut rx) = tokio::sync::mpsc::channel(num_tasks);

    let mut progress = progress_bar::pb::ProgressBar::new_with_eta(0.3, 0x1_00000 / 0x400);
    progress.set_progress_style(progress_bar::ProgressStyle::Percentage);
    progress.set_action("Downloading", progress_bar::Color::Blue, progress_bar::Style::Bold);
    let mut progress = MyProgress {
        count: 0,
        pb: progress,
    };

    tokio::spawn({
        let retry_policy = reqwest::retry::for_host(Uri::from_static(URL).host().unwrap().to_string())
            .max_retries_per_request(8)
            .classify_fn(|req| {
                match req.status() {
                    Some(st) if st.is_success() || st.is_redirection() => req.success(),
                    _ => req.retryable(),
                }
            });
        let client = reqwest::ClientBuilder::new()
            .retry(retry_policy)
            .build()
            .unwrap();

        let sema = tokio::sync::Semaphore::new((num_tasks * 4).min(64));
        let sema = Arc::new(sema);
        let cache_dir = cache_dir.to_path_buf();
        async move {
            for id in 0..0x1_00000 {
                let permit = sema.clone().acquire_owned().await.unwrap();
                let name = shard_path(&cache_dir, id);

                if std::fs::exists(&name).unwrap() {
                    // already downloaded, just report
                    tx.send(ProgressEvent::Block).await.unwrap();
                    continue;
                }

                tokio::spawn({
                    let tx = tx.clone();
                    let client = client.clone();
                    let cache_dir = cache_dir.clone();
                    async move {
                        let mut retry = 0;
                        let piece = loop {
                            match download_piece(&client, id).await {
                                Ok(d) => break d,
                                Err(e) => {
                                    retry += 1;
                                    // report the error
                                    let msg = format!("error in piece 0x{id:X}, #{retry}: {e:#?}");
                                    tx.send(ProgressEvent::Error(msg)).await.unwrap();
                                    if retry == 4 {
                                        panic!("too many errors in the same piece");
                                    }
                                    tokio::time::sleep(Duration::from_secs(2_u64.pow(retry))).await;
                                }
                            }
                        };
                        write_piece(&cache_dir, &piece).unwrap();
                        tx.send(ProgressEvent::Block).await.unwrap();
                       drop(permit);
                    }
                });
            }
        }
    });


    while let Some(ev) = rx.recv().await {
        match ev {
            ProgressEvent::Block => {
                progress.count += 1;
                if progress.count % 0x400 == 0 {
                    progress.pb.inc();
                }
            }
            ProgressEvent::Error(msg) => {
                progress.pb.print_info("error", &msg, progress_bar::Color::Red, progress_bar::Style::Bold);
            }
        }
    }

    progress.pb.finalize();
    Ok(())
}

pub struct Piece {
    pub id: usize,
    pub data: Bytes,
}

async fn download_piece(client: &reqwest::Client, id: usize) -> Result<Piece> {
    let url = format!("{URL}{id:05X}");
    let req = client.get(&url)
        .build()?;
    let reply = client
        .execute(req)
        .await?;
    let reply = reply
        .error_for_status()?;

    let data = reply
        .bytes()
        .await?;
    Ok(Piece { id, data })
}

fn write_piece(cache_dir: &Path, piece: &Piece) -> std::io::Result<()> {
    use std::io::Write;

    let name = shard_path(cache_dir, piece.id);
    let name_tmp = name.with_extension("tmp");

    {
        let f = std::fs::File::create(&name_tmp)?;
        let f = std::io::BufWriter::new(f);
        let mut gz = flate2::write::GzEncoder::new(f, flate2::Compression::default());
        gz.write_all(&piece.data)?;
    }
    std::fs::rename(&name_tmp, &name)?;
    Ok(())
}

/// Reads the cached shard `id` from disk, returning `None` on a cache miss.
///
/// A shard that is present but cannot be read is deleted and treated as a miss,
/// so the cache repairs itself on the next read. That covers both the shard
/// being unreadable and it being truncated or otherwise corrupt.
///
/// An empty decompression result is also a miss. A valid gzip stream over empty
/// input is not an error, so this is the only guard against a corrupt shard
/// reading as zero hashes and silently reporting every password as safe.
fn read_cached_piece(cache_dir: &Path, id: usize) -> Result<Option<Vec<u8>>> {
    let name = shard_path(cache_dir, id);
    if !std::fs::exists(&name)? {
        return Ok(None);
    }

    let decoded = (|| -> std::io::Result<Vec<u8>> {
        let f = std::fs::File::open(&name)?;
        let mut gz = flate2::read::GzDecoder::new(std::io::BufReader::new(f));
        let mut data = Vec::new();
        gz.read_to_end(&mut data)?;
        Ok(data)
    })();

    match decoded {
        // an empty read is as useless as a failed one: see doc comment
        Ok(data) if !data.is_empty() => Ok(Some(data)),
        result => {
            let why = match &result {
                Err(e) => e.to_string(),
                Ok(_) => "decompressed to nothing".to_owned(),
            };
            log::error!("removing unreadable cache shard {}: {why}", name.display());
            if let Err(e) = std::fs::remove_file(&name) {
                log::error!("could not remove {}: {e}", name.display());
            }
            Ok(None)
        }
    }
}

pub async fn obtain_piece(id: usize, cache_dir: &Path) -> Result<Piece> {
    if let Some(data) = read_cached_piece(cache_dir, id)? {
        return Ok(Piece { id, data: data.into() });
    }
    let client = reqwest::Client::new();
    let piece = download_piece(&client, id).await?;
    // writing the piece is not mandatory: a read-only or full cache should still
    // answer the check, it just won't be reused next time
    if let Err(e) = std::fs::create_dir_all(cache_dir) {
        log::error!("could not create cache dir {}: {e}", cache_dir.display());
    } else if let Err(e) = write_piece(cache_dir, &piece) {
        log::error!("could not cache shard {id:05X} in {}: {e}", cache_dir.display());
    }
    Ok(piece)
}
