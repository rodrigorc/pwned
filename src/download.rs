use std::sync::Arc;
use std::io::Read;
use std::time::Duration;
use anyhow::Result;
use bytes::Bytes;
use http::Uri;

const URL: &str = "https://api.pwnedpasswords.com/range/";

struct MyProgress {
    count: usize,
    pb: progress_bar::pb::ProgressBar,
}

enum ProgressEvent {
    Block,
    Error(String),
}

pub async fn download() -> Result<()> {
    std::fs::create_dir_all("out/pwned")?;


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
        async move {
            for id in 0..0x1_00000 {
                let permit = sema.clone().acquire_owned().await.unwrap();
                let name = format!("out/pwned/{:05X}.gz", id);

                if std::fs::exists(name).unwrap() {
                    // already downloaded, just report
                    tx.send(ProgressEvent::Block).await.unwrap();
                    continue;
                }

                tokio::spawn({
                    let tx = tx.clone();
                    let client = client.clone();
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
                        write_piece(&piece).unwrap();
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

fn write_piece(piece: &Piece) -> std::io::Result<()> {
    use std::path::PathBuf;
    use std::io::Write;

    let name = PathBuf::from(format!("out/pwned/{:05X}.gz", piece.id));
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

pub async fn obtain_piece(id: usize) -> Result<Piece> {
    let name = format!("out/pwned/{:05X}.gz", id);
    if std::fs::exists(&name)? {
        let f = std::fs::File::open(name)?;
        let f = std::io::BufReader::new(f);
        let mut gz = flate2::read::GzDecoder::new(f);
        let mut data = Vec::new();
        gz.read_to_end(&mut data)?;
        return Ok(Piece { id, data: data.into() });
    }
    let client = reqwest::Client::new();
    let piece = download_piece(&client, id).await?;
    // writing the piece is not mandatory
    let _ = write_piece(&piece);
    Ok(piece)
}
