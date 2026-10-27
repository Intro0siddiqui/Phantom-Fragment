//! Parallel layer downloader with resume support and progress tracking

use crate::{RegistryError, Result};
use futures::StreamExt;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use reqwest::Client;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::OpenOptions;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

/// Configuration for the downloader
#[derive(Debug, Clone)]
pub struct DownloaderConfig {
    /// Maximum concurrent downloads
    pub max_concurrent: usize,

    /// Directory to store layers
    pub cache_dir: PathBuf,
}

impl Default for DownloaderConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 3,
            cache_dir: PathBuf::from("~/.phantom/cache"),
        }
    }
}

/// Build the cache file name for a layer digest.
///
/// The digest comes from a remote manifest, so it is validated as hex before
/// being used as a path component (prevents `../../x` style traversal).
fn digest_file_name(digest: &str) -> Result<String> {
    let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
    if hex.is_empty() || hex.len() > 128 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(RegistryError::Other(format!(
            "Invalid layer digest: {:?}",
            digest
        )));
    }
    Ok(format!("{}.tar.gzip", hex))
}

/// Shorten a digest for logging without a non-char-boundary panic.
fn short_digest(digest: &str) -> String {
    digest.chars().take(12).collect()
}

/// Layer download task
#[derive(Debug, Clone)]
pub struct DownloadTask {
    pub url: String,
    pub digest: String,
    pub size: u64,
    pub token: String,
}

/// Parallel downloader
pub struct Downloader {
    client: Client,
    config: DownloaderConfig,
}

impl Downloader {
    pub fn new(client: Client, config: DownloaderConfig) -> Self {
        Self { client, config }
    }

    /// Download multiple layers in parallel
    pub async fn download_layers(&self, tasks: Vec<DownloadTask>) -> Result<Vec<PathBuf>> {
        let multi_progress = Arc::new(MultiProgress::new());
        let client = self.client.clone();
        let config = self.config.clone();

        // Create a stream of download futures
        let downloads = futures::stream::iter(tasks)
            .map(|task| {
                let client = client.clone();
                let config = config.clone();
                let mp = multi_progress.clone();

                async move { Self::download_layer(client, config, task, mp).await }
            })
            .buffer_unordered(config.max_concurrent); // Run N in parallel

        // Collect results
        let results: Vec<Result<PathBuf>> = downloads.collect().await;

        // Check for errors
        let mut paths = Vec::new();
        for res in results {
            paths.push(res?);
        }

        Ok(paths)
    }

    /// Download a single layer with resume support
    async fn download_layer(
        client: Client,
        config: DownloaderConfig,
        task: DownloadTask,
        mp: Arc<MultiProgress>,
    ) -> Result<PathBuf> {
        let file_name = digest_file_name(&task.digest)?;
        let file_path = config.cache_dir.join(&file_name);

        // Create parent directory if needed
        if let Some(parent) = file_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // Check if file exists and get current size for resume
        let mut current_size = 0;
        if file_path.exists() {
            let metadata = tokio::fs::metadata(&file_path).await?;
            current_size = metadata.len();

            if current_size == task.size {
                log::info!("Layer {} already downloaded", task.digest);
                return Ok(file_path);
            }
        }

        // Setup progress bar
        let pb = mp.add(ProgressBar::new(task.size));
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta}) {msg}")
            .unwrap()
            .progress_chars("#>-"));
        pb.set_message(format!("Layer {}", short_digest(&task.digest)));
        pb.set_position(current_size);

        // Open file for appending
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(&file_path)
            .await?;

        // Seek to end (just to be safe)
        file.seek(std::io::SeekFrom::Start(current_size)).await?;

        // Make request with Range header
        let response = client
            .get(&task.url)
            .header("Authorization", format!("Bearer {}", task.token))
            .header("Range", format!("bytes={}-", current_size))
            .send()
            .await
            .map_err(RegistryError::Network)?;

        if !response.status().is_success() && response.status() != 206 {
            return Err(RegistryError::Other(format!(
                "Failed to download layer: {} (status {})",
                task.digest,
                response.status()
            )));
        }

        // Stream content
        let mut stream = response.bytes_stream();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(RegistryError::Network)?;
            file.write_all(&chunk).await?;
            pb.inc(chunk.len() as u64);
        }

        pb.finish_with_message("Done");

        // Verify size
        let final_size = tokio::fs::metadata(&file_path).await?.len();
        if final_size != task.size {
            return Err(RegistryError::Other(format!(
                "Download incomplete: expected {} bytes, got {}",
                task.size, final_size
            )));
        }

        Ok(file_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digest_file_name_accepts_hex() {
        assert_eq!(
            digest_file_name("sha256:abcdef0123456789").unwrap(),
            "abcdef0123456789.tar.gzip"
        );
        assert_eq!(
            digest_file_name("abcdef0123456789").unwrap(),
            "abcdef0123456789.tar.gzip"
        );
    }

    #[test]
    fn test_digest_file_name_rejects_traversal() {
        for digest in [
            "sha256:../../etc/cron.d/evil",
            "../../etc/cron.d/evil",
            "sha256:",
            "sha256:zz",
            "",
        ] {
            assert!(
                digest_file_name(digest).is_err(),
                "digest {:?} should be rejected",
                digest
            );
        }
    }

    #[test]
    fn test_short_digest_multibyte() {
        assert_eq!(short_digest("éééééééééééééé"), "éééééééééééé");
    }
}
