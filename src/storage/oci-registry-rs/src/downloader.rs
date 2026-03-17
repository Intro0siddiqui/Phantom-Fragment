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
        let file_name = format!("{}.tar.gzip", task.digest.replace("sha256:", ""));
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
        pb.set_message(format!("Layer {}", &task.digest[..12]));
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
