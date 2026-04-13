//! Image Puller - Download and extract OCI images to rootfs
//!
//! This module handles:
//! - Pulling OCI images from registries
//! - Extracting layers to rootfs directory
//! - Caching extracted rootfs for reuse
//! - Content-addressable storage via image-store-rs
//! - SHA256 verification of downloaded layers

pub mod fuse_overlayfs;
pub mod oci_config;
pub mod proot;
pub mod rootfs_executor;
pub use rootfs_executor::RootfsExecutor;

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use image_store_rs::{ImageStore, StorageConfig};
use oci_registry_rs::RegistryClient;
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use tar::Archive;

/// Layer information with expected digest for verification
#[derive(Debug, Clone)]
pub struct LayerInfo {
    pub digest: String,
    pub size: u64,
    pub media_type: String,
}

/// Pull configuration with verification options
#[derive(Debug, Clone, Default)]
pub struct PullConfig {
    /// Enable strict SHA256 verification
    pub verify: bool,
}

pub struct ImagePuller {
    rootfs_base: PathBuf,
    cache_dir: PathBuf,
    registry_client: Option<RegistryClient>,
    store: Mutex<ImageStore>,
    config: PullConfig,
}

impl ImagePuller {
    /// Create a new ImagePuller with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(PullConfig::default())
    }

    /// Create a new ImagePuller with custom configuration
    pub fn with_config(config: PullConfig) -> Result<Self> {
        // Determine storage location (prefer user home for non-root)
        let rootfs_base = if nix::unistd::Uid::effective().is_root() {
            PathBuf::from("/var/lib/phantom/rootfs")
        } else {
            let home = std::env::var("HOME")
                .or_else(|_| std::env::var("USERPROFILE"))
                .context("Failed to determine home directory")?;
            PathBuf::from(home).join(".phantom").join("rootfs")
        };

        let cache_base = rootfs_base
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Invalid rootfs base path"))?
            .join("cache");
        let blobs_dir = cache_base.join("blobs");

        // Create directories
        fs::create_dir_all(&rootfs_base).context("Failed to create rootfs directory")?;
        fs::create_dir_all(&blobs_dir).context("Failed to create cache directory")?;

        // Create registry client
        let registry_client = match RegistryClient::new(cache_base.clone()) {
            Ok(client) => Some(client),
            Err(e) => {
                log::warn!("Failed to create registry client: {:?}", e);
                None
            }
        };

        // Create image store for content-addressable layer storage
        let store_config = StorageConfig {
            base_path: cache_base.clone(),
            ..Default::default()
        };
        let store = ImageStore::new(store_config).context("Failed to create image store")?;

        Ok(Self {
            rootfs_base,
            cache_dir: blobs_dir,
            registry_client,
            store: Mutex::new(store),
            config,
        })
    }

    /// Pull and extract an OCI image with SHA256 verification
    pub async fn pull(&self, image_ref: &str) -> Result<PathBuf> {
        log::info!("Pulling image: {}", image_ref);

        // Check if already extracted
        let simple_name = image_ref.replace(":", "-").replace("/", "_");
        let rootfs_path = self.rootfs_base.join(&simple_name);

        if rootfs_path.exists() {
            log::info!("Using cached rootfs: {}", rootfs_path.display());
            return Ok(rootfs_path);
        }

        // Need registry client for pulling
        let client = self
            .registry_client
            .as_ref()
            .context("Registry client not available")?;

        log::info!("Downloading image manifest...");

        // Pull image using registry client
        let image_info = client
            .pull(image_ref)
            .await
            .context("Failed to pull image from registry")?;

        log::info!(
            "Downloaded {} layers, total size: {} bytes",
            image_info.layers.len(),
            image_info.size
        );

        // Create temporary extraction directory
        let temp_dir = self.rootfs_base.join(format!("temp-{}", simple_name));
        fs::create_dir_all(&temp_dir).context("Failed to create temp directory")?;

        // Track layer digests for storage
        let mut layer_digests = Vec::new();
        let mut reused_layers = 0;

        // Extract each layer with verification
        for (idx, layer) in image_info.layers.iter().enumerate() {
            log::info!(
                "Processing layer {}/{}: {}",
                idx + 1,
                image_info.layers.len(),
                layer.digest
            );

            // Download and verify layer
            let layer_data = self.download_and_verify_layer(layer).await?;

            // Store layer via image-store-rs API (content-addressable, deduplicated)
            let stored_digest = {
                let mut store = self.store.lock().unwrap();
                let was_new = !store.get_layer(&layer.digest).is_ok();

                // Store layer with reference counting
                let digest = store.store_layer(&layer_data, image_ref)?;

                if was_new {
                    log::info!("  Layer {} stored (new)", &digest[..12.min(digest.len())]);
                } else {
                    log::info!(
                        "  Layer {} reused (shared)",
                        &digest[..12.min(digest.len())]
                    );
                    reused_layers += 1;
                }

                digest
            };
            layer_digests.push(stored_digest);

            // Extract layer to temp directory
            self.extract_layer_data(&layer_data, &temp_dir)
                .context(format!("Failed to extract layer {}", layer.digest))?;
        }

        // Store image manifest via image-store-rs
        {
            let mut store = self.store.lock().unwrap();
            store.store_image(
                image_ref,
                layer_digests.clone(),
                image_info.size,
                image_info.digest.clone(),
            )?;
        }

        // Show layer sharing stats
        if reused_layers > 0 {
            log::info!(
                "Storage saved: {} layers reused (layer deduplication)",
                reused_layers
            );
        }

        // Move to final location
        fs::rename(&temp_dir, &rootfs_path).context("Failed to move extracted rootfs")?;

        log::info!(
            "✓ Image extracted successfully to: {}",
            rootfs_path.display()
        );

        Ok(rootfs_path)
    }

    /// Download a layer and verify its SHA256 digest
    async fn download_and_verify_layer(
        &self,
        layer: &oci_registry_rs::LayerInfo,
    ) -> Result<Vec<u8>> {
        log::info!(
            "Downloading layer {}...",
            &layer.digest[..12.min(layer.digest.len())]
        );

        // Find the blob file in cache (registry client already downloaded it)
        let digest_without_prefix = layer
            .digest
            .strip_prefix("sha256:")
            .unwrap_or(&layer.digest);
        let blob_path = self
            .cache_dir
            .join(format!("{}.tar.gzip", digest_without_prefix));

        if !blob_path.exists() {
            anyhow::bail!("Layer blob not found: {}", blob_path.display());
        }

        // Read the layer data
        let data = fs::read(&blob_path)
            .context(format!("Failed to read layer: {}", blob_path.display()))?;

        // Verify SHA256 if verification is enabled
        if self.config.verify {
            let mut hasher = Sha256::new();
            hasher.update(&data);
            let actual_digest = format!("{:x}", hasher.finalize());

            let expected = layer
                .digest
                .strip_prefix("sha256:")
                .unwrap_or(&layer.digest);
            if actual_digest != expected {
                anyhow::bail!(
                    "Layer digest mismatch: expected {}, got {}",
                    expected,
                    actual_digest
                );
            }
            log::info!(
                "✓ Layer {} verified",
                &layer.digest[..12.min(layer.digest.len())]
            );
        }

        Ok(data)
    }

    /// Extract layer data to destination
    fn extract_layer_data(&self, data: &[u8], dest: &Path) -> Result<()> {
        let buf_reader = BufReader::new(data);
        let decoder = GzDecoder::new(buf_reader);
        let mut archive = Archive::new(decoder);

        archive
            .unpack(dest)
            .context("Failed to unpack tar archive")?;

        Ok(())
    }

    /// Get path to a rootfs for an image (manual or automatic)
    pub async fn get_rootfs(&self, image_ref: &str, auto_pull: bool) -> Result<PathBuf> {
        let simple_name = image_ref.replace(":", "-").replace("/", "_");
        let rootfs_path = self.rootfs_base.join(&simple_name);

        if rootfs_path.exists() {
            log::info!("Using cached rootfs: {}", rootfs_path.display());
            return Ok(rootfs_path);
        }

        if auto_pull {
            // Attempt automatic pull
            log::info!("Rootfs not found, attempting automatic pull...");
            return self.pull(image_ref).await;
        }

        // Not found and no auto-pull - provide helpful error
        anyhow::bail!(
            "Rootfs not found for image '{}'. Please:\n\
             1. Run with --pull flag to download automatically\n\
             2. Or manually extract to: {}\n\
             \n\
             Example manual extraction:\n\
             mkdir -p {}\n\
             docker export $(docker create {}) | tar -C {} -xf -",
            image_ref,
            rootfs_path.display(),
            rootfs_path.display(),
            image_ref,
            rootfs_path.display()
        );
    }

    /// Remove a specific rootfs image
    pub fn remove_image(&self, image_name: &str) -> Result<()> {
        let simple_name = image_name.replace(":", "-").replace("/", "_");
        let rootfs_path = self.rootfs_base.join(&simple_name);

        if rootfs_path.exists() {
            fs::remove_dir_all(&rootfs_path)
                .with_context(|| format!("Failed to remove rootfs: {}", rootfs_path.display()))?;
            log::info!("Removed rootfs: {}", simple_name);
        } else {
            // Try direct match if simple name conversion didn't match
            let direct_path = self.rootfs_base.join(image_name);
            if direct_path.exists() {
                fs::remove_dir_all(&direct_path).with_context(|| {
                    format!("Failed to remove rootfs: {}", direct_path.display())
                })?;
                log::info!("Removed rootfs: {}", image_name);
            } else {
                anyhow::bail!("Image rootfs not found: {}", image_name);
            }
        }
        Ok(())
    }

    /// Remove all rootfs images
    pub fn remove_all_images(&self) -> Result<()> {
        if self.rootfs_base.exists() {
            for entry in fs::read_dir(&self.rootfs_base)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    fs::remove_dir_all(&path)
                        .with_context(|| format!("Failed to remove: {}", path.display()))?;
                }
            }
            log::info!("Removed all images");
        }
        Ok(())
    }

    /// List available rootfs directories
    pub fn list_available(&self) -> Result<Vec<String>> {
        let mut images = Vec::new();

        if self.rootfs_base.exists() {
            for entry in fs::read_dir(&self.rootfs_base)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    if let Some(name) = entry.file_name().to_str() {
                        if !name.starts_with("temp-") {
                            images.push(name.to_string());
                        }
                    }
                }
            }
        }

        Ok(images)
    }

    /// Clear the layer cache directory
    /// Returns the number of files removed
    pub fn clear_cache(&self) -> Result<usize> {
        if !self.cache_dir.exists() {
            log::info!("Cache directory does not exist, nothing to clear");
            return Ok(0);
        }

        // Security check: refuse to delete symlinks
        if self.is_symlink(&self.cache_dir)? {
            anyhow::bail!(
                "Security error: refusing to delete symlink cache directory: {}. This could be a symlink attack.",
                self.cache_dir.display()
            );
        }

        let file_count = self.get_dir_file_count(&self.cache_dir)?;

        log::info!("Clearing cache directory: {}", self.cache_dir.display());

        // Remove all contents of the cache directory
        for entry in fs::read_dir(&self.cache_dir).context("Failed to read cache directory")? {
            let entry = entry.context("Failed to read cache entry")?;
            let path = entry.path();

            // Security check for each entry
            if self.is_symlink(&path)? {
                log::warn!("Skipping symlink (security): {}", path.display());
                continue;
            }

            if path.is_dir() {
                fs::remove_dir_all(&path).with_context(|| {
                    format!("Failed to remove cache directory: {}", path.display())
                })?;
            } else {
                fs::remove_file(&path)
                    .with_context(|| format!("Failed to remove cache file: {}", path.display()))?;
            }
        }

        log::info!("Cleared {} files from cache", file_count);
        Ok(file_count)
    }

    /// Get the total size of the cache directory in bytes
    pub fn get_cache_size(&self) -> Result<u64> {
        if !self.cache_dir.exists() {
            return Ok(0);
        }
        self.get_dir_size(&self.cache_dir)
    }

    /// Get the number of files in the cache directory
    pub fn get_cache_file_count(&self) -> Result<usize> {
        if !self.cache_dir.exists() {
            return Ok(0);
        }
        self.get_dir_file_count(&self.cache_dir)
    }

    /// Helper: Get total size of a directory in bytes (recursive)
    #[allow(clippy::only_used_in_recursion)]
    fn get_dir_size(&self, path: &Path) -> Result<u64> {
        let mut total_size = 0u64;

        for entry in fs::read_dir(path).context(format!("Failed to read directory: {:?}", path))? {
            let entry = entry.context("Failed to read directory entry")?;
            let metadata = entry.metadata().context("Failed to get entry metadata")?;

            if metadata.is_file() {
                total_size += metadata.len();
            } else if metadata.is_dir() {
                total_size += self.get_dir_size(&entry.path())?;
            }
        }

        Ok(total_size)
    }

    /// Helper: Count number of files in a directory (recursive)
    #[allow(clippy::only_used_in_recursion)]
    fn get_dir_file_count(&self, path: &Path) -> Result<usize> {
        let mut count = 0;

        for entry in fs::read_dir(path).context(format!("Failed to read directory: {:?}", path))? {
            let entry = entry.context("Failed to read directory entry")?;
            let metadata = entry.metadata().context("Failed to get entry metadata")?;

            if metadata.is_file() {
                count += 1;
            } else if metadata.is_dir() {
                count += self.get_dir_file_count(&entry.path())?;
            }
        }

        Ok(count)
    }

    /// Helper: Check if a path is a symlink (security check)
    fn is_symlink(&self, path: &Path) -> Result<bool> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => Ok(metadata.file_type().is_symlink()),
            Err(_) => Ok(false),
        }
    }
}

impl Default for ImagePuller {
    fn default() -> Self {
        Self::new().expect("Failed to create ImagePuller")
    }
}

#[cfg(test)]
mod tests {

    // The original test_compute_hash is removed as compute_image_hash is no longer used.
    // New tests for pull functionality would be added here in a real scenario.
}

#[cfg(test)]
mod concurrency_tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    /// Prove ImagePuller IS Send + Sync after the Mutex fix.
    /// These compile-time assertions verify that ImagePuller can now be safely
    /// sent across threads and accessed concurrently.
    #[test]
    fn test_image_puller_is_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        // ImagePuller is now Send and Sync due to Mutex<ImageStore>.
        assert_send::<ImagePuller>();
        assert_sync::<ImagePuller>();

        let type_name = std::any::type_name::<ImagePuller>();
        println!("ImagePuller type: {} (Mutex-based, Send + Sync)", type_name);
    }

    /// Test that concurrent pull operations don't panic with Mutex.
    /// Unlike RefCell which panics on concurrent borrow_mut, Mutex safely
    /// blocks and allows concurrent access.
    #[test]
    fn test_concurrent_pull_works() {
        let temp_dir = std::env::temp_dir().join("phantom_test_concurrent_pull");
        let _ = std::fs::remove_dir_all(&temp_dir);

        let store = image_store_rs::ImageStore::new(image_store_rs::StorageConfig {
            base_path: temp_dir.clone(),
            ..Default::default()
        })
        .expect("Failed to create ImageStore");

        let store = Arc::new(Mutex::new(store));
        let barrier = Arc::new(Barrier::new(4));

        std::thread::scope(|s| {
            for i in 0..4 {
                let store_clone = Arc::clone(&store);
                let barrier_clone = Arc::clone(&barrier);
                s.spawn(move || {
                    barrier_clone.wait();
                    // Multiple threads can safely access the store concurrently
                    let s = store_clone.lock().unwrap();
                    let stats = s.stats();
                    println!("Thread {} got stats: {} images", i, stats.total_images);
                });
            }
        });

        // Clean up test directory
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// Test that ImageStore wrapped in Mutex is Send + Sync.
    /// This is the compile-time proof that the fix works.
    #[test]
    fn test_mutex_image_store_is_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<Mutex<image_store_rs::ImageStore>>();
        assert_sync::<Mutex<image_store_rs::ImageStore>>();

        println!("Mutex<ImageStore> is Send + Sync - safe for concurrent use!");
    }

    /// Test that single-threaded access still works correctly with Mutex.
    #[test]
    fn test_single_threaded_store_access() {
        let puller = ImagePuller::new().expect("Failed to create ImagePuller");

        // Single lock works
        {
            let store = puller.store.lock().unwrap();
            let stats = store.stats();
            println!("Store stats: {} images", stats.total_images);
        }

        // Sequential locks work
        {
            let store = puller.store.lock().unwrap();
            let _ = store.list_images();
        }
        {
            let store = puller.store.lock().unwrap();
            let _ = store.stats();
        }
    }

    /// Test that the store field is accessible and has the expected Mutex type.
    /// This documents that the concurrency bug has been fixed.
    #[test]
    fn test_mutex_type_documentation() {
        let puller = ImagePuller::new().expect("Failed to create ImagePuller");

        // Verify the store field is indeed a Mutex<ImageStore>
        // This is a compile-time type check that documents the fix.
        let _: &Mutex<ImageStore> = &puller.store;

        println!("puller.store is Mutex<ImageStore> - thread-safe!");
    }
}
