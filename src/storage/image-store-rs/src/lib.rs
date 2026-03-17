//! Smart Image Storage with Auto-sizing and LRU Cleanup
//!
//! Manages image storage with:
//! - Automatic disk space detection
//! - Flexible sizing based on available space
//! - LRU (Least Recently Used) eviction
//! - Configurable size and age limits
//! - Content-addressable storage for deduplication
//! - Layer reference counting for shared layers

mod blob_store;

pub use blob_store::{BlobStore, BlobStoreStats, LayerRef, LayerRefStats};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Base storage directory
    pub base_path: PathBuf,

    /// Maximum cache size in bytes (None = auto)
    pub max_size: Option<u64>,

    /// Percentage of available disk to use (default: 80%)
    pub disk_usage_percent: Option<u8>,

    /// Maximum age for images in seconds (None = no age limit)
    pub max_age_seconds: Option<u64>,

    /// Enable LRU eviction
    pub enable_lru: bool,

    /// Minimum free space to maintain (bytes)
    pub min_free_space: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            base_path: PathBuf::from("~/.phantom/images"),
            max_size: None, // Auto-size
            disk_usage_percent: Some(80),
            max_age_seconds: Some(30 * 24 * 3600), // 30 days
            enable_lru: true,
            min_free_space: 5 * 1024 * 1024 * 1024, // 5 GB
        }
    }
}

/// Image metadata for tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageMetadata {
    /// Image reference
    pub reference: String,

    /// Size in bytes
    pub size: u64,

    /// Creation timestamp
    pub created_at: u64,

    /// Last accessed timestamp
    pub last_accessed: u64,

    /// Number of times accessed
    pub access_count: u64,

    /// Digest
    pub digest: String,

    /// Layer digests this image references (for shared layer tracking)
    pub layer_digests: Vec<String>,
}

/// Image manifest for storing layer references
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageManifest {
    pub name: String,
    pub layers: Vec<String>,
    pub created_at: u64,
}

/// Smart image storage manager with content-addressable layer storage
pub struct ImageStore {
    config: StorageConfig,
    metadata: HashMap<String, ImageMetadata>,
    metadata_path: PathBuf,
    dirty: bool,
    /// Content-addressable blob store for layer deduplication
    blob_store: BlobStore,
}

impl ImageStore {
    /// Create a new image store
    pub fn new(config: StorageConfig) -> Result<Self> {
        // Expand ~ in path
        let base_path = shellexpand::tilde(&config.base_path.to_string_lossy()).into_owned();
        let base_path = PathBuf::from(base_path);

        // Create directories
        fs::create_dir_all(&base_path)?;
        let blobs_dir = base_path.join("blobs");
        fs::create_dir_all(&blobs_dir)?;
        fs::create_dir_all(base_path.join("images"))?;

        let metadata_path = base_path.join("metadata.json");

        // Initialize blob store for content-addressable layer storage
        let blob_store = BlobStore::new(&blobs_dir)?;

        // Load existing metadata
        let metadata = if metadata_path.exists() {
            let content = fs::read_to_string(&metadata_path)?;
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            HashMap::new()
        };

        let mut store = Self {
            config: StorageConfig {
                base_path,
                ..config
            },
            metadata,
            metadata_path,
            dirty: false,
            blob_store,
        };

        // Auto-adjust size on init
        store.auto_adjust_size()?;

        Ok(store)
    }

    /// Auto-adjust cache size based on available disk space
    pub fn auto_adjust_size(&mut self) -> Result<()> {
        if self.config.max_size.is_some() {
            // Manual size set, don't auto-adjust
            return Ok(());
        }

        // Get available disk space
        let available = self.get_available_disk_space()?;

        // Use configured percentage (default 80%)
        let percent = self.config.disk_usage_percent.unwrap_or(80) as u64;
        let calculated_max = (available * percent) / 100;

        // Ensure minimum free space
        let max_size = calculated_max.saturating_sub(self.config.min_free_space);

        log::info!(
            "Auto-sized cache: {} GB ({}% of {} GB available)",
            max_size / (1024 * 1024 * 1024),
            percent,
            available / (1024 * 1024 * 1024)
        );

        self.config.max_size = Some(max_size);
        Ok(())
    }

    /// Get available disk space
    fn get_available_disk_space(&self) -> Result<u64> {
        use std::process::Command;

        // Use df command to get disk space
        let output = Command::new("df")
            .arg("-B1") // 1-byte blocks
            .arg(&self.config.base_path)
            .output()?;

        if !output.status.success() {
            return Err(anyhow::anyhow!("Failed to get disk space"));
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        // Parse df output (second line, fourth column for available)
        let available = output_str
            .lines()
            .nth(1)
            .and_then(|line| line.split_whitespace().nth(3))
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or_else(|| anyhow::anyhow!("Failed to parse df output"))?;

        Ok(available)
    }

    /// Get current cache size
    pub fn current_size(&self) -> u64 {
        self.metadata.values().map(|m| m.size).sum()
    }

    /// Check if we need cleanup
    pub fn needs_cleanup(&self) -> bool {
        if let Some(max_size) = self.config.max_size {
            if self.current_size() > max_size {
                return true;
            }
        }
        false
    }

    /// Perform LRU cleanup to free space
    pub fn cleanup_lru(&mut self, target_size: u64) -> Result<Vec<String>> {
        if !self.config.enable_lru {
            return Ok(Vec::new());
        }

        let current = self.current_size();
        if current <= target_size {
            return Ok(Vec::new());
        }

        // Sort images by last accessed (oldest first) and collect references to remove
        let mut images: Vec<(String, u64, u64)> = self
            .metadata
            .iter()
            .map(|(ref_, meta)| (ref_.clone(), meta.last_accessed, meta.size))
            .collect();
        images.sort_by_key(|(_, last_accessed, _)| *last_accessed);

        let mut removed = Vec::new();
        let mut freed = 0u64;
        let needed = current - target_size;

        for (reference, _, size) in images {
            if freed >= needed {
                break;
            }

            log::info!("LRU evicting: {} ({} bytes)", reference, size);
            self.remove_image(&reference)?;
            freed += size;
            removed.push(reference);
        }

        log::info!(
            "LRU cleanup: freed {} bytes, removed {} images",
            freed,
            removed.len()
        );
        Ok(removed)
    }

    /// Cleanup old images based on age
    pub fn cleanup_by_age(&mut self) -> Result<Vec<String>> {
        let max_age = match self.config.max_age_seconds {
            Some(age) => age,
            None => return Ok(Vec::new()),
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut removed = Vec::new();
        let mut to_remove = Vec::new();

        for (reference, meta) in &self.metadata {
            let age = now.saturating_sub(meta.created_at);
            if age > max_age {
                to_remove.push(reference.clone());
            }
        }

        for reference in to_remove {
            log::info!("Age-based eviction: {}", reference);
            self.remove_image(&reference)?;
            removed.push(reference);
        }

        if !removed.is_empty() {
            log::info!("Age-based cleanup: removed {} images", removed.len());
        }

        Ok(removed)
    }

    /// Record image access (for LRU tracking)
    pub fn record_access(&mut self, reference: &str) -> Result<()> {
        if let Some(meta) = self.metadata.get_mut(reference) {
            meta.last_accessed = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            meta.access_count += 1;
            self.dirty = true;
        }
        Ok(())
    }

    /// Store a layer with deduplication (content-addressable)
    /// Returns the layer digest
    pub fn store_layer(&mut self, layer_data: &[u8], image_ref: &str) -> Result<String> {
        self.blob_store.store_blob_with_ref(layer_data, image_ref)
    }

    /// Store an image with its layer digests
    /// This creates an image manifest referencing shared layers
    pub fn store_image(
        &mut self,
        name: &str,
        layer_digests: Vec<String>,
        size: u64,
        digest: String,
    ) -> Result<PathBuf> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let meta = ImageMetadata {
            reference: name.to_string(),
            size,
            created_at: now,
            last_accessed: now,
            access_count: 1,
            digest,
            layer_digests: layer_digests.clone(),
        };

        // Store image manifest in images directory
        let simple_name = name.replace(":", "_").replace("/", "_");
        let image_dir = self.config.base_path.join("images").join(&simple_name);
        fs::create_dir_all(&image_dir)?;

        // Write manifest
        let manifest_path = image_dir.join("manifest.json");
        let manifest = ImageManifest {
            name: name.to_string(),
            layers: layer_digests,
            created_at: now,
        };
        fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)?;

        log::info!("Stored image manifest: {}", name);

        // Add to metadata
        self.add_image(meta)?;

        Ok(image_dir)
    }

    /// Get image path by reference
    pub fn get_image_path(&self, image_ref: &str) -> Option<PathBuf> {
        let simple_name = image_ref.replace(":", "_").replace("/", "_");
        let image_dir = self.config.base_path.join("images").join(&simple_name);
        if image_dir.exists() {
            Some(image_dir)
        } else {
            None
        }
    }

    /// Get layer data by digest
    pub fn get_layer(&self, digest: &str) -> Result<Vec<u8>> {
        self.blob_store.get_blob(digest)
    }

    /// Get layer sharing statistics
    pub fn layer_stats(&self) -> LayerRefStats {
        self.blob_store.ref_stats()
    }

    /// Add image to store
    pub fn add_image(&mut self, meta: ImageMetadata) -> Result<()> {
        if self.needs_cleanup() {
            if let Some(max_size) = self.config.max_size {
                let target = (max_size * 90) / 100;
                self.cleanup_lru(target)?;
            }
        }

        self.metadata.insert(meta.reference.clone(), meta);
        self.dirty = true;
        self.save_metadata()?;
        Ok(())
    }

    /// Remove image from store with layer reference counting
    pub fn remove_image(&mut self, reference: &str) -> Result<()> {
        // Get layer digests before removing metadata
        let layer_digests = self
            .metadata
            .get(reference)
            .map(|m| m.layer_digests.clone())
            .unwrap_or_default();

        if let Some(meta) = self.metadata.remove(reference) {
            self.dirty = true;
            self.save_metadata()?;

            // Decrement reference counts for all layers
            for digest in &layer_digests {
                if let Err(e) = self.blob_store.decrement_ref_count(digest, reference) {
                    log::warn!("Failed to decrement ref count for {}: {}", digest, e);
                }
            }

            // Physically delete the rootfs if it exists
            let simple_name = reference.replace(":", "-").replace("/", "_");
            let image_dir = self.config.base_path.join("images").join(&simple_name);
            if image_dir.exists() {
                fs::remove_dir_all(&image_dir)?;
                log::info!(
                    "Physically removed image directory: {}",
                    image_dir.display()
                );
            }

            // Also check for the digest-based directory if it exists
            let digest_dir = self.config.base_path.join("images").join(&meta.digest);
            if digest_dir.exists() {
                fs::remove_dir_all(&digest_dir)?;
            }
        }
        Ok(())
    }

    /// Get image metadata
    pub fn get_image(&self, reference: &str) -> Option<&ImageMetadata> {
        self.metadata.get(reference)
    }

    /// List all images
    pub fn list_images(&self) -> Vec<ImageMetadata> {
        self.metadata.values().cloned().collect()
    }

    /// Save metadata to disk (only if dirty)
    fn save_metadata(&mut self) -> Result<()> {
        if !self.dirty {
            return Ok(());
        }
        let json = serde_json::to_string_pretty(&self.metadata)?;
        fs::write(&self.metadata_path, json)?;
        self.dirty = false;
        Ok(())
    }

    /// Explicitly flush pending metadata changes to disk
    pub fn flush(&mut self) -> Result<()> {
        self.save_metadata()
    }

    /// Get storage statistics
    pub fn stats(&self) -> StorageStats {
        StorageStats {
            total_images: self.metadata.len(),
            total_size: self.current_size(),
            max_size: self.config.max_size,
            oldest_image: self
                .metadata
                .values()
                .min_by_key(|m| m.created_at)
                .map(|m| m.reference.clone()),
            newest_image: self
                .metadata
                .values()
                .max_by_key(|m| m.created_at)
                .map(|m| m.reference.clone()),
        }
    }
}

impl Drop for ImageStore {
    fn drop(&mut self) {
        if self.dirty {
            if let Err(e) = self.save_metadata() {
                log::warn!("Failed to flush metadata on drop: {}", e);
            }
        }
    }
}

/// Storage statistics
#[derive(Debug, Clone, Serialize)]
pub struct StorageStats {
    pub total_images: usize,
    pub total_size: u64,
    pub max_size: Option<u64>,
    pub oldest_image: Option<String>,
    pub newest_image: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_config_default() {
        let config = StorageConfig::default();
        assert_eq!(config.disk_usage_percent, Some(80));
        assert!(config.enable_lru);
    }

    #[test]
    fn test_lru_sorting() {
        let meta1 = ImageMetadata {
            reference: "image1:latest".to_string(),
            size: 1000,
            created_at: 100,
            last_accessed: 100,
            access_count: 1,
            digest: "sha256:abc".to_string(),
            layer_digests: vec!["sha256:layer1".to_string()],
        };

        let meta2 = ImageMetadata {
            reference: "image2:latest".to_string(),
            size: 2000,
            created_at: 200,
            last_accessed: 300,
            access_count: 5,
            digest: "sha256:def".to_string(),
            layer_digests: vec!["sha256:layer2".to_string()],
        };

        // meta1 accessed earlier = should be evicted first
        assert!(meta1.last_accessed < meta2.last_accessed);
    }
}
