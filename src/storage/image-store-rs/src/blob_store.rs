//! Content-Addressable Storage for Image Layers
//!
//! Implements CAS (Content-Addressable Storage) for efficient
//! layer deduplication across images
//!
//! Features:
//! - Content-addressable storage using SHA256 digests
//! - Layer deduplication (same layer stored once)
//! - Reference counting for shared layers
//! - Automatic cleanup of unreferenced layers

use anyhow::Result;
use compression_rs::{Compressor, ZstdCompressor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Track layer references for deduplication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerRef {
    /// Number of images referencing this layer
    pub ref_count: u64,
    /// Size of the layer in bytes
    pub size: u64,
    /// When the layer was first stored (Unix timestamp)
    pub created_at: u64,
    /// List of image references that use this layer
    pub referenced_by: Vec<String>,
}

/// Content-addressable storage manager with reference counting
pub struct BlobStore {
    base_path: PathBuf,
    /// Track layer references for deduplication and cleanup
    layer_refs: HashMap<String, LayerRef>,
    /// Path to layer reference metadata
    refs_path: PathBuf,
    /// Dirty flag for metadata
    dirty: bool,
}

impl BlobStore {
    /// Create a new blob store
    pub fn new<P: AsRef<Path>>(base_path: P) -> Result<Self> {
        let base_path = base_path.as_ref().to_path_buf();
        fs::create_dir_all(&base_path)?;

        let refs_path = base_path.join("layer_refs.json");

        // Load existing layer references
        let layer_refs = if refs_path.exists() {
            let content = fs::read_to_string(&refs_path)?;
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            HashMap::new()
        };

        Ok(Self {
            base_path,
            layer_refs,
            refs_path,
            dirty: false,
        })
    }

    /// Store a blob and return its digest
    pub fn store_blob(&self, data: &[u8]) -> Result<String> {
        // Calculate SHA256 digest
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        let digest = format!("sha256:{}", hex::encode(hash));

        // Use content-addressable path
        let blob_path = self.blob_path(&digest);

        // Only write if doesn't exist (deduplication!)
        if !blob_path.exists() {
            if let Some(parent) = blob_path.parent() {
                fs::create_dir_all(parent)?;
            }

            let mut file = fs::File::create(&blob_path)?;
            file.write_all(data)?;

            log::debug!("Stored new blob: {} ({} bytes)", digest, data.len());
        } else {
            log::debug!("Blob already exists (deduplicated): {}", digest);
        }

        Ok(digest)
    }

    /// Store a blob with reference tracking (for layer sharing)
    pub fn store_blob_with_ref(&mut self, data: &[u8], image_ref: &str) -> Result<String> {
        // Calculate SHA256 digest
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        let digest = format!("sha256:{}", hex::encode(hash));

        // Use content-addressable path
        let blob_path = self.blob_path(&digest);
        let size = data.len() as u64;

        // Only write if doesn't exist (deduplication!)
        let is_new = !blob_path.exists();
        if is_new {
            if let Some(parent) = blob_path.parent() {
                fs::create_dir_all(parent)?;
            }

            let mut file = fs::File::create(&blob_path)?;
            file.write_all(data)?;

            log::info!("Layer {} stored (new)", &digest[..12]);
        } else {
            log::info!("Layer {} reused (already exists)", &digest[..12]);
        }

        // Update reference count
        self.increment_ref_count(&digest, image_ref, size)?;

        Ok(digest)
    }

    /// Increment reference count for a layer
    fn increment_ref_count(&mut self, digest: &str, image_ref: &str, size: u64) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let entry = self
            .layer_refs
            .entry(digest.to_string())
            .or_insert(LayerRef {
                ref_count: 0,
                size,
                created_at: now,
                referenced_by: Vec::new(),
            });

        entry.ref_count += 1;
        if !entry.referenced_by.contains(&image_ref.to_string()) {
            entry.referenced_by.push(image_ref.to_string());
        }
        entry.size = size; // Update size if changed

        self.dirty = true;
        self.save_refs()?;

        Ok(())
    }

    /// Decrement reference count for a layer
    pub fn decrement_ref_count(&mut self, digest: &str, image_ref: &str) -> Result<bool> {
        if let Some(layer_ref) = self.layer_refs.get_mut(digest) {
            if layer_ref.ref_count > 0 {
                layer_ref.ref_count -= 1;
            }

            // Remove from referenced_by list
            layer_ref.referenced_by.retain(|r| r != image_ref);

            self.dirty = true;

            // Return true if layer should be removed (no more references)
            let should_remove = layer_ref.ref_count == 0;

            if should_remove {
                // Delete the actual blob file
                let blob_path = self.blob_path(digest);
                if blob_path.exists() {
                    fs::remove_file(&blob_path)?;
                    log::info!("Layer {} removed (no references)", &digest[..12]);
                }
                self.layer_refs.remove(digest);
            } else {
                log::info!(
                    "Layer {} kept (referenced by {} images)",
                    &digest[..12],
                    layer_ref.ref_count
                );
            }

            self.save_refs()?;
            Ok(should_remove)
        } else {
            Ok(false)
        }
    }

    /// Get reference count for a layer
    pub fn get_ref_count(&self, digest: &str) -> u64 {
        self.layer_refs
            .get(digest)
            .map(|lr| lr.ref_count)
            .unwrap_or(0)
    }

    /// Get all images referencing a layer
    pub fn get_referencing_images(&self, digest: &str) -> Vec<String> {
        self.layer_refs
            .get(digest)
            .map(|lr| lr.referenced_by.clone())
            .unwrap_or_default()
    }

    /// Save layer references to disk
    fn save_refs(&self) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.layer_refs)?;
        fs::write(&self.refs_path, json)?;
        Ok(())
    }

    /// Get layer reference statistics
    pub fn ref_stats(&self) -> LayerRefStats {
        let total_layers = self.layer_refs.len();
        let shared_layers = self
            .layer_refs
            .values()
            .filter(|lr| lr.ref_count > 1)
            .count();
        let total_refs: u64 = self.layer_refs.values().map(|lr| lr.ref_count).sum();

        LayerRefStats {
            total_layers,
            shared_layers,
            total_refs,
        }
    }

    /// Store a blob from a file
    pub fn store_file<P: AsRef<Path>>(&self, path: P) -> Result<String> {
        let data = fs::read(path)?;
        self.store_blob(&data)
    }

    /// Compress and store a blob (using Zstd)
    pub fn compress_and_store(&self, data: &[u8]) -> Result<String> {
        let mut compressed = Vec::new();
        // Use default compression level 3
        let compressor = ZstdCompressor::new(3);
        compressor.compress(&mut &data[..], &mut compressed)?;

        // Store the compressed data
        self.store_blob(&compressed)
    }

    /// Get blob data
    pub fn get_blob(&self, digest: &str) -> Result<Vec<u8>> {
        let blob_path = self.blob_path(digest);
        fs::read(blob_path).map_err(Into::into)
    }

    /// Check if blob exists
    pub fn has_blob(&self, digest: &str) -> bool {
        self.blob_path(digest).exists()
    }

    /// Delete a blob
    pub fn delete_blob(&self, digest: &str) -> Result<()> {
        let blob_path = self.blob_path(digest);
        if blob_path.exists() {
            fs::remove_file(blob_path)?;
        }
        Ok(())
    }

    /// Get path for a blob
    fn blob_path(&self, digest: &str) -> PathBuf {
        // Extract hash from sha256:hash format
        let hash = digest.strip_prefix("sha256:").unwrap_or(digest);

        // Use first 2 chars for directory sharding (prevents too many files in one dir)
        // e.g., sha256:abcd1234 -> blobs/ab/cd1234
        if hash.len() >= 4 {
            self.base_path.join(&hash[0..2]).join(&hash[2..])
        } else {
            self.base_path.join(hash)
        }
    }

    /// Get all stored blobs
    pub fn list_blobs(&self) -> Result<Vec<String>> {
        let mut blobs = Vec::new();

        if !self.base_path.exists() {
            return Ok(blobs);
        }

        for entry in fs::read_dir(&self.base_path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                let prefix = entry.file_name().to_string_lossy().to_string();

                for sub_entry in fs::read_dir(entry.path())? {
                    let sub_entry = sub_entry?;
                    if sub_entry.file_type()?.is_file() {
                        let suffix = sub_entry.file_name().to_string_lossy().to_string();
                        blobs.push(format!("sha256:{}{}", prefix, suffix));
                    }
                }
            }
        }

        Ok(blobs)
    }

    /// Calculate storage statistics
    pub fn stats(&self) -> Result<BlobStoreStats> {
        let mut total_size = 0u64;
        let mut blob_count = 0usize;

        if self.base_path.exists() {
            for entry in fs::read_dir(&self.base_path)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    for sub_entry in fs::read_dir(entry.path())? {
                        let sub_entry = sub_entry?;
                        if sub_entry.file_type()?.is_file() {
                            blob_count += 1;
                            total_size += sub_entry.metadata()?.len();
                        }
                    }
                }
            }
        }

        Ok(BlobStoreStats {
            blob_count,
            total_size,
        })
    }
}

/// Blob store statistics
#[derive(Debug, Clone)]
pub struct BlobStoreStats {
    pub blob_count: usize,
    pub total_size: u64,
}

/// Layer reference statistics
#[derive(Debug, Clone)]
pub struct LayerRefStats {
    pub total_layers: usize,
    pub shared_layers: usize,
    pub total_refs: u64,
}

impl Drop for BlobStore {
    fn drop(&mut self) {
        if self.dirty {
            if let Err(e) = self.save_refs() {
                log::warn!("Failed to save layer refs on drop: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_store_and_retrieve_blob() {
        let temp_dir = env::temp_dir().join("test_blob_store");
        let store = BlobStore::new(&temp_dir).unwrap();

        let data = b"Hello, World!";
        let digest = store.store_blob(data).unwrap();

        assert!(digest.starts_with("sha256:"));
        assert!(store.has_blob(&digest));

        let retrieved = store.get_blob(&digest).unwrap();
        assert_eq!(retrieved, data);

        // Cleanup
        fs::remove_dir_all(temp_dir).ok();
    }

    #[test]
    fn test_deduplication() {
        let temp_dir = env::temp_dir().join("test_dedup");
        let store = BlobStore::new(&temp_dir).unwrap();

        let data = b"Same data";
        let digest1 = store.store_blob(data).unwrap();
        let digest2 = store.store_blob(data).unwrap();

        // Same data = same digest
        assert_eq!(digest1, digest2);

        // Should only have one blob
        let blobs = store.list_blobs().unwrap();
        assert_eq!(blobs.len(), 1);

        // Cleanup
        fs::remove_dir_all(temp_dir).ok();
    }

    #[test]
    fn test_blob_path_sharding() {
        let temp_dir = env::temp_dir().join("test_sharding");
        let store = BlobStore::new(&temp_dir).unwrap();

        let digest = "sha256:abcd1234567890";
        let path = store.blob_path(digest);

        // Should shard into subdirectory
        assert!(path.to_string_lossy().contains("ab"));
        assert!(path.to_string_lossy().contains("cd1234567890"));

        // Cleanup
        fs::remove_dir_all(temp_dir).ok();
    }

    #[test]
    fn test_compression_round_trip() {
        use compression_rs::{Compressor, ZstdCompressor};
        let temp_dir = env::temp_dir().join("test_compression");
        let store = BlobStore::new(&temp_dir).unwrap();

        // 1. Generate heavy random data that compresses well (repetition)
        let original_data = b"RepetitionRepetitionRepetitionRepetition".repeat(1000);

        // 2. Compress and store
        let digest = store.compress_and_store(&original_data).unwrap();

        // 3. Retrieve raw blob (compressed)
        let compressed_data = store.get_blob(&digest).unwrap();
        assert!(
            compressed_data.len() < original_data.len(),
            "Compression failed to reduce size"
        );

        // 4. Decompress manually to verify integrity
        let mut decompressed = Vec::new();
        let compressor = ZstdCompressor::new(3);
        compressor
            .decompress(&mut &compressed_data[..], &mut decompressed)
            .unwrap();

        assert_eq!(decompressed, original_data, "Decompressed data mismatch!");

        // Cleanup
        fs::remove_dir_all(temp_dir).ok();
    }

    #[test]
    fn test_layer_reference_counting() {
        let temp_dir = env::temp_dir().join("test_layer_refs");
        let mut store = BlobStore::new(&temp_dir).unwrap();

        let data = b"Shared layer data";

        // Store layer with first image reference
        let digest1 = store.store_blob_with_ref(data, "alpine:latest").unwrap();
        assert_eq!(store.get_ref_count(&digest1), 1);

        // Store same layer with second image reference (should deduplicate)
        let digest2 = store.store_blob_with_ref(data, "myapp:latest").unwrap();
        assert_eq!(digest1, digest2);
        assert_eq!(store.get_ref_count(&digest1), 2);

        // Check referencing images
        let refs = store.get_referencing_images(&digest1);
        assert!(refs.contains(&"alpine:latest".to_string()));
        assert!(refs.contains(&"myapp:latest".to_string()));

        // Decrement ref count for first image
        let removed = store
            .decrement_ref_count(&digest1, "alpine:latest")
            .unwrap();
        assert!(!removed); // Should not be removed (still referenced by myapp)
        assert_eq!(store.get_ref_count(&digest1), 1);

        // Decrement ref count for second image
        let removed = store.decrement_ref_count(&digest1, "myapp:latest").unwrap();
        assert!(removed); // Should be removed (no more references)
        assert_eq!(store.get_ref_count(&digest1), 0);

        // Cleanup
        fs::remove_dir_all(temp_dir).ok();
    }

    #[test]
    fn test_layer_sharing_stats() {
        let temp_dir = env::temp_dir().join("test_sharing_stats");
        let mut store = BlobStore::new(&temp_dir).unwrap();

        let layer1 = b"Layer 1 data";
        let layer2 = b"Layer 2 data";

        // Store layer1 referenced by 2 images
        store.store_blob_with_ref(layer1, "alpine:latest").unwrap();
        store.store_blob_with_ref(layer1, "ubuntu:latest").unwrap();

        // Store layer2 referenced by 1 image
        store.store_blob_with_ref(layer2, "ubuntu:latest").unwrap();

        let stats = store.ref_stats();
        assert_eq!(stats.total_layers, 2);
        assert_eq!(stats.shared_layers, 1); // layer1 is shared
        assert_eq!(stats.total_refs, 3); // 2 + 1

        // Cleanup
        fs::remove_dir_all(temp_dir).ok();
    }
}
