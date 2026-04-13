//! Content-Addressed Storage (CAS)
//!
//! Provides deduplicated storage for container layers and assets using SHA256 hashing.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use types_rs::PhantomError;

use serde::{Deserialize, Serialize};

/// Metadata for a stored blob
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobMetadata {
    pub hash: String,
    pub size: u64,
    pub compressed_size: u64,
    pub ref_count: u32,
}

/// Storage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    pub total_blobs: usize,
    pub total_size: u64,
    pub compressed_size: u64,
    pub compression_ratio: f64,
    pub dedup_count: u32,
    pub space_saved: u64,
}

/// Garbage collection statistics
#[derive(Debug, Clone)]
pub struct GcStats {
    pub removed: usize,
    pub space_freed: u64,
}

/// Content-Addressed Store
pub struct ContentStore {
    root_path: PathBuf,
    metadata_path: PathBuf,
    metadata: Arc<Mutex<HashMap<String, BlobMetadata>>>,
}

impl ContentStore {
    /// Open or create a store at the specified path
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, PhantomError> {
        let root_path = path.as_ref().to_path_buf();
        fs::create_dir_all(&root_path)
            .map_err(|e| PhantomError::Internal(format!("Failed to create storage root: {}", e)))?;

        let metadata_path = root_path.join("metadata.json");
        let metadata = if metadata_path.exists() {
            let file = File::open(&metadata_path)
                .map_err(|e| PhantomError::Internal(format!("Failed to open metadata: {}", e)))?;
            serde_json::from_reader(file)
                .map_err(|e| PhantomError::Internal(format!("Failed to parse metadata: {}", e)))?
        } else {
            HashMap::new()
        };

        Ok(Self {
            root_path,
            metadata_path,
            metadata: Arc::new(Mutex::new(metadata)),
        })
    }

    /// Store data, returning its hash
    pub fn store(&self, data: &[u8]) -> Result<String, PhantomError> {
        // Calculate hash
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hex::encode(hasher.finalize());

        let mut meta_lock = match self.metadata.lock() {
            Ok(guard) => guard,
            Err(e) => {
                return Err(PhantomError::Internal(format!(
                    "Metadata lock poisoned: {}",
                    e
                )))
            }
        };

        // Check if already exists
        if let Some(meta) = meta_lock.get_mut(&hash) {
            meta.ref_count += 1;
            self.save_metadata_locked(&meta_lock)?;
            return Ok(hash);
        }

        // Compress data
        let compressed = zstd::encode_all(data, 3) // Level 3 compression
            .map_err(|e| PhantomError::Internal(format!("Compression failed: {}", e)))?;

        // Write to disk
        let blob_path = self.get_blob_path(&hash);
        let mut file = File::create(&blob_path)
            .map_err(|e| PhantomError::Internal(format!("Failed to create blob file: {}", e)))?;
        file.write_all(&compressed)
            .map_err(|e| PhantomError::Internal(format!("Failed to write blob: {}", e)))?;

        // Update metadata
        meta_lock.insert(
            hash.clone(),
            BlobMetadata {
                hash: hash.clone(),
                size: data.len() as u64,
                compressed_size: compressed.len() as u64,
                ref_count: 1,
            },
        );
        self.save_metadata_locked(&meta_lock)?;

        Ok(hash)
    }

    fn save_metadata_locked(
        &self,
        metadata: &HashMap<String, BlobMetadata>,
    ) -> Result<(), PhantomError> {
        let file = File::create(&self.metadata_path).map_err(|e| {
            PhantomError::Internal(format!("Failed to create metadata file: {}", e))
        })?;
        serde_json::to_writer(file, metadata)
            .map_err(|e| PhantomError::Internal(format!("Failed to write metadata: {}", e)))?;
        Ok(())
    }

    /// Retrieve data by hash
    pub fn retrieve(&self, hash: &str) -> Result<Vec<u8>, PhantomError> {
        let blob_path = self.get_blob_path(hash);
        if !blob_path.exists() {
            return Err(PhantomError::Internal(format!("Blob not found: {}", hash)));
        }

        let mut file = File::open(&blob_path)
            .map_err(|e| PhantomError::Internal(format!("Failed to open blob: {}", e)))?;
        let mut compressed = Vec::new();
        file.read_to_end(&mut compressed)
            .map_err(|e| PhantomError::Internal(format!("Failed to read blob: {}", e)))?;

        let data = zstd::decode_all(&compressed[..])
            .map_err(|e| PhantomError::Internal(format!("Decompression failed: {}", e)))?;

        Ok(data)
    }

    /// Helper to get path for a hash
    fn get_blob_path(&self, hash: &str) -> PathBuf {
        self.root_path.join(hash)
    }

    /// Get metadata for a hash
    pub fn get_metadata(&self, hash: &str) -> Option<BlobMetadata> {
        match self.metadata.lock() {
            Ok(meta_lock) => meta_lock.get(hash).cloned(),
            Err(e) => {
                log::error!("Metadata lock poisoned: {}", e);
                None
            }
        }
    }

    /// Get storage statistics
    pub fn get_stats(&self) -> StorageStats {
        let meta = match self.metadata.lock() {
            Ok(guard) => guard,
            Err(e) => {
                log::error!("Metadata lock poisoned: {}", e);
                return StorageStats {
                    total_blobs: 0,
                    total_size: 0,
                    compressed_size: 0,
                    compression_ratio: 1.0,
                    dedup_count: 0,
                    space_saved: 0,
                };
            }
        };
        let total_blobs = meta.len();
        let total_size: u64 = meta.values().map(|m| m.size).sum();
        let compressed_size: u64 = meta.values().map(|m| m.compressed_size).sum();
        let dedup_count: u32 = meta.values().filter(|m| m.ref_count > 1).count() as u32;

        StorageStats {
            total_blobs,
            total_size,
            compressed_size,
            compression_ratio: if compressed_size > 0 {
                total_size as f64 / compressed_size as f64
            } else {
                1.0
            },
            dedup_count,
            space_saved: total_size.saturating_sub(compressed_size),
        }
    }

    /// Perform garbage collection (remove blobs with ref_count = 0)
    pub fn gc(&mut self) -> Result<GcStats, PhantomError> {
        let mut meta = match self.metadata.lock() {
            Ok(guard) => guard,
            Err(e) => {
                return Err(PhantomError::Internal(format!(
                    "Metadata lock poisoned: {}",
                    e
                )))
            }
        };
        let mut removed = 0;
        let mut space_freed = 0u64;

        let to_remove: Vec<String> = meta
            .iter()
            .filter(|(_, blob)| blob.ref_count == 0)
            .map(|(hash, _)| hash.clone())
            .collect();

        for hash in to_remove {
            if let Some(_blob_meta) = meta.remove(&hash) {
                let blob_path = self.get_blob_path(&hash);
                if blob_path.exists() {
                    if let Ok(file_meta) = std::fs::metadata(&blob_path) {
                        space_freed += file_meta.len();
                    }
                    let _ = std::fs::remove_file(blob_path);
                    removed += 1;
                }
            }
        }

        if removed > 0 {
            self.save_metadata_locked(&meta)?;
        }

        Ok(GcStats {
            removed,
            space_freed,
        })
    }

    /// Decrement reference count for a blob
    pub fn release(&mut self, hash: &str) -> Result<(), PhantomError> {
        let mut meta = match self.metadata.lock() {
            Ok(guard) => guard,
            Err(e) => {
                return Err(PhantomError::Internal(format!(
                    "Metadata lock poisoned: {}",
                    e
                )))
            }
        };

        if let Some(blob_meta) = meta.get_mut(hash) {
            if blob_meta.ref_count > 0 {
                blob_meta.ref_count -= 1;
            }
            self.save_metadata_locked(&meta)?;
        }

        Ok(())
    }
}
