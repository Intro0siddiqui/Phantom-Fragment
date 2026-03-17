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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_store_retrieve() {
        let dir = tempdir().unwrap();
        let store = ContentStore::new(dir.path()).unwrap();

        let data = b"Hello, Phantom Fragment!";
        let hash = store.store(data).unwrap();

        let retrieved = store.retrieve(&hash).unwrap();
        assert_eq!(data.to_vec(), retrieved);
    }

    #[test]
    fn test_deduplication() {
        let dir = tempdir().unwrap();
        let store = ContentStore::new(dir.path()).unwrap();

        let data = b"Duplicate Data";
        let hash1 = store.store(data).unwrap();
        let hash2 = store.store(data).unwrap();

        assert_eq!(hash1, hash2);

        let meta = store.get_metadata(&hash1).unwrap();
        assert_eq!(meta.ref_count, 2);
    }

    #[test]
    fn test_compression_ratio() {
        let dir = tempdir().unwrap();
        let store = ContentStore::new(dir.path()).unwrap();

        // Create highly compressible data (repeated pattern)
        let data = vec![0u8; 1024 * 1024]; // 1MB of zeros
        let hash = store.store(&data).unwrap();

        let meta = store.get_metadata(&hash).unwrap();
        let compression_ratio = meta.size as f64 / meta.compressed_size as f64;

        println!("Original: {} bytes", meta.size);
        println!("Compressed: {} bytes", meta.compressed_size);
        println!("Compression ratio: {:.2}x", compression_ratio);

        // Zeros should compress very well
        assert!(
            compression_ratio > 10.0,
            "Should have high compression ratio for zeros"
        );
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let dir = tempdir().unwrap();
        let store = Arc::new(ContentStore::new(dir.path()).unwrap());

        let mut handles = vec![];

        for i in 0..10 {
            let store_clone = Arc::clone(&store);
            let handle = thread::spawn(move || {
                let data = vec![i as u8; 1024];
                store_clone.store(&data).unwrap()
            });
            handles.push(handle);
        }

        let hashes: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Verify all hashes are unique (different data)
        let unique_hashes: std::collections::HashSet<_> = hashes.iter().collect();
        assert_eq!(unique_hashes.len(), 10);

        // Verify all can be retrieved
        for hash in hashes {
            let data = store.retrieve(&hash).unwrap();
            assert_eq!(data.len(), 1024);
        }
    }

    #[test]
    fn test_error_handling_nonexistent_blob() {
        let dir = tempdir().unwrap();
        let store = ContentStore::new(dir.path()).unwrap();

        let result = store.retrieve("nonexistent_hash");
        assert!(result.is_err());
    }

    #[test]
    fn test_garbage_collection() {
        let dir = tempdir().unwrap();
        let mut store = ContentStore::new(dir.path()).unwrap();

        let data1 = b"data1";
        let data2 = b"data2";

        let hash1 = store.store(data1).unwrap();
        let hash2 = store.store(data2).unwrap();

        // Release hash1
        store.release(&hash1).unwrap();

        // Run GC
        let gc_stats = store.gc().unwrap();
        assert_eq!(gc_stats.removed, 1);

        // Verify hash1 is gone
        assert!(store.retrieve(&hash1).is_err());

        // Verify hash2 is still there
        assert!(store.retrieve(&hash2).is_ok());
    }

    #[test]
    fn test_storage_stats() {
        let dir = tempdir().unwrap();
        let store = ContentStore::new(dir.path()).unwrap();

        let data1 = vec![1u8; 1024];
        let data2 = vec![2u8; 2048];

        store.store(&data1).unwrap();
        store.store(&data2).unwrap();

        let stats = store.get_stats();
        assert_eq!(stats.total_blobs, 2);
        assert_eq!(stats.total_size, 1024 + 2048);
        assert!(stats.compression_ratio > 0.0);
    }

    #[test]
    fn test_metadata_persistence() {
        let dir = tempdir().unwrap();
        let data = b"persistent data";

        let hash = {
            let store = ContentStore::new(dir.path()).unwrap();
            store.store(data).unwrap()
        };

        // Reopen store
        let store = ContentStore::new(dir.path()).unwrap();

        // Verify data is still there
        let retrieved = store.retrieve(&hash).unwrap();
        assert_eq!(data.to_vec(), retrieved);

        // Verify metadata
        let meta = store.get_metadata(&hash).unwrap();
        assert_eq!(meta.ref_count, 1);
    }

    #[test]
    fn test_large_blob() {
        let dir = tempdir().unwrap();
        let store = ContentStore::new(dir.path()).unwrap();

        // 10MB blob
        let data = vec![42u8; 10 * 1024 * 1024];
        let hash = store.store(&data).unwrap();

        let retrieved = store.retrieve(&hash).unwrap();
        assert_eq!(data, retrieved);
    }

    #[test]
    fn test_empty_blob() {
        let dir = tempdir().unwrap();
        let store = ContentStore::new(dir.path()).unwrap();

        let data = b"";
        let hash = store.store(data).unwrap();

        let retrieved = store.retrieve(&hash).unwrap();
        assert_eq!(data.to_vec(), retrieved);
    }

    #[test]
    fn test_multiple_releases() {
        let dir = tempdir().unwrap();
        let mut store = ContentStore::new(dir.path()).unwrap();

        let data = b"test";
        let hash = store.store(data).unwrap();
        store.store(data).unwrap(); // ref_count = 2

        let meta = store.get_metadata(&hash).unwrap();
        assert_eq!(meta.ref_count, 2);

        // Release once
        store.release(&hash).unwrap();
        let meta = store.get_metadata(&hash).unwrap();
        assert_eq!(meta.ref_count, 1);

        // Release again
        store.release(&hash).unwrap();
        let meta = store.get_metadata(&hash).unwrap();
        assert_eq!(meta.ref_count, 0);

        // GC should remove it
        let gc_stats = store.gc().unwrap();
        assert_eq!(gc_stats.removed, 1);
    }

    #[test]
    fn test_hash_consistency() {
        let dir = tempdir().unwrap();
        let store = ContentStore::new(dir.path()).unwrap();

        let data = b"consistent data";
        let hash1 = store.store(data).unwrap();

        // Store same data again
        let hash2 = store.store(data).unwrap();

        assert_eq!(hash1, hash2);

        // Verify hash matches SHA256
        let mut hasher = Sha256::new();
        hasher.update(data);
        let expected_hash = hex::encode(hasher.finalize());

        assert_eq!(hash1, expected_hash);
    }
}
