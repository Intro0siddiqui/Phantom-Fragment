use storage_rs::*;
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
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let expected_hash = hex::encode(hasher.finalize());

    assert_eq!(hash1, expected_hash);
}
