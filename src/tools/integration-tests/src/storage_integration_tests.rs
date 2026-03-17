//! Storage integration tests
//! Real-world tests for content-addressed storage with 1GB OS images and fragment layers

#[cfg(test)]
mod tests {
    use crate::test_helpers::{create_file_with_size, find_large_system_file};
    use sha2::{Digest, Sha256};
    use std::fs::File;
    use std::io::Read;
    use storage_rs::ContentStore;
    use tempfile::TempDir;

    #[test]
    fn test_1gb_os_image_storage() {
        println!("=== Testing 1GB OS Image Storage ===");

        let temp_dir = TempDir::new().unwrap();
        let store = ContentStore::new(temp_dir.path()).unwrap();

        // Try to find a large system file first (faster than generating)
        let test_file = if let Some(system_file) = find_large_system_file(100) {
            println!("Using existing system file: {:?}", system_file);
            system_file
        } else {
            println!("Generating 1GB test file...");
            let path = temp_dir.path().join("test_os_image.img");
            create_file_with_size(&path, 1024 * 1024 * 1024).unwrap(); // 1GB
            path
        };

        // Read the file
        println!("Reading file...");
        let mut file = File::open(&test_file).unwrap();
        let mut data = Vec::new();
        file.read_to_end(&mut data).unwrap();

        let original_size = data.len();
        println!("Original size: {} MB", original_size / 1024 / 1024);

        // Store the data
        println!("Storing data...");
        let start = std::time::Instant::now();
        let hash = store.store(&data).unwrap();
        let store_duration = start.elapsed();

        println!("Stored in {:?}", store_duration);
        println!("Hash: {}", hash);

        // Verify metadata
        let metadata = store.get_metadata(&hash).unwrap();
        assert_eq!(metadata.size, original_size as u64);
        assert_eq!(metadata.ref_count, 1);
        println!(
            "Compressed size: {} MB",
            metadata.compressed_size / 1024 / 1024
        );
        println!(
            "Compression ratio: {:.2}x",
            metadata.size as f64 / metadata.compressed_size as f64
        );

        // Retrieve and verify
        println!("Retrieving data...");
        let start = std::time::Instant::now();
        let retrieved = store.retrieve(&hash).unwrap();
        let retrieve_duration = start.elapsed();

        println!("Retrieved in {:?}", retrieve_duration);
        assert_eq!(data, retrieved);

        // Test deduplication - store the same data again
        println!("Testing deduplication...");
        let hash2 = store.store(&data).unwrap();
        assert_eq!(hash, hash2, "Same data should produce same hash");

        let metadata2 = store.get_metadata(&hash).unwrap();
        assert_eq!(
            metadata2.ref_count, 2,
            "Reference count should be incremented"
        );

        // Get storage stats
        let stats = store.get_stats();
        println!("\n=== Storage Statistics ===");
        println!("Total blobs: {}", stats.total_blobs);
        println!("Total size: {} MB", stats.total_size / 1024 / 1024);
        println!(
            "Compressed size: {} MB",
            stats.compressed_size / 1024 / 1024
        );
        println!("Compression ratio: {:.2}x", stats.compression_ratio);
        println!("Dedup count: {}", stats.dedup_count);
        println!("Space saved: {} MB", stats.space_saved / 1024 / 1024);

        assert_eq!(stats.total_blobs, 1);
        assert_eq!(stats.dedup_count, 1); // One blob with ref_count > 1
    }

    #[test]
    fn test_container_layer_simulation() {
        println!("=== Testing Container Layer Simulation ===");

        let temp_dir = TempDir::new().unwrap();
        let store = ContentStore::new(temp_dir.path()).unwrap();

        // Simulate fragment layers
        // Layer 1: Base OS layer (Ubuntu-like, 100MB)
        println!("Creating base OS layer (100MB)...");
        let base_layer = create_layer_data(100 * 1024 * 1024, b"base");
        let base_hash = store.store(&base_layer).unwrap();
        println!("Base layer hash: {}", base_hash);

        // Layer 2: System libraries (50MB, some overlap with base)
        println!("Creating system libraries layer (50MB)...");
        let lib_layer = create_layer_data(50 * 1024 * 1024, b"libs");
        let lib_hash = store.store(&lib_layer).unwrap();
        println!("Libraries layer hash: {}", lib_hash);

        // Layer 3: Application layer (20MB)
        println!("Creating application layer (20MB)...");
        let app_layer = create_layer_data(20 * 1024 * 1024, b"app");
        let app_hash = store.store(&app_layer).unwrap();
        println!("Application layer hash: {}", app_hash);

        // Layer 4: Config layer (1MB)
        println!("Creating config layer (1MB)...");
        let config_layer = create_layer_data(1024 * 1024, b"config");
        let config_hash = store.store(&config_layer).unwrap();
        println!("Config layer hash: {}", config_hash);

        // Simulate another container sharing the base layer
        println!("\nSimulating second fragment sharing base layer...");
        let base_hash2 = store.store(&base_layer).unwrap();
        assert_eq!(base_hash, base_hash2);

        // Different app layer for second fragment
        let app2_layer = create_layer_data(25 * 1024 * 1024, b"app2");
        let _app2_hash = store.store(&app2_layer).unwrap();

        // Get statistics
        let stats = store.get_stats();
        println!("\n=== Container Layer Statistics ===");
        println!("Total layers (blobs): {}", stats.total_blobs);
        println!("Total size: {} MB", stats.total_size / 1024 / 1024);
        println!(
            "Compressed size: {} MB",
            stats.compressed_size / 1024 / 1024
        );
        println!("Compression ratio: {:.2}x", stats.compression_ratio);
        println!("Shared layers (dedup): {}", stats.dedup_count);
        println!("Space saved: {} MB", stats.space_saved / 1024 / 1024);

        // Verify layer sharing
        let base_meta = store.get_metadata(&base_hash).unwrap();
        assert_eq!(
            base_meta.ref_count, 2,
            "Base layer should be shared between 2 fragments"
        );

        // Calculate space savings from deduplication
        let total_without_dedup = base_layer.len() * 2
            + lib_layer.len()
            + app_layer.len()
            + config_layer.len()
            + app2_layer.len();
        let total_with_dedup = stats.total_size as usize;
        let dedup_savings = total_without_dedup - total_with_dedup;

        println!(
            "\nDeduplication savings: {} MB ({:.1}%)",
            dedup_savings / 1024 / 1024,
            (dedup_savings as f64 / total_without_dedup as f64) * 100.0
        );

        assert!(dedup_savings > 0, "Should have deduplication savings");
    }

    #[test]
    fn test_garbage_collection() {
        println!("=== Testing Garbage Collection ===");

        let temp_dir = TempDir::new().unwrap();
        let mut store = ContentStore::new(temp_dir.path()).unwrap();

        // Store multiple blobs
        let data1 = vec![1u8; 10 * 1024 * 1024]; // 10MB
        let data2 = vec![2u8; 20 * 1024 * 1024]; // 20MB
        let data3 = vec![3u8; 15 * 1024 * 1024]; // 15MB

        let hash1 = store.store(&data1).unwrap();
        let hash2 = store.store(&data2).unwrap();
        let hash3 = store.store(&data3).unwrap();

        println!("Stored 3 blobs: {} {} {}", hash1, hash2, hash3);

        let stats_before = store.get_stats();
        println!(
            "Before GC - Total blobs: {}, Size: {} MB",
            stats_before.total_blobs,
            stats_before.total_size / 1024 / 1024
        );

        // Release references to blob 1 and 2
        println!("\nReleasing references to blob 1 and 2...");
        store.release(&hash1).unwrap();
        store.release(&hash2).unwrap();

        // Verify ref counts
        let meta1 = store.get_metadata(&hash1).unwrap();
        let meta2 = store.get_metadata(&hash2).unwrap();
        assert_eq!(meta1.ref_count, 0);
        assert_eq!(meta2.ref_count, 0);

        // Run garbage collection
        println!("Running garbage collection...");
        let gc_stats = store.gc().unwrap();

        println!("\n=== GC Results ===");
        println!("Removed blobs: {}", gc_stats.removed);
        println!("Space freed: {} MB", gc_stats.space_freed / 1024 / 1024);

        assert_eq!(gc_stats.removed, 2, "Should have removed 2 blobs");

        // Verify stats after GC
        let stats_after = store.get_stats();
        println!(
            "\nAfter GC - Total blobs: {}, Size: {} MB",
            stats_after.total_blobs,
            stats_after.total_size / 1024 / 1024
        );

        assert_eq!(stats_after.total_blobs, 1, "Should have 1 blob remaining");

        // Verify blob 3 is still accessible
        let retrieved3 = store.retrieve(&hash3).unwrap();
        assert_eq!(data3, retrieved3);

        // Verify blobs 1 and 2 are gone
        assert!(store.retrieve(&hash1).is_err());
        assert!(store.retrieve(&hash2).is_err());
    }

    #[test]
    fn test_concurrent_storage_access() {
        use std::sync::Arc;
        use std::thread;

        println!("=== Testing Concurrent Storage Access ===");

        let temp_dir = TempDir::new().unwrap();
        let store = Arc::new(ContentStore::new(temp_dir.path()).unwrap());

        let num_threads = 4;
        let items_per_thread = 10;

        let mut handles = vec![];

        for thread_id in 0..num_threads {
            let store_clone = Arc::clone(&store);
            let handle = thread::spawn(move || {
                let mut hashes = vec![];
                for i in 0..items_per_thread {
                    let data = vec![(thread_id * 100 + i) as u8; 1024 * 1024]; // 1MB each
                    let hash = store_clone.store(&data).unwrap();
                    hashes.push(hash);
                }
                hashes
            });
            handles.push(handle);
        }

        // Wait for all threads
        let mut all_hashes = vec![];
        for handle in handles {
            let hashes = handle.join().unwrap();
            all_hashes.extend(hashes);
        }

        println!("Stored {} blobs concurrently", all_hashes.len());

        // Verify all blobs are accessible
        for hash in &all_hashes {
            let data = store.retrieve(hash).unwrap();
            assert_eq!(data.len(), 1024 * 1024);
        }

        let stats = store.get_stats();
        println!("Total blobs: {}", stats.total_blobs);
        println!("Total size: {} MB", stats.total_size / 1024 / 1024);

        assert_eq!(stats.total_blobs, (num_threads * items_per_thread) as usize);
    }

    #[test]
    fn test_storage_performance() {
        println!("=== Testing Storage Performance ===");

        let temp_dir = TempDir::new().unwrap();
        let store = ContentStore::new(temp_dir.path()).unwrap();

        let num_files = 100;
        let file_size = 1024 * 1024; // 1MB each

        println!(
            "Storing {} files of {} MB each...",
            num_files,
            file_size / 1024 / 1024
        );

        let start = std::time::Instant::now();
        let mut hashes = vec![];

        for i in 0..num_files {
            let data = vec![(i % 256) as u8; file_size];
            let hash = store.store(&data).unwrap();
            hashes.push(hash);
        }

        let store_duration = start.elapsed();
        let store_throughput =
            (num_files * file_size) as f64 / store_duration.as_secs_f64() / 1024.0 / 1024.0;

        println!("Store time: {:?}", store_duration);
        println!("Store throughput: {:.2} MB/s", store_throughput);

        // Test retrieval performance
        let start = std::time::Instant::now();

        for hash in &hashes {
            let _ = store.retrieve(hash).unwrap();
        }

        let retrieve_duration = start.elapsed();
        let retrieve_throughput =
            (num_files * file_size) as f64 / retrieve_duration.as_secs_f64() / 1024.0 / 1024.0;

        println!("Retrieve time: {:?}", retrieve_duration);
        println!("Retrieve throughput: {:.2} MB/s", retrieve_throughput);

        let stats = store.get_stats();
        println!("\nFinal stats:");
        println!("  Total blobs: {}", stats.total_blobs);
        println!("  Compression ratio: {:.2}x", stats.compression_ratio);
    }

    // Helper function to create layer data with specific pattern
    fn create_layer_data(size: usize, seed: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(size);
        let mut hasher = Sha256::new();
        hasher.update(seed);

        let pattern = hasher.finalize();
        let pattern_len = pattern.len();

        for i in 0..size {
            data.push(pattern[i % pattern_len]);
        }

        data
    }
}
