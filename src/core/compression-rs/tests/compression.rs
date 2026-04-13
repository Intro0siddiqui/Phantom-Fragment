use compression_rs::*;
use std::io::Cursor;

fn make_test_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

#[test]
fn test_zstd_roundtrip() {
    let data = make_test_data(100);
    let mut input = Cursor::new(&data);
    let mut compressed = Cursor::new(Vec::new());

    let compressor = ZstdCompressor::new(3);
    compressor.compress(&mut input, &mut compressed).unwrap();

    let mut compressed_cursor = Cursor::new(compressed.into_inner());
    let mut decompressed = Cursor::new(Vec::new());

    compressor.decompress(&mut compressed_cursor, &mut decompressed).unwrap();

    assert_eq!(decompressed.into_inner(), data);
}

#[test]
fn test_gzip_roundtrip() {
    let data = make_test_data(100);
    let mut input = Cursor::new(&data);
    let mut compressed = Cursor::new(Vec::new());

    let compressor = GzipCompressor::new(6);
    compressor.compress(&mut input, &mut compressed).unwrap();

    let mut compressed_cursor = Cursor::new(compressed.into_inner());
    let mut decompressed = Cursor::new(Vec::new());

    compressor.decompress(&mut compressed_cursor, &mut decompressed).unwrap();

    assert_eq!(decompressed.into_inner(), data);
}

#[test]
fn test_lz4_roundtrip() {
    let data = make_test_data(100);
    let mut input = Cursor::new(&data);
    let mut compressed = Cursor::new(Vec::new());

    let compressor = Lz4Compressor::new(3);
    compressor.compress(&mut input, &mut compressed).unwrap();

    let mut compressed_cursor = Cursor::new(compressed.into_inner());
    let mut decompressed = Cursor::new(Vec::new());

    compressor.decompress(&mut compressed_cursor, &mut decompressed).unwrap();

    assert_eq!(decompressed.into_inner(), data);
}

#[test]
fn test_zstd_large_data() {
    let data = make_test_data(100_000);
    let mut input = Cursor::new(&data);
    let mut compressed = Cursor::new(Vec::new());

    let compressor = ZstdCompressor::new(3);
    compressor.compress(&mut input, &mut compressed).unwrap();

    let mut compressed_cursor = Cursor::new(compressed.into_inner());
    let mut decompressed = Cursor::new(Vec::new());

    compressor.decompress(&mut compressed_cursor, &mut decompressed).unwrap();

    assert_eq!(decompressed.into_inner(), data);
}

#[test]
fn test_compression_error_display() {
    let err = CompressionError::Io(std::io::Error::new(std::io::ErrorKind::Other, "test error"));
    assert!(err.to_string().contains("test error"));

    let err = CompressionError::Compression("something went wrong".to_string());
    assert!(err.to_string().contains("something went wrong"));
}
