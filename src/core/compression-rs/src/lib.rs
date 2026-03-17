use anyhow::Result;
use std::io::{Read, Write};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CompressionError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Compression error: {0}")]
    Compression(String),
}

pub trait Compressor {
    fn compress<R: Read, W: Write>(&self, input: &mut R, output: &mut W) -> Result<()>;
    fn decompress<R: Read, W: Write>(&self, input: &mut R, output: &mut W) -> Result<()>;
}

pub struct ZstdCompressor {
    level: i32,
}

impl ZstdCompressor {
    pub fn new(level: i32) -> Self {
        Self { level }
    }
}

impl Compressor for ZstdCompressor {
    fn compress<R: Read, W: Write>(&self, input: &mut R, output: &mut W) -> Result<()> {
        let mut encoder = zstd::Encoder::new(output, self.level)?;
        std::io::copy(input, &mut encoder)?;
        encoder.finish()?;
        Ok(())
    }

    fn decompress<R: Read, W: Write>(&self, input: &mut R, output: &mut W) -> Result<()> {
        let mut decoder = zstd::Decoder::new(input)?;
        std::io::copy(&mut decoder, output)?;
        Ok(())
    }
}

pub struct GzipCompressor {
    level: flate2::Compression,
}

impl GzipCompressor {
    pub fn new(level: u32) -> Self {
        Self {
            level: flate2::Compression::new(level),
        }
    }
}

impl Compressor for GzipCompressor {
    fn compress<R: Read, W: Write>(&self, input: &mut R, output: &mut W) -> Result<()> {
        let mut encoder = flate2::write::GzEncoder::new(output, self.level);
        std::io::copy(input, &mut encoder)?;
        encoder.finish()?;
        Ok(())
    }

    fn decompress<R: Read, W: Write>(&self, input: &mut R, output: &mut W) -> Result<()> {
        let mut decoder = flate2::read::GzDecoder::new(input);
        std::io::copy(&mut decoder, output)?;
        Ok(())
    }
}

pub struct Lz4Compressor {
    level: u32,
}

impl Lz4Compressor {
    pub fn new(level: u32) -> Self {
        Self { level }
    }
}

impl Compressor for Lz4Compressor {
    fn compress<R: Read, W: Write>(&self, input: &mut R, output: &mut W) -> Result<()> {
        let mut encoder = lz4::EncoderBuilder::new().level(self.level).build(output)?;
        std::io::copy(input, &mut encoder)?;
        let (_output, result) = encoder.finish();
        result.map_err(|e| e.into())
    }

    fn decompress<R: Read, W: Write>(&self, input: &mut R, output: &mut W) -> Result<()> {
        let mut decoder = lz4::Decoder::new(input)?;
        std::io::copy(&mut decoder, output)?;
        Ok(())
    }
}
