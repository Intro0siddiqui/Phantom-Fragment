//! Phantom Build - Fragmentfile builder
//!
//! Docker-compatible++ build system

use anyhow::Result;
use clap::Parser;
use phantom_build::{run, Args};

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    if args.verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    }

    run(args).await
}
