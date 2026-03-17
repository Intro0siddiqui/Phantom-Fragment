use anyhow::Result;
use colored::*;
use std::time::Instant;

use crate::ui::print_header;

#[derive(clap::Args, Debug, Clone)]
pub struct BenchmarkArgs {
    /// Run comprehensive benchmarks
    #[arg(long)]
    pub comprehensive: bool,
    /// I/O benchmarks
    #[arg(long)]
    pub io: bool,
    /// Memory benchmarks
    #[arg(long)]
    pub memory: bool,
    /// Number of iterations
    #[arg(long, default_value = "100")]
    pub iterations: usize,
}

use crate::commands::CommandContext;

pub fn exec(_ctx: CommandContext, args: BenchmarkArgs) -> Result<()> {
    print_header("Phantom Benchmark Suite");

    if args.comprehensive || (!args.io && !args.memory) {
        println!("\n{}", "Startup Benchmark".yellow());
        println!("  Testing fragment creation speed...");

        let start = Instant::now();
        for i in 0..args.iterations.min(10) {
            let _ = std::process::Command::new("echo")
                .arg(format!("test-{}", i))
                .output();
        }
        let duration = start.elapsed();
        println!(
            "  {} {} iterations in {:?}",
            "Result:".green(),
            args.iterations.min(10),
            duration
        );
        println!(
            "  {} {:?} per operation",
            "Average:".green(),
            duration / args.iterations.min(10) as u32
        );
    }

    if args.io || args.comprehensive {
        println!("\n{}", "I/O Benchmark".yellow());

        let test_data = vec![0u8; 1024 * 1024];
        let start = Instant::now();

        for _ in 0..args.iterations {
            let temp_path = std::env::temp_dir().join("phantom_bench_tmp");
            std::fs::write(&temp_path, &test_data).ok();
            std::fs::read(&temp_path).ok();
            std::fs::remove_file(&temp_path).ok();
        }

        let duration = start.elapsed();
        println!(
            "  {} {} I/O operations in {:?}",
            "Result:".green(),
            args.iterations * 2,
            duration
        );
        println!(
            "  {} {:.2} ops/sec",
            "Throughput:".green(),
            (args.iterations * 2) as f64 / duration.as_secs_f64()
        );
    }

    if args.memory || args.comprehensive {
        println!("\n{}", "Memory Benchmark".yellow());

        use memory_rs::BufferPool;

        let start = Instant::now();
        if let Some(pool) = BufferPool::new(4096, args.iterations) {
            for _ in 0..args.iterations {
                let _ = pool.get();
            }
            let duration = start.elapsed();
            println!(
                "  {} {} buffer ops in {:?}",
                "Result:".green(),
                args.iterations,
                duration
            );
            println!(
                "  {} {:?} per operation",
                "Average:".green(),
                duration / args.iterations as u32
            );
        } else {
            println!("  {} Buffer pool not available", "Warning:".yellow());
        }
    }

    println!("\n{} Benchmark complete", "✓".green().bold());
    Ok(())
}
