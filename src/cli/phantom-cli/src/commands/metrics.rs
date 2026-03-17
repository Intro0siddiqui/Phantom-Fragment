use anyhow::Result;
use colored::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use crate::commands::CommandContext;
use crate::fragment_registry::{FragmentRegistry, FragmentStatus};
use crate::ui::{dimmed, print_divider_full, print_header};

#[derive(clap::Args, Debug, Clone, Default)]
pub struct MetricsArgs {
    /// Include registry metrics (fragment counts, memory usage)
    #[arg(long)]
    pub with_registry: bool,

    /// Show detailed per-fragment metrics
    #[arg(long)]
    pub detailed: bool,
}

#[derive(clap::Subcommand, Debug, Clone)]
pub enum MetricsCommands {
    /// Show system metrics
    Show(MetricsArgs),
    /// Start metrics HTTP server for Prometheus scraping
    Serve {
        /// Port to listen on (default: 9090)
        #[arg(long, default_value = "9090")]
        port: u16,
        /// Output format (prometheus, json)
        #[arg(long, default_value = "prometheus")]
        format: String,
    },
}

/// Format a Unix timestamp (seconds) into a human-readable age string
fn format_timestamp_simple(secs: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let age_secs = now.saturating_sub(secs);

    if age_secs < 60 {
        format!("{}s", age_secs)
    } else if age_secs < 3600 {
        format!("{}m", age_secs / 60)
    } else if age_secs < 86400 {
        format!("{}h", age_secs / 3600)
    } else {
        format!("{}d", age_secs / 86400)
    }
}

/// Print fragment status breakdown
fn print_status_breakdown(registry: &FragmentRegistry) {
    let all = registry.list();
    let running = registry.list_by_status(FragmentStatus::Running);
    let stopped = registry.list_by_status(FragmentStatus::Stopped);
    let failed = registry.list_by_status(FragmentStatus::Failed);
    let stale = registry.get_stale_fragments();

    println!(
        "  {:<15} {}",
        "Total:".dimmed(),
        all.len().to_string().cyan()
    );
    println!(
        "  {:<15} {}",
        "Running:".dimmed(),
        running.len().to_string().green()
    );
    println!(
        "  {:<15} {}",
        "Stopped:".dimmed(),
        stopped.len().to_string().yellow()
    );
    println!(
        "  {:<15} {}",
        "Failed:".dimmed(),
        failed.len().to_string().red()
    );
    println!(
        "  {:<15} {}",
        "Stale:".dimmed(),
        stale.len().to_string().red().bold()
    );
}

/// Print detailed per-fragment metrics
fn print_detailed_fragment_metrics(registry: &FragmentRegistry) {
    let fragments = registry.list();

    if fragments.is_empty() {
        dimmed("  No fragments registered");
        return;
    }

    println!();
    println!("  {}", "Fragment Details:".cyan().bold());
    print_divider_full();

    println!(
        "  {:<20} {:<10} {:<10} {:<12} {:<10} {:<10}",
        "NAME".bold(),
        "STATUS".bold(),
        "PID".bold(),
        "MEMORY".bold(),
        "AGE".bold(),
        "PROFILE".bold()
    );
    print_divider_full();

    for fragment in fragments {
        let status_str = match fragment.status {
            FragmentStatus::Running => "Running".green(),
            FragmentStatus::Stopped => "Stopped".yellow(),
            FragmentStatus::Failed => "Failed".red(),
        };

        let pid_str = fragment.pid.map_or("N/A".to_string(), |p| p.to_string());
        let age_str = format_timestamp_simple(fragment.created_at);

        println!(
            "  {:<20} {:<10} {:<10} {:<12} {:<10} {:<10}",
            fragment.name.cyan(),
            status_str,
            pid_str,
            format!("{} KB", fragment.memory_kb),
            age_str,
            fragment.profile
        );
    }
}

/// Format memory size in human-readable format
fn format_memory_size(kb: u64) -> String {
    if kb >= 1_048_576 {
        format!("{:.2} GB", kb as f64 / 1_048_576.0)
    } else if kb >= 1024 {
        format!("{:.2} MB", kb as f64 / 1024.0)
    } else {
        format!("{} KB", kb)
    }
}

pub fn exec(ctx: CommandContext, command: MetricsCommands) -> Result<()> {
    match command {
        MetricsCommands::Show(args) => exec_show(ctx, args),
        MetricsCommands::Serve { port, format } => exec_serve(port, &format),
    }
}

/// Execute the metrics show command
fn exec_show(ctx: CommandContext, args: MetricsArgs) -> Result<()> {
    use metrics_rs::MetricsCollector;

    // Create metrics collector and ALWAYS update with actual registry data
    let collector = MetricsCollector::new();

    // Update metrics with actual registry data from context
    let CommandContext { registry, .. } = ctx;
    let _running = registry.list_by_status(FragmentStatus::Running);
    let total_memory_kb: u64 = registry.list().iter().map(|f| f.memory_kb).sum();

    collector.set_container_count(_running.len() as f64);
    collector.set_memory_usage((total_memory_kb * 1024) as f64);

    // If --with-registry flag is set, show detailed registry metrics
    if args.with_registry {
        // Need to create new context since ctx was moved
        let registry = FragmentRegistry::new()?;
        return print_registry_metrics_detailed(&registry, &args);
    }

    // Default behavior: show system metrics (with updated container count)
    print_header("System Metrics");
    print_divider_full();

    let metrics = collector.export().map_err(|e| anyhow::anyhow!("{:?}", e))?;
    println!("{}", metrics);

    Ok(())
}

/// Execute the metrics serve command - starts HTTP server for Prometheus scraping
fn exec_serve(port: u16, format: &str) -> Result<()> {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    println!("{}", "Starting metrics server".cyan().bold());
    println!("  {} http://0.0.0.0:{}/metrics", "Endpoint:".yellow(), port);
    println!("  {} {}", "Format:".yellow(), format);
    println!();
    println!("{} Press Ctrl+C to stop", "Info:".yellow());
    println!();

    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr)
        .map_err(|e| anyhow::anyhow!("Failed to bind to {}: {}", addr, e))?;

    println!(
        "{} Metrics server listening on http://{}",
        "✓".green().bold(),
        addr
    );
    println!();

    // Set up Ctrl+C handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        println!("\n{} Shutting down metrics server...", "Info:".yellow());
        r.store(false, Ordering::SeqCst);
    })
    .map_err(|e| anyhow::anyhow!("Failed to set Ctrl+C handler: {}", e))?;

    for stream in listener.incoming() {
        if !running.load(Ordering::SeqCst) {
            break;
        }

        let mut stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Set read timeout
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .ok();

        // Read HTTP request
        let mut buffer = [0u8; 1024];
        if stream.read(&mut buffer).is_err() {
            continue;
        }

        // Check if it's a GET request to /metrics
        let request = String::from_utf8_lossy(&buffer);
        if request.starts_with("GET /metrics") {
            // Build metrics response
            use metrics_rs::MetricsCollector;
            let collector = MetricsCollector::new();

            let metrics = if format == "json" {
                // JSON format (simplified)
                let json = serde_json::json!({
                    "phantom_fragments_active": 0,
                    "phantom_memory_usage_bytes": 0,
                });
                json.to_string()
            } else {
                // Prometheus format
                let mut metrics = String::new();
                metrics.push_str("# HELP phantom_fragments_active Number of active fragments\n");
                metrics.push_str("# TYPE phantom_fragments_active gauge\n");
                metrics.push_str("phantom_fragments_active 0\n");

                if let Ok(collected) = collector.export() {
                    metrics.push_str(&collected);
                }
                metrics
            };

            let content_type = if format == "json" {
                "application/json"
            } else {
                "text/plain; version=0.0.4"
            };

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\n\r\n{}",
                content_type,
                metrics.len(),
                metrics
            );

            let _ = stream.write_all(response.as_bytes());
        } else if request.starts_with("GET /health") {
            // Health check endpoint
            let response =
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK";
            let _ = stream.write_all(response.as_bytes());
        } else {
            // 404 for other paths
            let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found";
            let _ = stream.write_all(response.as_bytes());
        }

        let _ = stream.flush();
    }

    println!("{} Metrics server stopped", "Info:".yellow());
    Ok(())
}

/// Print detailed registry metrics (separate function to avoid context move issue)
fn print_registry_metrics_detailed(registry: &FragmentRegistry, args: &MetricsArgs) -> Result<()> {
    print_header("Fragment Registry Metrics");
    print_divider_full();

    // Get fragment counts by status
    let all = registry.list();
    let _running = registry.list_by_status(FragmentStatus::Running);
    let _stopped = registry.list_by_status(FragmentStatus::Stopped);
    let _failed = registry.list_by_status(FragmentStatus::Failed);
    let _stale = registry.get_stale_fragments();

    // Calculate total memory usage
    let total_memory_kb: u64 = all.iter().map(|f| f.memory_kb).sum();

    // Print status breakdown
    print_status_breakdown(registry);

    // Print memory usage
    println!();
    println!(
        "  {:<15} {}",
        "Memory:".dimmed(),
        format_memory_size(total_memory_kb).cyan()
    );

    // Print detailed per-fragment metrics if requested
    if args.detailed {
        print_detailed_fragment_metrics(registry);
    }

    Ok(())
}
