use clap::{Parser, Subcommand};
use colored::Colorize;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

mod commands;
mod config;
mod daemon;
mod fragment_pool;
mod fragment_registry;
mod io_utils;
mod permission_prompt;
mod ui;

use commands::CommandContext;
use fragment_registry::FragmentRegistry;

/// Initialize tracing/logging for the application
fn init_logging() {
    // Try to initialize tracing subscriber
    // Use JSON format for production (when RUST_LOG=json is set)
    let use_json = std::env::var("PHANTOM_LOG_JSON")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false);

    let fmt_layer = if use_json {
        fmt::layer().json().boxed()
    } else {
        fmt::layer().boxed()
    };

    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(fmt_layer)
        .try_init()
        .unwrap_or_else(|_| {
            // If tracing is already initialized, fall back to env_logger
            let _ = env_logger::try_init();
        });

    tracing::debug!("Logging initialized");
}

#[derive(Parser)]
#[command(name = "phantom")]
#[command(version = "3.1.0")]
#[command(about = "Phantom Fragment Runtime", long_about = None)]
struct Cli {
    /// Internal: Run as warm daemon (hidden)
    #[arg(long, hide = true)]
    internal_warm_daemon: bool,

    /// Internal: Socket path for daemon (hidden)
    #[arg(long, hide = true)]
    socket: Option<String>,

    /// Internal: Rootfs path for daemon (hidden)
    #[arg(long, hide = true)]
    rootfs: Option<String>,

    /// Internal: CPU count for daemon (hidden)
    #[arg(long, hide = true)]
    cpu_count: Option<usize>,

    /// Internal: Memory MB for daemon (hidden)
    #[arg(long, hide = true)]
    memory_mb: Option<usize>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new fragment
    Create(commands::create::CreateArgs),
    /// Run a command in a fragment
    Run(commands::run::RunArgs),
    /// List active fragments
    List(commands::list::ListArgs),
    /// View logs from a fragment
    Logs(commands::logs::LogsArgs),
    /// Destroy a fragment
    Destroy(commands::delete::DeleteArgs),
    /// Check system health
    Health(commands::health::HealthArgs),
    /// Show system metrics and start metrics server
    Metrics {
        #[command(subcommand)]
        command: commands::metrics::MetricsCommands,
    },
    /// Clean up rootfs images
    Clean(commands::clean::CleanArgs),
    /// Search for images on Docker Hub
    #[command(visible_alias = "s")]
    Search(commands::search::SearchArgs),
    /// Migration tools
    Migrate(phantom_migrate::Args),
    /// Build images from Fragmentfiles
    Build(phantom_build::Args),
    /// List available images
    Images(commands::images::ImagesArgs),
    /// Network management commands
    Network {
        #[command(subcommand)]
        command: commands::network::NetworkCommands,
    },
    /// Profile management commands
    Profile {
        #[command(subcommand)]
        command: commands::profile::ProfileCommands,
    },
    /// Inspect fragment details
    Inspect(commands::inspect::InspectArgs),
    /// Update fragment configuration
    Update(commands::update::UpdateArgs),
    /// Restart a fragment
    Restart(commands::restart::RestartArgs),
    /// Monitor fragment in real-time
    Monitor(commands::monitor::MonitorArgs),
    /// Warm fragment pool management (experimental)
    Warm {
        #[command(subcommand)]
        command: commands::warm::WarmCommands,
    },
    /// Run performance benchmarks
    Benchmark(commands::benchmark::BenchmarkArgs),
    /// Volume management commands
    Volume {
        #[command(subcommand)]
        command: commands::volume::VolumeCommands,
    },
    /// Security commands
    Security {
        #[command(subcommand)]
        command: commands::security::SecurityCommands,
    },
    /// Registry management commands
    Registry {
        #[command(subcommand)]
        command: commands::registry::RegistryCommands,
    },
    /// Debug commands
    Debug {
        #[command(subcommand)]
        command: commands::debug::DebugCommands,
    },
    /// Stop a running fragment
    Stop(commands::stop::StopArgs),
    /// Show detailed fragment status
    Status(commands::status::StatusArgs),
    /// Document the security model
    Explain(commands::explain::ExplainArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    eprintln!("DEBUG: main() started");
    // Initialize structured logging with tracing
    init_logging();

    // Check for internal daemon mode BEFORE CLI parsing
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--internal-warm-daemon") {
        return daemon::run_daemon_mode(&args).await;
    }

    // Try to run the main logic, handling NeedSudo errors
    match run_cli().await {
        Ok(()) => Ok(()),
        Err(e) => {
            // Check if this is a NeedSudo error by checking the error message
            let error_msg = e.to_string();
            if error_msg.contains("Permission denied") && error_msg.contains("sudo") {
                return reexec_with_sudo();
            }
            Err(e)
        }
    }
}

/// Re-execute the current process with sudo
fn reexec_with_sudo() -> anyhow::Result<()> {
    use std::process::Command;

    let args: Vec<String> = std::env::args().collect();
    let program = &args[0];

    println!("{} Re-executing with sudo...", "ℹ️".blue());

    let status = Command::new("sudo")
        .arg("-E") // Preserve environment
        .arg(program)
        .args(&args[1..])
        .status()?;

    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("sudo execution failed with status: {}", status)
    }
}

async fn run_cli() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let app_config = config::Config::load().unwrap_or_else(|e| {
        eprintln!("Warning: Failed to load config: {}", e);
        config::Config::default()
    });

    let mut registry = FragmentRegistry::new()?;

    match cli.command {
        Commands::Create(args) => {
            let ctx = CommandContext::new(&app_config, &mut registry);
            commands::create::exec(ctx, args)?;
        }
        Commands::Run(args) => {
            let ctx = CommandContext::new(&app_config, &mut registry);
            commands::run::exec(ctx, args).await?;
        }
        Commands::List(args) => {
            let ctx = CommandContext::new(&app_config, &mut registry);
            commands::list::exec(ctx, args)?;
        }
        Commands::Logs(args) => {
            let ctx = CommandContext::new(&app_config, &mut registry);
            commands::logs::exec(ctx, args).await?;
        }
        Commands::Destroy(args) => {
            let ctx = CommandContext::new(&app_config, &mut registry);
            commands::delete::exec(ctx, args)?;
        }
        Commands::Health(args) => {
            let ctx = CommandContext::new(&app_config, &mut registry);
            commands::health::exec(ctx, args)?;
        }
        Commands::Warm { command } => {
            let ctx = CommandContext::new(&app_config, &mut registry);
            commands::warm::exec(ctx, command).await?;
        }
        Commands::Metrics { command } => {
            let ctx = CommandContext::new(&app_config, &mut registry);
            commands::metrics::exec(ctx, command)?;
        }
        Commands::Clean(args) => {
            let ctx = CommandContext::new(&app_config, &mut registry);
            commands::clean::exec(ctx, args)?;
        }
        Commands::Migrate(args) => {
            phantom_migrate::run(args)?;
        }
        Commands::Build(args) => {
            if args.verbose {
                let _ = env_logger::Builder::from_env(
                    env_logger::Env::default().default_filter_or("debug"),
                )
                .try_init();
            }
            phantom_build::run(args).await?;
        }
        Commands::Search(args) => {
            let ctx = CommandContext::new(&app_config, &mut registry);
            commands::search::exec(ctx, args).await?;
        }
        Commands::Images(args) => {
            let ctx = CommandContext::new(&app_config, &mut registry);
            commands::images::exec(ctx, args)?;
        }
        Commands::Network { command } => {
            let ctx = CommandContext::new(&app_config, &mut registry);
            commands::network::exec(ctx, command).await?;
        }
        Commands::Profile { command } => {
            let ctx = CommandContext::new(&app_config, &mut registry);
            commands::profile::exec(ctx, command)?;
        }
        Commands::Inspect(args) => {
            let ctx = CommandContext::new(&app_config, &mut registry);
            commands::inspect::exec(ctx, args)?;
        }
        Commands::Update(args) => {
            let ctx = CommandContext::new(&app_config, &mut registry);
            commands::update::exec(ctx, args)?;
        }
        Commands::Restart(args) => {
            let ctx = CommandContext::new(&app_config, &mut registry);
            commands::restart::exec(ctx, args)?;
        }
        Commands::Monitor(args) => {
            let ctx = CommandContext::new(&app_config, &mut registry);
            commands::monitor::exec(ctx, args)?;
        }
        Commands::Benchmark(args) => {
            let ctx = CommandContext::new(&app_config, &mut registry);
            commands::benchmark::exec(ctx, args)?;
        }
        Commands::Volume { command } => {
            let ctx = CommandContext::new(&app_config, &mut registry);
            commands::volume::exec(ctx, command).await?;
        }
        Commands::Security { command } => {
            let ctx = CommandContext::new(&app_config, &mut registry);
            commands::security::exec(ctx, command).await?;
        }
        Commands::Registry { command } => {
            let ctx = CommandContext::new(&app_config, &mut registry);
            commands::registry::exec(ctx, command).await?;
        }
        Commands::Debug { command } => {
            let ctx = CommandContext::new(&app_config, &mut registry);
            commands::debug::exec(ctx, command)?;
        }
        Commands::Stop(args) => {
            let ctx = CommandContext::new(&app_config, &mut registry);
            commands::stop::exec(ctx, args)?;
        }
        Commands::Status(args) => {
            let ctx = CommandContext::new(&app_config, &mut registry);
            commands::status::exec(ctx, args)?;
        }
        Commands::Explain(args) => {
            commands::explain::exec(args)?;
        }
    }

    Ok(())
}
