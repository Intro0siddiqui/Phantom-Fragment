use anyhow::{Context, Result};
use colored::*;
use tokio_stream::StreamExt;

use crate::commands::CommandContext;
use crate::io_utils::{follow_file, get_log_path, read_file_lines, strip_timestamp, tail_file};

#[derive(clap::Args, Clone, Debug)]
pub struct LogsArgs {
    #[arg(help = "Fragment name")]
    pub name: String,

    #[arg(short = 'n', long, help = "Number of lines to show from the end")]
    pub tail: Option<usize>,

    #[arg(short, long, help = "Follow log output in real-time")]
    pub follow: bool,

    #[arg(short, long, help = "Show timestamps")]
    pub timestamps: bool,
}

pub async fn exec(_ctx: CommandContext<'_>, args: LogsArgs) -> Result<()> {
    let log_path = get_log_path(&args.name);

    if !log_path.exists() {
        anyhow::bail!(
            "No logs found for fragment '{}'\n  Logs may not be enabled for this fragment",
            args.name
        );
    }

    if args.follow {
        println!(
            "{} Following logs for '{}' (Ctrl+C to exit)",
            "→".yellow(),
            args.name.cyan().bold()
        );
        println!("{}", "─".repeat(80).dimmed());

        let lines = read_file_lines(log_path.clone()).context("Failed to read logs")?;

        for line in lines {
            if args.timestamps {
                println!("{}", line);
            } else {
                println!("{}", strip_timestamp(&line));
            }
        }

        let mut stream = follow_file(log_path)
            .await
            .context("Failed to follow logs")?;
        while let Some(line_result) = stream.next().await {
            let line = line_result.context("Failed to read line")?;
            if args.timestamps {
                println!("{}", line);
            } else {
                println!("{}", strip_timestamp(&line));
            }
        }
    } else {
        let lines_to_show = args.tail.unwrap_or(50);
        let lines = tail_file(log_path, lines_to_show).context("Failed to read logs")?;

        println!("Logs for fragment '{}'", args.name.cyan().bold());
        println!("{}", "─".repeat(80).dimmed());

        for line in &lines {
            if args.timestamps {
                println!("{}", line);
            } else {
                println!("{}", strip_timestamp(line));
            }
        }

        println!("{}", "─".repeat(80).dimmed());
        println!("{} Showing {} lines", "Info:".dimmed(), lines.len());
    }

    Ok(())
}
