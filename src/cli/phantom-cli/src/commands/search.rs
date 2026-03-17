use anyhow::{Context, Result};
use colored::*;

#[derive(clap::Args, Debug, Clone)]
pub struct SearchArgs {
    /// Search term (e.g., "kali", "ubuntu")
    pub term: String,
}

#[derive(serde::Deserialize)]
struct SearchResult {
    repo_name: String,
    short_description: String,
    star_count: u32,
    is_official: bool,
}

#[derive(serde::Deserialize)]
struct SearchResponse {
    results: Vec<SearchResult>,
}

use crate::commands::CommandContext;

pub async fn exec(_ctx: CommandContext<'_>, args: SearchArgs) -> Result<()> {
    println!(
        "{} {}",
        "Searching Docker Hub for:".cyan().bold(),
        args.term
    );

    let url = format!(
        "https://hub.docker.com/v2/search/repositories/?query={}",
        args.term
    );
    let client = reqwest::Client::new();

    let resp = client
        .get(&url)
        .send()
        .await
        .context("Failed to contact Docker Hub")?;

    if !resp.status().is_success() {
        anyhow::bail!("Search failed: {}", resp.status());
    }

    let search_resp: SearchResponse = resp
        .json()
        .await
        .context("Failed to parse search results")?;

    if search_resp.results.is_empty() {
        println!("No results found.");
        return Ok(());
    }

    println!(
        "\n{0: <30} {1: <10} {2: <10} {3}",
        "NAME", "STARS", "OFFICIAL", "DESCRIPTION"
    );
    println!("{}", "─".repeat(80).dimmed());

    for result in search_resp.results.iter().take(10) {
        let official = if result.is_official { "[OK]" } else { "" };
        let desc = if result.short_description.len() > 40 {
            format!("{}...", &result.short_description[..37])
        } else {
            result.short_description.clone()
        };

        println!(
            "{0: <30} {1: <10} {2: <10} {3}",
            result.repo_name.cyan(),
            result.star_count,
            official.green(),
            desc.dimmed()
        );
    }
    println!("");

    Ok(())
}
