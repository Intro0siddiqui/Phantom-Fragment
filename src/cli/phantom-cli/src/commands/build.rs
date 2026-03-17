use std::path::PathBuf;

#[derive(clap::Args, Debug, Clone)]
pub struct BuildArgs {
    /// Path to build context
    #[arg(value_name = "PATH", default_value = ".")]
    pub context: PathBuf,

    /// Name and tag for the image
    #[arg(short, long, value_name = "NAME:TAG")]
    pub tag: Option<String>,

    /// Path to Fragmentfile
    #[arg(short, long, value_name = "FILE", default_value = "Fragmentfile")]
    pub file: String,

    /// Disable layer caching
    #[arg(long)]
    pub no_cache: bool,

    /// Target build stage
    #[arg(long)]
    pub target: Option<String>,

    /// Enable verbose logging
    #[arg(short, long)]
    pub verbose: bool,

    /// Build secrets (id=path)
    #[arg(long, value_name = "ID=PATH")]
    pub secret: Vec<String>,

    /// Build-time variables (can be specified multiple times)
    #[arg(long, value_name = "NAME=VALUE")]
    pub build_arg: Vec<String>,
}
