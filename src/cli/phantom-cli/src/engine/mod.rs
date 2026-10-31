//! Execution engines.
//!
//! `sandbox` holds the security stack shared by the warm mother and the native
//! cold executor. `native` is the one-shot sandbox used for image runs.

pub(crate) mod native;
pub(crate) mod sandbox;

use clap::ValueEnum;

/// Which backend runs a cold image fragment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum EngineChoice {
    /// Native engine, falling back to bubblewrap when the host cannot provide
    /// the namespace or mount primitives. Never falls back for a profile that
    /// requires confinement the fallback cannot enforce.
    Auto,
    /// Native engine only. Any failure is fatal.
    Native,
    /// Bubblewrap (`RootfsExecutor`) only.
    Bwrap,
}
