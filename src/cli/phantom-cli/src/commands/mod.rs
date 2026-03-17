use crate::config::{Config, PhantomPaths};
use crate::fragment_registry::FragmentRegistry;

pub mod benchmark;
pub mod build;
pub mod clean;
pub mod create;
pub mod debug;
pub mod delete;
pub mod explain;
pub mod health;
pub mod images;
pub mod inspect;
pub mod list;
pub mod logs;
pub mod metrics;
pub mod monitor;
pub mod network;
pub mod profile;
pub mod registry;
pub mod restart;
pub mod run;
pub mod search;
pub mod security;
pub mod status;
pub mod stop;
pub mod update;
pub mod volume;
pub mod warm;

/// Shared context for all commands
pub struct CommandContext<'a> {
    pub config: &'a Config,
    pub paths: PhantomPaths,
    pub registry: &'a mut FragmentRegistry,
}

impl<'a> CommandContext<'a> {
    pub fn new(config: &'a Config, registry: &'a mut FragmentRegistry) -> Self {
        Self {
            config,
            paths: PhantomPaths::new(),
            registry,
        }
    }
}
