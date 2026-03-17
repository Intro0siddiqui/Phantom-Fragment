//! OCI Registry Client for Phantom Fragment
//!
//! Supports pulling and pushing images from/to:
//! - Docker Hub (docker.io)
//! - GitHub Container Registry (ghcr.io)
//! - Quay.io (quay.io)
//! - Google Container Registry (gcr.io)
//! - Amazon ECR (elastic container registry)
//! - Azure Container Registry (azurecr.io)
//! - Any OCI-compliant registry
//!
//! Features:
//! - Dual authentication (Docker credential helpers + custom)
//! - Parallel layer downloads
//! - Resume support
//! - Progress tracking
//! - Image push support
//! - Multi-registry support
//! - Token-based authentication

mod auth;
mod client;
mod downloader;
mod manifest;
mod pusher;
mod types;

pub use auth::{AuthConfig, CredentialHelper};
pub use client::RegistryClient;
pub use downloader::{DownloadTask, Downloader, DownloaderConfig};
pub use manifest::{Descriptor, ImageManifest, ManifestList, Platform, PlatformManifest};
pub use pusher::{PushConfig, PushImage, PushLayer, RegistryPusher};
pub use types::*;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum RegistryError {
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Image not found: {0}")]
    ImageNotFound(String),

    #[error("Invalid manifest: {0}")]
    InvalidManifest(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Registry error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, RegistryError>;
