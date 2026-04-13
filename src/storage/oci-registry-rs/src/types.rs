//! Image types and structures

use core::fmt;
use serde::{Deserialize, Serialize};

/// Parsed image reference
#[derive(Debug, Clone)]
pub struct ImageReference {
    /// Registry (e.g., "docker.io", "ghcr.io")
    pub registry: String,

    /// Repository (e.g., "library/ubuntu", "user/app")
    pub repository: String,

    /// Tag (e.g., "latest", "22.04")
    pub tag: String,

    /// Digest (optional, e.g., "sha256:...")
    pub digest: Option<String>,
}

impl fmt::Display for ImageReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}:{}", self.registry, self.repository, self.tag)
    }
}

impl ImageReference {
    /// Parse an image reference string
    ///
    /// Examples:
    /// - "ubuntu:22.04" -> docker.io/library/ubuntu:22.04
    /// - "ghcr.io/user/app:latest" -> ghcr.io/user/app:latest
    /// - "myregistry.com:5000/app:v1" -> myregistry.com:5000/app:v1
    pub fn parse(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split('/').collect();

        let (registry, repo_start) =
            if parts.len() > 1 && (parts[0].contains('.') || parts[0].contains(':')) {
                // Has explicit registry
                (parts[0].to_string(), 1)
            } else {
                // Default to Docker Hub
                ("docker.io".to_string(), 0)
            };

        let repo_parts = &parts[repo_start..];
        let repo_with_tag = if repo_parts.is_empty() {
            return Err("Empty repository".to_string());
        } else {
            repo_parts.join("/")
        };

        let (repository, tag) = if let Some(colon_pos) = repo_with_tag.rfind(':') {
            let repo = repo_with_tag[..colon_pos].to_string();
            let tag = repo_with_tag[colon_pos + 1..].to_string();
            (repo, tag)
        } else {
            (repo_with_tag, "latest".to_string())
        };

        // Add "library/" for official Docker Hub images
        let repository = if registry == "docker.io" && !repository.contains('/') {
            format!("library/{}", repository)
        } else {
            repository
        };

        Ok(ImageReference {
            registry,
            repository,
            tag,
            digest: None,
        })
    }

    /// Get registry URL
    pub fn registry_url(&self) -> String {
        if self.registry == "docker.io" {
            "https://registry-1.docker.io".to_string()
        } else if self.registry == "ghcr.io" {
            "https://ghcr.io".to_string()
        } else if self.registry == "quay.io" {
            "https://quay.io".to_string()
        } else {
            format!("https://{}", self.registry)
        }
    }
}

/// Information about a pulled image
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageInfo {
    /// Image reference
    pub reference: String,

    /// Digest
    pub digest: String,

    /// Size in bytes
    pub size: u64,

    /// Layers
    pub layers: Vec<LayerInfo>,

    /// Path to extracted rootfs
    pub rootfs_path: String,
}

/// Layer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerInfo {
    /// Layer digest
    pub digest: String,

    /// Size in bytes
    pub size: u64,

    /// Media type
    pub media_type: String,
}
