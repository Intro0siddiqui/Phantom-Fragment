//! OCI Registry Push Support
//!
//! Provides functionality to push images to OCI registries.

use crate::{
    AuthConfig, CredentialHelper, Descriptor, ImageManifest, ImageReference, RegistryError, Result,
};
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::AsyncReadExt;

/// Push configuration
#[derive(Debug, Clone)]
pub struct PushConfig {
    /// Maximum concurrent uploads
    pub max_concurrent: usize,

    /// Enable compression
    pub compress: bool,
}

impl Default for PushConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 3,
            compress: true,
        }
    }
}

/// Layer to push
#[derive(Debug, Clone)]
pub struct PushLayer {
    /// Path to layer tarball
    pub path: PathBuf,

    /// Media type
    pub media_type: String,

    /// Optional digest (computed if not provided)
    pub digest: Option<String>,

    /// Optional size (computed if not provided)
    pub size: Option<u64>,
}

/// Image to push
#[derive(Debug, Clone)]
pub struct PushImage {
    /// Image reference
    pub reference: String,

    /// Layers to push
    pub layers: Vec<PushLayer>,

    /// Config blob path
    pub config_path: Option<PathBuf>,

    /// Annotations
    pub annotations: std::collections::HashMap<String, String>,
}

/// Registry pusher
pub struct RegistryPusher {
    client: Client,
    auth_helper: CredentialHelper,
}

impl RegistryPusher {
    /// Create a new pusher
    pub fn new(_config: PushConfig) -> Result<Self> {
        let client = Client::builder()
            .user_agent("phantom-fragment/0.1.0")
            .build()
            .map_err(|e| RegistryError::Other(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            client,
            auth_helper: CredentialHelper::new(),
        })
    }

    /// Push an image to a registry
    pub async fn push(&self, image: &PushImage) -> Result<String> {
        let reference = ImageReference::parse(&image.reference)
            .map_err(|e| RegistryError::Other(format!("Invalid image reference: {}", e)))?;

        log::info!("Pushing image: {}", reference);

        // Get authentication
        let auth = self.get_auth(&reference)?;
        let token = self.authenticate(&reference, &auth).await?;

        // Push layers
        let mut layer_descriptors = Vec::new();
        for layer in &image.layers {
            let descriptor = self.push_layer(&reference, layer, &token).await?;
            layer_descriptors.push(descriptor);
        }

        // Push config if provided
        let config_descriptor = if let Some(config_path) = &image.config_path {
            Some(self.push_config(&reference, config_path, &token).await?)
        } else {
            // Create default config
            Some(self.create_default_config(&reference, &token).await?)
        };

        // Create and push manifest
        let manifest = ImageManifest {
            schema_version: 2,
            media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            config: config_descriptor.unwrap_or_else(|| Descriptor {
                media_type: "application/vnd.oci.image.config.v1+json".to_string(),
                size: 0,
                digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
            }),
            layers: layer_descriptors,
        };

        let digest = self.push_manifest(&reference, &manifest, &token).await?;

        log::info!("Image pushed successfully: {}", digest);
        Ok(digest)
    }

    /// Push a single layer
    async fn push_layer(
        &self,
        reference: &ImageReference,
        layer: &PushLayer,
        token: &str,
    ) -> Result<Descriptor> {
        log::info!("Pushing layer: {}", layer.path.display());

        // Read layer file
        let mut file = File::open(&layer.path)
            .await
            .map_err(|e| RegistryError::Io(e))?;

        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .await
            .map_err(|e| RegistryError::Io(e))?;

        // Compute digest
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let digest = format!("sha256:{:x}", hasher.finalize());
        let size = data.len() as u64;

        log::info!("Layer digest: {} ({} bytes)", &digest[..17], size);

        // Check if layer already exists
        if self.layer_exists(reference, &digest, token).await? {
            log::info!("Layer already exists, skipping upload");
            return Ok(Descriptor {
                media_type: layer.media_type.clone(),
                size,
                digest,
            });
        }

        // Upload layer
        let upload_url = format!(
            "{}/v2/{}/blobs/uploads/",
            reference.registry_url(),
            reference.repository
        );

        // Start upload
        let response = self
            .client
            .post(&upload_url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .map_err(RegistryError::Network)?;

        if !response.status().is_success() {
            return Err(RegistryError::Other(format!(
                "Failed to start upload: {}",
                response.status()
            )));
        }

        // Get upload location
        let upload_location = response
            .headers()
            .get("Location")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| RegistryError::Other("No upload location in response".to_string()))?;

        // Upload blob
        let response = self
            .client
            .put(format!("{}&digest={}", upload_location, digest))
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/octet-stream")
            .body(data)
            .send()
            .await
            .map_err(RegistryError::Network)?;

        if !response.status().is_success() {
            return Err(RegistryError::Other(format!(
                "Failed to upload layer: {}",
                response.status()
            )));
        }

        Ok(Descriptor {
            media_type: layer.media_type.clone(),
            size,
            digest,
        })
    }

    /// Push config blob
    async fn push_config(
        &self,
        reference: &ImageReference,
        config_path: &Path,
        token: &str,
    ) -> Result<Descriptor> {
        log::info!("Pushing config: {}", config_path.display());

        let mut file = File::open(config_path)
            .await
            .map_err(|e| RegistryError::Io(e))?;

        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .await
            .map_err(|e| RegistryError::Io(e))?;

        let mut hasher = Sha256::new();
        hasher.update(&data);
        let digest = format!("sha256:{:x}", hasher.finalize());
        let size = data.len() as u64;

        // Upload config
        let upload_url = format!(
            "{}/v2/{}/blobs/uploads/",
            reference.registry_url(),
            reference.repository
        );

        let response = self
            .client
            .post(&upload_url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .map_err(RegistryError::Network)?;

        let upload_location = response
            .headers()
            .get("Location")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| RegistryError::Other("No upload location".to_string()))?;

        let response = self
            .client
            .put(format!("{}&digest={}", upload_location, digest))
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/octet-stream")
            .body(data)
            .send()
            .await
            .map_err(RegistryError::Network)?;

        if !response.status().is_success() {
            return Err(RegistryError::Other(format!(
                "Failed to upload config: {}",
                response.status()
            )));
        }

        Ok(Descriptor {
            media_type: "application/vnd.oci.image.config.v1+json".to_string(),
            size,
            digest,
        })
    }

    /// Create default config
    async fn create_default_config(
        &self,
        _reference: &ImageReference,
        _token: &str,
    ) -> Result<Descriptor> {
        // Create minimal OCI config
        let config = serde_json::json!({
            "architecture": "amd64",
            "os": "linux",
            "created": chrono::Utc::now().to_rfc3339(),
            "config": {
                "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
                "Cmd": ["/bin/sh"],
            },
            "rootfs": {
                "type": "layers",
                "diff_ids": []
            }
        });

        let data = serde_json::to_vec(&config)
            .map_err(|e| RegistryError::Other(format!("Failed to serialize config: {}", e)))?;

        let mut hasher = Sha256::new();
        hasher.update(&data);
        let digest = format!("sha256:{:x}", hasher.finalize());
        let size = data.len() as u64;

        // For default config, we just return the descriptor without uploading
        // In a full implementation, this would be uploaded
        Ok(Descriptor {
            media_type: "application/vnd.oci.image.config.v1+json".to_string(),
            size,
            digest,
        })
    }

    /// Push manifest
    async fn push_manifest(
        &self,
        reference: &ImageReference,
        manifest: &ImageManifest,
        token: &str,
    ) -> Result<String> {
        log::info!("Pushing manifest");

        let data = serde_json::to_vec(manifest)
            .map_err(|e| RegistryError::Other(format!("Failed to serialize manifest: {}", e)))?;

        let mut hasher = Sha256::new();
        hasher.update(&data);
        let digest = format!("sha256:{:x}", hasher.finalize());

        let manifest_url = format!(
            "{}/v2/{}/manifests/{}",
            reference.registry_url(),
            reference.repository,
            reference.tag
        );

        let response = self
            .client
            .put(&manifest_url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/vnd.oci.image.manifest.v1+json")
            .body(data)
            .send()
            .await
            .map_err(RegistryError::Network)?;

        if !response.status().is_success() {
            return Err(RegistryError::Other(format!(
                "Failed to push manifest: {}",
                response.status()
            )));
        }

        Ok(digest)
    }

    /// Check if a layer exists
    async fn layer_exists(
        &self,
        reference: &ImageReference,
        digest: &str,
        token: &str,
    ) -> Result<bool> {
        let url = format!(
            "{}/v2/{}/blobs/{}",
            reference.registry_url(),
            reference.repository,
            digest
        );

        let response = self
            .client
            .head(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .map_err(RegistryError::Network)?;

        Ok(response.status().is_success())
    }

    /// Get authentication
    fn get_auth(&self, reference: &ImageReference) -> Result<AuthConfig> {
        match self.auth_helper.get_credentials(&reference.registry) {
            Ok(auth) => {
                if auth.username.is_some() || auth.token.is_some() {
                    return Ok(auth);
                }
            }
            Err(e) => {
                log::debug!("Credential helper failed: {}", e);
            }
        }

        Ok(AuthConfig::anonymous())
    }

    /// Authenticate with registry
    async fn authenticate(&self, reference: &ImageReference, auth: &AuthConfig) -> Result<String> {
        let (auth_url, service) = match reference.registry.as_str() {
            "docker.io" => ("https://auth.docker.io/token", "registry.docker.io"),
            "ghcr.io" => ("https://ghcr.io/token", "ghcr.io"),
            "quay.io" => ("https://quay.io/v2/auth", "quay.io"),
            _ => {
                let url = format!("{}/v2/token", reference.registry_url());
                return self.authenticate_custom(&url, reference, auth).await;
            }
        };

        let mut request = self.client.get(auth_url).query(&[
            ("service", service),
            (
                "scope",
                &format!("repository:{}:push", reference.repository),
            ),
        ]);

        if let Some(basic_auth) = auth.basic_auth_header() {
            request = request.header("Authorization", basic_auth);
        }

        let response = request.send().await.map_err(RegistryError::Network)?;

        if !response.status().is_success() {
            return Err(RegistryError::AuthenticationFailed(format!(
                "Status: {}",
                response.status()
            )));
        }

        #[derive(serde::Deserialize)]
        struct TokenResponse {
            token: Option<String>,
            access_token: Option<String>,
        }

        let token_resp: TokenResponse = response
            .json()
            .await
            .map_err(|e| RegistryError::Other(format!("Failed to parse token response: {}", e)))?;

        let token = token_resp
            .token
            .or(token_resp.access_token)
            .ok_or_else(|| {
                RegistryError::AuthenticationFailed("No token in response".to_string())
            })?;

        Ok(token)
    }

    /// Authenticate with custom registry
    async fn authenticate_custom(
        &self,
        url: &str,
        reference: &ImageReference,
        auth: &AuthConfig,
    ) -> Result<String> {
        let result = self
            .client
            .get(url)
            .query(&[(
                "scope",
                &format!("repository:{}:push", reference.repository),
            )])
            .send()
            .await;

        match result {
            Ok(response) if response.status().is_success() => {
                #[derive(serde::Deserialize)]
                struct TokenResponse {
                    token: Option<String>,
                    access_token: Option<String>,
                }

                if let Ok(token_resp) = response.json::<TokenResponse>().await {
                    if let Some(token) = token_resp.token.or(token_resp.access_token) {
                        return Ok(token);
                    }
                }
            }
            _ => {}
        }

        if let Some(token) = &auth.token {
            Ok(token.clone())
        } else if auth.username.is_some() {
            Ok(auth.basic_auth_header().unwrap_or_default())
        } else {
            Ok(String::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_config_default() {
        let config = PushConfig::default();
        assert_eq!(config.max_concurrent, 3);
        assert!(config.compress);
    }
}
