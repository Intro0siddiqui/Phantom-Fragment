//! Registry client for pulling images from OCI registries

use crate::types::{ImageInfo, LayerInfo};
use crate::{AuthConfig, CredentialHelper, ImageManifest, ImageReference, RegistryError, Result};
use reqwest::Client;
use std::path::PathBuf;

/// OCI Registry Client
pub struct RegistryClient {
    client: Client,
    auth_helper: CredentialHelper,
    cache_dir: PathBuf,
}

impl RegistryClient {
    /// Create a new registry client
    pub fn new(cache_dir: PathBuf) -> Result<Self> {
        let client = Client::builder()
            .user_agent("phantom-fragment/0.1.0")
            .build()
            .map_err(|e| RegistryError::Other(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            client,
            auth_helper: CredentialHelper::new(),
            cache_dir,
        })
    }

    /// Pull an image from a registry
    pub async fn pull(&self, image_ref: &str) -> Result<ImageInfo> {
        let reference = ImageReference::parse(image_ref).map_err(RegistryError::Other)?;

        log::info!("Pulling image: {}", reference);
        log::info!("Registry: {}", reference.registry);

        // Get authentication
        let auth = self.get_auth(&reference)?;

        // Get authentication token from registry
        let token = self.authenticate(&reference, &auth).await?;

        // Fetch manifest
        let manifest = self.fetch_manifest(&reference, &token).await?;

        log::info!("Manifest received: {} layers", manifest.layers.len());

        // Download layers
        let layers = self.download_layers(&reference, &manifest, &token).await?;

        Ok(ImageInfo {
            reference: reference.to_string(),
            digest: manifest.config.digest.clone(),
            size: manifest.total_size(),
            layers,
            rootfs_path: self.cache_dir.join("rootfs").to_string_lossy().into_owned(),
        })
    }

    /// Get authentication for a registry
    fn get_auth(&self, reference: &ImageReference) -> Result<AuthConfig> {
        // Try credential helper first
        match self.auth_helper.get_credentials(&reference.registry) {
            Ok(auth) => {
                if auth.username.is_some() || auth.token.is_some() {
                    log::debug!("Using credentials from helper for {}", reference.registry);
                    return Ok(auth);
                }
            }
            Err(e) => {
                log::debug!("Credential helper failed: {}", e);
            }
        }

        // Fall back to anonymous
        log::debug!("Using anonymous access for {}", reference.registry);
        Ok(AuthConfig::anonymous())
    }

    /// Authenticate with registry and get token
    async fn authenticate(&self, reference: &ImageReference, auth: &AuthConfig) -> Result<String> {
        // Different registries have different auth endpoints
        let (auth_url, service) = match reference.registry.as_str() {
            "docker.io" => ("https://auth.docker.io/token", "registry.docker.io"),
            "ghcr.io" => ("https://ghcr.io/token", "ghcr.io"),
            "quay.io" => ("https://quay.io/v2/auth", "quay.io"),
            _ => {
                // Custom registry - try standard token endpoint
                let url = format!("{}/v2/token", reference.registry_url());
                return self.authenticate_custom(&url, reference, auth).await;
            }
        };

        let mut request = self.client.get(auth_url).query(&[
            ("service", service),
            (
                "scope",
                &format!("repository:{}:pull", reference.repository),
            ),
        ]);

        // Add auth header if we have credentials
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
        // Try token endpoint first
        let result = self
            .client
            .get(url)
            .query(&[(
                "scope",
                &format!("repository:{}:pull", reference.repository),
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

        // Fall back to using provided credentials directly
        if let Some(token) = auth.token.clone() {
            Ok(token)
        } else if auth.username.is_some() {
            // Use basic auth header as token
            Ok(auth.basic_auth_header().unwrap_or_default())
        } else {
            // No authentication
            Ok(String::new())
        }
    }

    /// Fetch image manifest
    async fn fetch_manifest(
        &self,
        reference: &ImageReference,
        token: &str,
    ) -> Result<ImageManifest> {
        let url = format!(
            "{}/v2/{}/manifests/{}",
            reference.registry_url(),
            reference.repository,
            reference.tag
        );

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Accept", "application/vnd.oci.image.manifest.v1+json")
            .header(
                "Accept",
                "application/vnd.docker.distribution.manifest.v2+json",
            )
            .header("Accept", "application/vnd.oci.image.index.v1+json")
            .header(
                "Accept",
                "application/vnd.docker.distribution.manifest.list.v2+json",
            )
            .send()
            .await
            .map_err(RegistryError::Network)?;

        if !response.status().is_success() {
            return Err(RegistryError::Other(format!(
                "Failed to fetch manifest: {}",
                response.status()
            )));
        }

        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()) // Clone the string!
            .unwrap_or_default();

        let bytes = response.bytes().await.map_err(RegistryError::Network)?;

        // Check if this is a manifest list
        if content_type.contains("manifest.list") || content_type.contains("image.index") {
            log::info!("Received manifest list, selecting platform...");

            use crate::manifest::ManifestList;
            let manifest_list = ManifestList::from_bytes(&bytes)
                .map_err(|e| RegistryError::InvalidManifest(e.to_string()))?;

            // Find linux/amd64 manifest
            let platform_manifest = manifest_list
                .find_platform("linux", "amd64")
                .ok_or_else(|| RegistryError::Other("No linux/amd64 manifest found".to_string()))?;

            log::info!("Fetching platform manifest: {}", platform_manifest.digest);

            // Fetch the actual platform-specific manifest
            let platform_url = format!(
                "{}/v2/{}/manifests/{}",
                reference.registry_url(),
                reference.repository,
                platform_manifest.digest
            );

            let platform_response = self
                .client
                .get(&platform_url)
                .header("Authorization", format!("Bearer {}", token))
                .header("Accept", "application/vnd.oci.image.manifest.v1+json")
                .header(
                    "Accept",
                    "application/vnd.docker.distribution.manifest.v2+json",
                )
                .send()
                .await
                .map_err(RegistryError::Network)?;

            let platform_bytes = platform_response
                .bytes()
                .await
                .map_err(RegistryError::Network)?;

            ImageManifest::from_bytes(&platform_bytes)
                .map_err(|e| RegistryError::InvalidManifest(e.to_string()))
        } else {
            // Single manifest
            ImageManifest::from_bytes(&bytes)
                .map_err(|e| RegistryError::InvalidManifest(e.to_string()))
        }
    }

    /// Download all layers
    async fn download_layers(
        &self,
        reference: &ImageReference,
        manifest: &ImageManifest,
        token: &str,
    ) -> Result<Vec<LayerInfo>> {
        use crate::downloader::{DownloadTask, Downloader, DownloaderConfig};

        let config = DownloaderConfig {
            max_concurrent: 3,
            cache_dir: self.cache_dir.join("blobs"),
        };

        let downloader = Downloader::new(self.client.clone(), config);
        let mut tasks = Vec::new();

        for layer in &manifest.layers {
            let url = format!(
                "{}/v2/{}/blobs/{}",
                reference.registry_url(),
                reference.repository,
                layer.digest
            );

            tasks.push(DownloadTask {
                url,
                digest: layer.digest.clone(),
                size: layer.size,
                token: token.to_string(),
            });
        }

        log::info!("Starting parallel download of {} layers...", tasks.len());
        let _paths = downloader.download_layers(tasks).await?;

        // Return layer info
        let mut layers = Vec::new();
        for layer_desc in manifest.layers.iter() {
            layers.push(LayerInfo {
                digest: layer_desc.digest.clone(),
                size: layer_desc.size,
                media_type: layer_desc.media_type.clone(),
            });
        }

        Ok(layers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_docker_hub() {
        let ref_ = ImageReference::parse("ubuntu:22.04").unwrap();
        assert_eq!(ref_.registry, "docker.io");
        assert_eq!(ref_.registry_url(), "https://registry-1.docker.io");
    }

    #[test]
    fn test_parse_ghcr() {
        let ref_ = ImageReference::parse("ghcr.io/user/app:latest").unwrap();
        assert_eq!(ref_.registry, "ghcr.io");
        assert_eq!(ref_.registry_url(), "https://ghcr.io");
    }

    #[test]
    fn test_parse_quay() {
        let ref_ = ImageReference::parse("quay.io/org/image:v1").unwrap();
        assert_eq!(ref_.registry, "quay.io");
        assert_eq!(ref_.registry_url(), "https://quay.io");
    }

    #[test]
    fn test_parse_custom_registry() {
        let ref_ = ImageReference::parse("myregistry.com:5000/app:latest").unwrap();
        assert_eq!(ref_.registry, "myregistry.com:5000");
        assert_eq!(ref_.registry_url(), "https://myregistry.com:5000");
    }
}
