//! OCI manifest parsing

use serde::{Deserialize, Serialize};

/// OCI Image Manifest (OCI v1)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageManifest {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,

    ///Media type
    #[serde(rename = "mediaType")]
    pub media_type: String,

    /// Config descriptor
    pub config: Descriptor,

    /// Layer descriptors
    pub layers: Vec<Descriptor>,
}

/// Docker Image Manifest (V2 Schema 2)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerManifest {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,

    #[serde(rename = "mediaType")]
    pub media_type: String,

    pub config: Descriptor,
    pub layers: Vec<Descriptor>,
}

/// Manifest List (multi-platform)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestList {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,

    #[serde(rename = "mediaType")]
    pub media_type: String,

    pub manifests: Vec<PlatformManifest>,
}

/// Platform-specific manifest descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformManifest {
    #[serde(rename = "mediaType")]
    pub media_type: String,

    pub size: u64,
    pub digest: String,

    pub platform: Platform,
}

/// Platform specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Platform {
    pub architecture: String,
    pub os: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
}

/// Descriptor for a blob
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Descriptor {
    /// Media type
    #[serde(rename = "mediaType")]
    pub media_type: String,

    /// Size in bytes
    pub size: u64,

    /// Digest (sha256:...)
    pub digest: String,
}

impl ImageManifest {
    /// Parse from JSON bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, serde_json::Error> {
        // Try OCI format first
        if let Ok(manifest) = serde_json::from_slice::<ImageManifest>(data) {
            return Ok(manifest);
        }

        // Try Docker V2 format
        if let Ok(docker_manifest) = serde_json::from_slice::<DockerManifest>(data) {
            // Convert to OCI format
            return Ok(ImageManifest {
                schema_version: docker_manifest.schema_version,
                media_type: docker_manifest.media_type,
                config: docker_manifest.config,
                layers: docker_manifest.layers,
            });
        }

        // If both fail, return the original error
        serde_json::from_slice(data)
    }

    /// Get total size of all layers
    pub fn total_size(&self) -> u64 {
        self.layers.iter().map(|l| l.size).sum::<u64>() + self.config.size
    }
}

impl ManifestList {
    /// Parse from JSON bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }

    /// Find manifest for linux/amd64
    pub fn find_platform(&self, os: &str, arch: &str) -> Option<&PlatformManifest> {
        self.manifests
            .iter()
            .find(|m| m.platform.os == os && m.platform.architecture == arch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_oci_manifest() {
        let json = r#"{
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "size": 1234,
                "digest": "sha256:abcd"
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "size": 5678,
                    "digest": "sha256:efgh"
                }
            ]
        }"#;

        let manifest = ImageManifest::from_bytes(json.as_bytes()).unwrap();
        assert_eq!(manifest.schema_version, 2);
        assert_eq!(manifest.layers.len(), 1);
        assert_eq!(manifest.total_size(), 1234 + 5678);
    }
}
