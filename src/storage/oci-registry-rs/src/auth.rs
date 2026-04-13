//! Authentication for OCI registries
//!
//! Supports both Docker credential helpers and custom authentication

use crate::{RegistryError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Username (for custom auth)
    pub username: Option<String>,

    /// Password (for custom auth)
    pub password: Option<String>,

    /// Auth token (Bearer token)
    pub token: Option<String>,
}

impl AuthConfig {
    /// Create anonymous auth (no credentials)
    pub fn anonymous() -> Self {
        Self {
            username: None,
            password: None,
            token: None,
        }
    }

    /// Create from username/password
    pub fn from_credentials(username: String, password: String) -> Self {
        Self {
            username: Some(username),
            password: Some(password),
            token: None,
        }
    }

    /// Create from token
    pub fn from_token(token: String) -> Self {
        Self {
            username: None,
            password: None,
            token: Some(token),
        }
    }

    /// Get Basic Auth header value
    pub fn basic_auth_header(&self) -> Option<String> {
        if let (Some(user), Some(pass)) = (&self.username, &self.password) {
            use base64::{engine::general_purpose::STANDARD, Engine as _};
            let encoded_credentials = STANDARD.encode(format!("{}:{}", user, pass));
            Some(format!("Basic {}", encoded_credentials))
        } else {
            None
        }
    }

    /// Get Bearer token header value
    pub fn bearer_token_header(&self) -> Option<String> {
        self.token.as_ref().map(|t| format!("Bearer {}", t))
    }
}

/// Docker credential helper interface
pub struct CredentialHelper {
    config_dir: PathBuf,
}

impl CredentialHelper {
    /// Create a new credential helper
    pub fn new() -> Self {
        let config_dir = home::home_dir()
            .map(|h| h.join(".docker"))
            .unwrap_or_else(|| PathBuf::from(".docker"));

        Self { config_dir }
    }

    /// Get credentials for a registry using Docker credential helper
    pub fn get_credentials(&self, registry: &str) -> Result<AuthConfig> {
        // Try docker-credential-* helpers
        let helpers = self.list_credential_helpers();

        for helper in helpers {
            if let Ok(auth) = self.call_helper(&helper, "get", registry) {
                return Ok(auth);
            }
        }

        // Fallback: check docker config.json
        self.get_from_config(registry)
    }

    /// List available credential helpers
    fn list_credential_helpers(&self) -> Vec<String> {
        let mut helpers = Vec::new();

        // Check common credential helpers
        for helper in &[
            "docker-credential-secretservice",
            "docker-credential-pass",
            "docker-credential-osxkeychain",
            "docker-credential-wincred",
        ] {
            if which::which(helper).is_ok() {
                helpers.push(helper.to_string());
            }
        }

        helpers
    }

    /// Call a credential helper
    fn call_helper(&self, helper: &str, action: &str, server: &str) -> Result<AuthConfig> {
        let output = Command::new(helper)
            .arg(action)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                if let Some(mut stdin) = child.stdin.take() {
                    stdin.write_all(server.as_bytes())?;
                }
                child.wait_with_output()
            })
            .map_err(|e| RegistryError::Other(format!("Failed to run credential helper: {}", e)))?;

        if !output.status.success() {
            return Err(RegistryError::AuthenticationFailed(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }

        #[derive(Deserialize)]
        struct HelperResponse {
            #[serde(rename = "Username")]
            username: String,
            #[serde(rename = "Secret")]
            secret: String,
        }

        let response: HelperResponse = serde_json::from_slice(&output.stdout)
            .map_err(|e| RegistryError::Other(format!("Invalid helper response: {}", e)))?;

        Ok(AuthConfig::from_credentials(
            response.username,
            response.secret,
        ))
    }

    /// Get credentials from Docker config.json
    fn get_from_config(&self, registry: &str) -> Result<AuthConfig> {
        let config_path = self.config_dir.join("config.json");

        if !config_path.exists() {
            return Ok(AuthConfig::anonymous());
        }

        #[derive(Deserialize)]
        struct DockerConfig {
            auths: Option<HashMap<String, AuthEntry>>,
        }

        #[derive(Deserialize)]
        struct AuthEntry {
            auth: Option<String>,
        }

        let config_content = std::fs::read_to_string(&config_path)?;
        let config: DockerConfig = serde_json::from_str(&config_content)
            .map_err(|e| RegistryError::Other(format!("Invalid config.json: {}", e)))?;

        if let Some(auths) = config.auths {
            // Try exact match first
            if let Some(entry) = auths.get(registry) {
                if let Some(auth) = &entry.auth {
                    return self.decode_auth(auth);
                }
            }

            // Try with https:// prefix
            let registry_url = format!("https://{}", registry);
            if let Some(entry) = auths.get(&registry_url) {
                if let Some(auth) = &entry.auth {
                    return self.decode_auth(auth);
                }
            }
        }

        Ok(AuthConfig::anonymous())
    }

    /// Decode base64 auth string
    fn decode_auth(&self, auth: &str) -> Result<AuthConfig> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let decoded = STANDARD
            .decode(auth)
            .map_err(|e| RegistryError::Other(format!("Invalid auth encoding: {}", e)))?;

        let auth_str = String::from_utf8(decoded)
            .map_err(|e| RegistryError::Other(format!("Invalid auth string: {}", e)))?;

        if let Some(colon_pos) = auth_str.find(':') {
            let username = auth_str[..colon_pos].to_string();
            let password = auth_str[colon_pos + 1..].to_string();
            Ok(AuthConfig::from_credentials(username, password))
        } else {
            Err(RegistryError::Other("Invalid auth format".to_string()))
        }
    }
}

impl Default for CredentialHelper {
    fn default() -> Self {
        Self::new()
    }
}
