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
        fragmentfile.push_str(&format!("ENV {}=\"{}\"\n", key, value));
    }

    // Add command if specified
    if let Some(cmd) = &container.command {
        fragmentfile.push_str(&format!("CMD {:?}\n", cmd));
    }

    std::fs::write(output, fragmentfile)?;

    Ok(())
}
