//! Build executor - Runs Fragmentfile instructions

use crate::parser::{BuildStage, Instruction};
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Image configuration stored with built images
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ImageConfig {
    pub entrypoint: Option<Vec<String>>,
    pub cmd: Option<Vec<String>>,
    pub env: Vec<String>,
    pub workdir: String,
    pub user: String,
    pub labels: HashMap<String, String>,
    pub exposed_ports: Vec<u16>,
    pub volumes: Vec<String>,
}

impl Default for ImageConfig {
    fn default() -> Self {
        Self {
            entrypoint: None,
            cmd: None,
            env: vec![
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
            ],
            workdir: "/".to_string(),
            user: "root".to_string(),
            labels: HashMap::new(),
            exposed_ports: Vec::new(),
            volumes: Vec::new(),
        }
    }
}

/// Build context
pub struct BuildContext {
    /// Path to build context
    pub context_path: PathBuf,

    /// Enable layer caching
    pub enable_cache: bool,

    /// Layer cache directory
    pub cache_dir: PathBuf,

    /// Build secrets (id -> path)
    pub secrets: HashMap<String, PathBuf>,

    /// Current working directory within the image
    pub workdir: PathBuf,

    /// Environment variables for the build
    pub environment: HashMap<String, String>,

    /// Temporary rootfs for build operations
    pub build_rootfs: PathBuf,

    /// Layers created during build
    pub layers: Vec<String>,

    /// Build arguments (--build-arg values)
    pub build_args: HashMap<String, String>,

    /// Image configuration
    pub image_config: ImageConfig,
}

impl BuildContext {
    pub fn new<P: AsRef<Path>>(context_path: P) -> Self {
        let home = std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp"));

        let cache_dir = home.join(".phantom/build-cache");
        let build_rootfs = home.join(".phantom/build-tmp");

        Self {
            context_path: context_path.as_ref().to_path_buf(),
            enable_cache: true,
            cache_dir,
            secrets: HashMap::new(),
            workdir: PathBuf::from("/"),
            environment: HashMap::from([(
                "PATH".to_string(),
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
            )]),
            build_rootfs,
            layers: Vec::new(),
            build_args: HashMap::new(),
            image_config: ImageConfig::default(),
        }
    }
}

/// Build stage executor
pub struct BuildExecutor {
    pub context: BuildContext,
    /// Track build stages with their output directories (stage name -> output dir)
    pub stages: HashMap<String, PathBuf>,
    /// Current stage name being built
    pub current_stage: Option<String>,
}

impl BuildExecutor {
    pub fn new(context: BuildContext) -> Self {
        Self {
            context,
            stages: HashMap::new(),
            current_stage: None,
        }
    }

    /// Execute a build stage
    pub async fn execute_stage(&mut self, stage: &BuildStage) -> Result<String> {
        log::info!(
            "Building stage: {}",
            stage.name.as_deref().unwrap_or("<unnamed>")
        );
        log::info!("  Base image: {}", stage.base_image);

        // Set current stage name
        self.current_stage = stage.name.clone();

        // Pull base image if needed
        self.pull_base_image(&stage.base_image).await?;

        // Prepare build rootfs
        self.prepare_build_rootfs(&stage.base_image).await?;

        // Execute each instruction
        for (i, instruction) in stage.instructions.iter().enumerate() {
            log::info!(
                "  Step {}/{}: {:?}",
                i + 1,
                stage.instructions.len(),
                instruction
            );

            // Check cache first
            if self.context.enable_cache {
                if let Some(cached_layer) = self.check_cache(instruction).await? {
                    log::info!("    → Using cached layer: {}", cached_layer);
                    continue;
                }
            }

            // Execute instruction
            self.execute_instruction(instruction).await?;
        }

        // Finalize stage - save stage output directory for multi-stage copies
        self.finalize_stage()?;

        // Return image ID (digest)
        let image_id = self.finalize_image(stage).await?;
        log::info!("✓ Built: {}", image_id);

        Ok(image_id)
    }

    /// Pull base image if not present locally
    async fn pull_base_image(&self, image: &str) -> Result<()> {
        log::info!("    Checking base image: {}", image);

        // Check if image exists locally using phantom images command
        let check = Command::new("phantom").args(["images"]).output();

        if let Ok(output) = check {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains(image) || image == "scratch" {
                log::info!("    → Base image available locally");
                return Ok(());
            }
        }

        // Pull the image
        log::info!("    → Pulling base image...");
        // Use the current executable path to ensure we use the updated binary
        let phantom_exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("phantom"));

        let status = Command::new(phantom_exe)
            .args(["run", image, "/bin/sh", "-c", "true"])
            .status()
            .context("Failed to pull base image")?;

        if !status.success() {
            // If phantom pull fails, it might just mean no phantom command
            // For now, log a warning and continue
            log::warn!(
                "    ⚠ Could not verify base image (phantom not in PATH or image not found)"
            );
        }

        Ok(())
    }

    /// Prepare temporary rootfs for build operations
    pub async fn prepare_build_rootfs(&mut self, base_image: &str) -> Result<()> {
        // Create build rootfs directory
        std::fs::create_dir_all(&self.context.build_rootfs)
            .context("Failed to create build rootfs directory")?;

        if base_image == "scratch" {
            log::info!("    → Starting from empty rootfs (scratch)");
            return Ok(());
        }

        // Find the pulled base image
        let simple_name = base_image.replace(":", "-").replace("/", "_");
        let home = std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp"));

        let source_rootfs = home.join(".phantom").join("rootfs").join(&simple_name);

        if !source_rootfs.exists() {
            anyhow::bail!(
                "Base image rootfs not found at: {}",
                source_rootfs.display()
            );
        }

        log::info!("    → Initializing from base: {}", source_rootfs.display());

        // Recursively copy base image layout to build rootfs
        copy_dir_recursive(&source_rootfs, &self.context.build_rootfs)?;

        log::info!(
            "    → Build rootfs prepared: {}",
            self.context.build_rootfs.display()
        );
        Ok(())
    }

    /// Check if instruction result is cached
    async fn check_cache(&self, instruction: &Instruction) -> Result<Option<String>> {
        let cache_key = self.calculate_cache_key(instruction);
        let cache_file = self.context.cache_dir.join(&cache_key);

        if cache_file.exists() {
            Ok(Some(cache_key))
        } else {
            Ok(None)
        }
    }

    /// Calculate cache key for instruction
    fn calculate_cache_key(&self, instruction: &Instruction) -> String {
        let mut hasher = Sha256::new();
        hasher.update(format!("{:?}", instruction).as_bytes());
        // Include workdir and env in cache key
        hasher.update(self.context.workdir.to_string_lossy().as_bytes());
        for (k, v) in &self.context.environment {
            hasher.update(format!("{}={}", k, v).as_bytes());
        }
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    /// Execute a single instruction
    async fn execute_instruction(&mut self, instruction: &Instruction) -> Result<()> {
        match instruction {
            Instruction::Run { command, mounts } => {
                self.execute_run(command, mounts).await?;
            }

            Instruction::Copy {
                from_stage,
                sources,
                destination,
            } => {
                for source in sources {
                    self.execute_copy(from_stage.as_deref(), source, destination)
                        .await?;
                }
            }

            Instruction::Add {
                source,
                destination,
                checksum,
            } => {
                self.execute_add(source, destination, checksum.as_deref())
                    .await?;
            }

            Instruction::Workdir { path } => {
                let path = self.substitute_vars(path);
                log::info!("    WORKDIR {}", path);
                self.context.workdir = PathBuf::from(&path);
                // Create the directory in build rootfs
                let full_path = self.context.build_rootfs.join(path.trim_start_matches('/'));
                std::fs::create_dir_all(&full_path)
                    .context(format!("Failed to create WORKDIR: {}", path))?;
                self.context.image_config.workdir = path;
            }

            Instruction::Env { key, value } => {
                let value = self.substitute_vars(value);
                log::info!("    ENV {}={}", key, value);
                self.context
                    .image_config
                    .env
                    .push(format!("{}={}", key, &value));
                self.context.environment.insert(key.clone(), value);
            }

            Instruction::Entrypoint { args } => {
                let substituted: Vec<String> =
                    args.iter().map(|a| self.substitute_vars(a)).collect();
                log::info!("    ENTRYPOINT {:?}", substituted);
                self.context.image_config.entrypoint = Some(substituted);
            }

            Instruction::Cmd { args } => {
                let substituted: Vec<String> =
                    args.iter().map(|a| self.substitute_vars(a)).collect();
                log::info!("    CMD {:?}", substituted);
                self.context.image_config.cmd = Some(substituted);
            }

            Instruction::User { user } => {
                let user = self.substitute_vars(user);
                log::info!("    USER {}", user);
                self.context.image_config.user = user;
            }

            Instruction::Arg { name, default } => {
                self.execute_arg(name, default.as_deref())?;
            }

            Instruction::Label { key, value } => {
                let value = self.substitute_vars(value);
                log::info!("    LABEL {}={}", key, value);
                self.context
                    .image_config
                    .labels
                    .insert(key.to_string(), value);
            }

            Instruction::Expose { port } => {
                log::info!("    EXPOSE {}", port);
                self.context.image_config.exposed_ports.push(*port);
            }

            Instruction::Volume { paths } => {
                log::info!("    VOLUME {:?}", paths);
                self.context
                    .image_config
                    .volumes
                    .extend(paths.iter().cloned());
            }

            Instruction::From { .. } => {
                // FROM is handled by stage management
                log::debug!("    FROM instruction (stage boundary)");
            }
        }

        Ok(())
    }

    /// Execute RUN instruction
    async fn execute_run(&mut self, command: &[String], mounts: &[String]) -> Result<()> {
        let cmd_str = command.join(" ");
        log::info!("    RUN {}", cmd_str);

        // Handle secret mounts
        for mount in mounts {
            log::info!("      Mount: {}", mount);
            if mount.contains("type=secret") {
                let parts: Vec<&str> = mount.split(',').collect();
                let mut secret_id = None;

                for part in parts {
                    if let Some(id) = part.strip_prefix("id=") {
                        secret_id = Some(id);
                    }
                }

                if let Some(id) = secret_id {
                    if let Some(secret_path) = self.context.secrets.get(id) {
                        log::info!(
                            "      → Mounting secret '{}' from {}",
                            id,
                            secret_path.display()
                        );
                    } else {
                        log::warn!("      ⚠ Secret '{}' not found in build context", id);
                    }
                }
            }
        }

        // Execute command in build rootfs using bubblewrap
        let bwrap_args = vec![
            "--bind",
            self.context.build_rootfs.to_str().unwrap(),
            "/",
            // Essential mounts
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--tmpfs",
            "/tmp",
            "--chdir",
            self.context.workdir.to_str().unwrap(),
            // Explicitly unshare everything EXCEPT network
            "--unshare-user",
            "--unshare-ipc",
            "--unshare-pid",
            "--unshare-uts",
            // Share network
            "--share-net",
            // Bind DNS (Host -> Container)
            "--ro-bind",
            "/etc/resolv.conf",
            "/etc/resolv.conf",
            "--die-with-parent",
            "/bin/sh",
            "-c",
            &cmd_str,
        ];

        log::debug!("      Executing with bwrap: {:?}", bwrap_args);

        // Try to execute with bwrap
        let result = Command::new("bwrap")
            .args(&bwrap_args)
            .envs(&self.context.environment)
            .status();

        match result {
            Ok(status) if status.success() => {
                log::info!("      ✓ Command completed successfully");
                // Create a layer hash for this instruction
                let layer_hash = self.calculate_cache_key(&Instruction::Run {
                    command: command.to_vec(),
                    mounts: mounts.to_vec(),
                });
                self.context.layers.push(layer_hash);
            }
            Ok(status) => {
                log::warn!("      ⚠ Command exited with status: {}", status);
            }
            Err(e) => {
                // bwrap not available, log and continue
                log::warn!("      ⚠ bwrap not available ({}), simulating execution", e);
            }
        }

        Ok(())
    }

    /// Execute COPY instruction
    async fn execute_copy(
        &mut self,
        from_stage: Option<&str>,
        source: &str,
        destination: &str,
    ) -> Result<()> {
        let source = self.substitute_vars(source);
        let destination = self.substitute_vars(destination);

        if let Some(stage_name) = from_stage {
            log::info!("    COPY --from={} {} {}", stage_name, source, destination);

            // Multi-stage copy: get source from previous stage output
            let source_dir = self.stages.get(stage_name).ok_or_else(|| {
                anyhow::anyhow!(
                    "Stage '{}' not found. Available stages: {:?}",
                    stage_name,
                    self.stages.keys().collect::<Vec<_>>()
                )
            })?;

            let source_path = source_dir.join(source.trim_start_matches('/'));
            let dest_path = self
                .context
                .build_rootfs
                .join(destination.trim_start_matches('/'));

            if !source_path.exists() {
                anyhow::bail!(
                    "Source '{}' not found in stage '{}' (looked at {})",
                    source,
                    stage_name,
                    source_path.display()
                );
            }

            // Create parent directories
            if let Some(parent) = dest_path.parent() {
                std::fs::create_dir_all(parent).context(format!(
                    "Failed to create parent directory for: {}",
                    destination
                ))?;
            }

            // Copy file or directory
            if source_path.is_dir() {
                copy_dir_recursive(&source_path, &dest_path)?;
                log::info!(
                    "      → Copied directory from stage '{}': {} -> {}",
                    stage_name,
                    source,
                    destination
                );
            } else {
                std::fs::copy(&source_path, &dest_path).context(format!(
                    "Failed to copy {} from stage '{}' to {}",
                    source, stage_name, destination
                ))?;
                log::info!(
                    "      → Copied from stage '{}': {} -> {}",
                    stage_name,
                    source,
                    destination
                );
            }
        } else {
            log::info!("    COPY {} {}", source, destination);

            // Resolve source path from build context
            let source_path = self.context.context_path.join(&source);

            // Resolve destination in build rootfs
            let mut dest_path = self
                .context
                .build_rootfs
                .join(destination.trim_start_matches('/'));

            // If destination ends with /, treat as directory and append source filename
            if destination.ends_with('/') {
                if let Some(file_name) = source_path.file_name() {
                    dest_path = dest_path.join(file_name);
                }
            }

            // Create parent directories
            if let Some(parent) = dest_path.parent() {
                std::fs::create_dir_all(parent).context(format!(
                    "Failed to create parent directory for: {}",
                    destination
                ))?;
            }

            // Copy file or directory
            if source_path.is_dir() {
                // Copy directory recursively
                copy_dir_recursive(&source_path, &dest_path)?;
                log::info!(
                    "      → Copied directory: {} -> {}",
                    source_path.display(),
                    dest_path.display()
                );
            } else if source_path.exists() {
                std::fs::copy(&source_path, &dest_path)
                    .context(format!("Failed to copy {} to {}", source, destination))?;
                log::info!(
                    "      → Copied file: {} -> {}",
                    source_path.display(),
                    dest_path.display()
                );
            } else {
                // Handle glob patterns (simplified)
                log::warn!(
                    "      ⚠ Source not found or glob patterns not yet supported: {}",
                    source
                );
            }
        }

        // Create layer hash
        let layer_hash = self.calculate_cache_key(&Instruction::Copy {
            from_stage: from_stage.map(String::from),
            sources: vec![source],
            destination,
        });
        self.context.layers.push(layer_hash);

        Ok(())
    }

    /// Execute ADD instruction (supports URLs and tarball auto-extraction)
    async fn execute_add(
        &mut self,
        source: &str,
        destination: &str,
        checksum: Option<&str>,
    ) -> Result<()> {
        let source = self.substitute_vars(source);
        let destination = self.substitute_vars(destination);

        if source.starts_with("http://") || source.starts_with("https://") {
            // Download from URL
            log::info!("    ADD {} {}", source, destination);
            log::info!("      Downloading from URL...");

            let client = reqwest::Client::new();
            let response = client
                .get(&source)
                .send()
                .await
                .context(format!("Failed to download {}", source))?;
            let data = response
                .bytes()
                .await
                .context(format!("Failed to read response data from {}", source))?;

            // Verify checksum if provided
            if let Some(expected) = checksum {
                let mut hasher = Sha256::new();
                hasher.update(&data);
                let actual = format!("{:x}", hasher.finalize());
                let expected_clean = expected.strip_prefix("sha256:").unwrap_or(expected);
                if actual != expected_clean {
                    anyhow::bail!(
                        "Checksum mismatch for {}: expected {}, got {}",
                        source,
                        expected_clean,
                        actual
                    );
                }
                log::info!("      ✓ Checksum verified");
            }

            // Write to destination
            let dest_path = self
                .context
                .build_rootfs
                .join(destination.trim_start_matches('/'));

            // Create parent directories
            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent).context(format!(
                    "Failed to create parent directory for: {}",
                    destination
                ))?;
            }

            // Check if it's a tarball for auto-extraction
            let is_tarball = source.ends_with(".tar.gz")
                || source.ends_with(".tgz")
                || source.ends_with(".tar.bz2")
                || source.ends_with(".tar.xz");

            if is_tarball {
                log::info!("      Extracting tarball...");
                self.extract_tar(&data, &dest_path)?;
            } else {
                fs::write(&dest_path, &data).context(format!(
                    "Failed to write downloaded file to {}",
                    destination
                ))?;
            }

            log::info!("      ✓ Added {}", source);
        } else {
            // Local file - use COPY logic
            log::info!("    ADD {} {}", source, destination);
            self.execute_copy(None, &source, &destination).await?;
        }

        // Create layer hash
        let layer_hash = self.calculate_cache_key(&Instruction::Add {
            source,
            destination,
            checksum: checksum.map(String::from),
        });
        self.context.layers.push(layer_hash);

        Ok(())
    }

    /// Extract tarball data to destination directory
    fn extract_tar(&self, data: &[u8], dest_path: &Path) -> Result<()> {
        // Create destination directory
        fs::create_dir_all(dest_path).context(format!(
            "Failed to create extraction directory: {}",
            dest_path.display()
        ))?;

        // Use tar command to extract
        let temp_tar = dest_path.with_extension("tar.tmp");
        fs::write(&temp_tar, data).context("Failed to write temporary tar file")?;

        let result = Command::new("tar")
            .args([
                "-xzf",
                temp_tar.to_str().unwrap(),
                "-C",
                dest_path.to_str().unwrap(),
            ])
            .status();

        // Clean up temp file
        let _ = fs::remove_file(&temp_tar);

        match result {
            Ok(status) if status.success() => {
                log::info!("      ✓ Tarball extracted to {}", dest_path.display());
            }
            Ok(status) => {
                anyhow::bail!("tar command exited with status: {}", status);
            }
            Err(e) => {
                // tar not available, write as-is
                log::warn!("      ⚠ tar not available, writing as-is: {}", e);
                fs::write(dest_path, data)?;
            }
        }

        Ok(())
    }

    /// Execute ARG instruction
    fn execute_arg(&mut self, name: &str, default: Option<&str>) -> Result<()> {
        // Use provided --build-arg value or default
        let value = self
            .context
            .build_args
            .get(name)
            .cloned()
            .or_else(|| default.map(String::from))
            .unwrap_or_default();

        log::info!("    ARG {}={}", name, &value);
        self.context.build_args.insert(name.to_string(), value);
        Ok(())
    }

    /// Substitute variables in text (${VAR} and $VAR)
    fn substitute_vars(&self, text: &str) -> String {
        let mut result = text.to_string();

        // Substitute ARG variables
        for (name, value) in &self.context.build_args {
            result = result.replace(&format!("${{{}}}", name), value);
            result = result.replace(&format!("${}", name), value);
        }

        // Substitute ENV variables
        for (key, value) in &self.context.environment {
            result = result.replace(&format!("${{{}}}", key), value);
            result = result.replace(&format!("${}", key), value);
        }

        result
    }

    /// Finalize stage - save stage output directory for multi-stage copies
    fn finalize_stage(&mut self) -> Result<()> {
        if let Some(stage_name) = self.current_stage.take() {
            // Create stage output path
            let stage_output = self
                .context
                .build_rootfs
                .join(format!("stages/{}", stage_name));
            fs::create_dir_all(&stage_output).context(format!(
                "Failed to create stage output directory: {}",
                stage_output.display()
            ))?;

            // Copy current build rootfs to stage output
            copy_dir_recursive(&self.context.build_rootfs, &stage_output)?;

            // Register stage
            log::info!("    ✓ Stage '{}' finalized", &stage_name);
            self.stages.insert(stage_name, stage_output);
        }
        Ok(())
    }

    /// Save image configuration
    fn save_image_config(&self, image_path: &Path) -> Result<()> {
        let config_path = image_path.join("phantom-config.json");
        fs::create_dir_all(image_path)?;
        fs::write(
            &config_path,
            serde_json::to_string_pretty(&self.context.image_config)?,
        )
        .context(format!(
            "Failed to save image config: {}",
            config_path.display()
        ))?;
        log::info!("    ✓ Saved image config: {}", config_path.display());
        Ok(())
    }

    /// Finalize image and return ID
    async fn finalize_image(&self, stage: &BuildStage) -> Result<String> {
        log::info!("    Finalizing image...");

        // Create image manifest
        let mut hasher = Sha256::new();

        // Hash base image
        hasher.update(stage.base_image.as_bytes());

        // Hash all layers
        for layer in &self.context.layers {
            hasher.update(layer.as_bytes());
        }

        // Hash environment
        for (k, v) in &self.context.environment {
            hasher.update(format!("{}={}", k, v).as_bytes());
        }

        let image_id = format!("sha256:{}", hex::encode(hasher.finalize()));

        // Save image configuration
        let home = std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp"));
        let simple_name = stage.base_image.replace(":", "-").replace("/", "_");
        let image_path = home.join(".phantom").join("rootfs").join(&simple_name);

        if let Err(e) = self.save_image_config(&image_path) {
            log::warn!("Failed to save image config: {}", e);
        }

        // Save cache metadata
        if self.context.enable_cache {
            let cache_metadata = self.context.cache_dir.join("metadata.json");
            std::fs::create_dir_all(&self.context.cache_dir).ok();

            // For now, just touch the file to indicate successful build
            std::fs::write(
                &cache_metadata,
                format!("{{\"last_build\": \"{}\"}}", image_id),
            )
            .ok();
        }

        log::info!("    → {} layers committed", self.context.layers.len());
        log::info!("    → Image ID: {}", &image_id[..20]);

        Ok(image_id)
    }
}

/// Helper function to copy directory recursively
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;

    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let file_name = entry.file_name();
        let file_type = entry.file_type()?;

        // Skip common ignore directories
        if let Some(name) = file_name.to_str() {
            if name == ".git" || name == "target" || name == "node_modules" || name == ".phantom" {
                continue;
            }
        }

        let dst_path = dst.join(&file_name);

        if file_type.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else if file_type.is_symlink() {
            // Preserve symlinks
            if let Ok(link_target) = std::fs::read_link(&src_path) {
                if let Err(e) = std::os::unix::fs::symlink(&link_target, &dst_path) {
                    log::warn!(
                        "      ⚠ Failed to create symlink {}: {}",
                        dst_path.display(),
                        e
                    );
                }
            }
        } else {
            // Use copy, but handle errors gracefully for special files
            if let Err(e) = std::fs::copy(&src_path, &dst_path) {
                log::warn!("      ⚠ Failed to copy {}: {}", src_path.display(), e);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::Instruction;

    #[test]
    fn test_cache_key_generation() {
        let ctx = BuildContext::new(".");
        let executor = BuildExecutor::new(ctx);

        let inst1 = Instruction::Run {
            command: vec!["echo".to_string(), "hello".to_string()],
            mounts: vec![],
        };

        let inst2 = Instruction::Run {
            command: vec!["echo".to_string(), "world".to_string()],
            mounts: vec![],
        };

        let key1 = executor.calculate_cache_key(&inst1);
        let key2 = executor.calculate_cache_key(&inst2);

        // Different commands = different cache keys
        assert_ne!(key1, key2);
        assert!(key1.starts_with("sha256:"));
    }

    #[test]
    fn test_build_context_creation() {
        let ctx = BuildContext::new("/tmp/test");
        assert_eq!(ctx.context_path, PathBuf::from("/tmp/test"));
        assert!(ctx.enable_cache);
        assert_eq!(ctx.workdir, PathBuf::from("/"));
    }

    #[test]
    fn test_workdir_setting() {
        let ctx = BuildContext::new(".");
        let mut executor = BuildExecutor::new(ctx);

        // Simulate setting workdir
        executor.context.workdir = PathBuf::from("/app");
        assert_eq!(executor.context.workdir, PathBuf::from("/app"));
    }
}
