use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn chrono_lite_timestamp() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    let secs_of_day = secs % 60;
    format!("{:02}:{:02}:{:02}", hours, mins, secs_of_day)
}

pub fn parse_run_args(
    image_or_command: Option<String>,
    mut command: Vec<String>,
) -> (Option<String>, Vec<String>) {
    if let Some(first_arg) = image_or_command {
        if is_image_name(&first_arg) {
            return (Some(first_arg), command);
        }
        // Fallback: check if rootfs exists for this name (it's an image)
        if has_rootfs(&first_arg) {
            return (Some(first_arg), command);
        }
        // Otherwise treat as command
        command.insert(0, first_arg);
        return (None, command);
    }
    (None, command)
}

fn has_rootfs(name: &str) -> bool {
    if let Ok(home) = std::env::var("HOME") {
        let rootfs_path = PathBuf::from(home)
            .join(".phantom")
            .join("rootfs")
            .join(name);
        return rootfs_path.exists();
    }
    false
}

pub fn is_image_name(s: &str) -> bool {
    // Docker/OCI image with registry tag
    if s.contains(':') && !s.starts_with('/') && !s.starts_with("./") {
        return true;
    }
    // Absolute path to local image/directory
    if s.starts_with('/') || s.starts_with("./") || s.starts_with("../") {
        return false;
    }
    // Starts with dash - likely a flag, not an image
    if s.starts_with('-') {
        return false;
    }
    // Common container image names (single word, no slash = likely image)
    if !s.contains('/') {
        return true;
    }
    // Has slash but no dots and looks like path - might be command
    if s.contains('/') && !s.contains('.') {
        // Could be either image (registry/name) or command path
        // Default to image for backward compatibility with registry names
        return true;
    }
    false
}

pub fn strip_timestamp(line: &str) -> String {
    if let Some(pos) = line.find(" │ ") {
        if pos + 3 < line.len() {
            return line[pos + 3..].to_string();
        }
    }
    line.to_string()
}

pub fn tail_file(path: PathBuf, n: usize) -> anyhow::Result<Vec<String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let all_lines: Vec<String> = reader.lines().filter_map(|l| l.ok()).collect();

    let start = if all_lines.len() > n {
        all_lines.len() - n
    } else {
        0
    };

    Ok(all_lines[start..].to_vec())
}

pub fn read_file_lines(path: PathBuf) -> anyhow::Result<Vec<String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    Ok(reader.lines().filter_map(|l| l.ok()).collect())
}

pub fn get_log_path(name: &str) -> PathBuf {
    use crate::config::PhantomPaths;
    let paths = PhantomPaths::new();
    paths.logs().join(format!("{}.log", name.replace('/', "-")))
}

pub async fn follow_file(
    path: PathBuf,
) -> anyhow::Result<impl tokio_stream::Stream<Item = std::io::Result<String>>> {
    use tokio::fs::File;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio_stream::wrappers::LinesStream;

    let file = File::open(path).await?;
    let reader = BufReader::new(file);
    Ok(LinesStream::new(reader.lines()))
}
