//! Fragment debugger attacher module

use async_trait::async_trait;
use std::collections::HashMap;
use tokio::net::TcpListener;
use tokio::process::Command as TokioCommand;

use crate::error::{DebugError, Result};
use crate::types::{DebuggerBackend, FragmentAttacher};

impl FragmentAttacher {
    pub fn new() -> Self {
        Self {
            debuggers: HashMap::new(),
        }
    }

    pub async fn attach(
        &mut self,
        fragment_id: &str,
        debugger_type: &str,
        port: Option<u16>,
    ) -> Result<()> {
        let pid = self.find_fragment_pid(fragment_id).await?;

        let backend = self.get_debugger_backend(debugger_type)?;

        let port_val = match port {
            Some(p) => p,
            None => Self::find_available_port().await.unwrap_or(23000),
        };
        backend.attach(pid, port_val).await?;

        println!(
            "Attached {} debugger to fragment {} (PID: {}) on port {}",
            debugger_type, fragment_id, pid, port_val
        );

        Ok(())
    }

    async fn find_available_port() -> Option<u16> {
        let base_port = 23000u16;

        for port in base_port..(base_port + 1000) {
            if Self::is_port_available(port).await {
                return Some(port);
            }
        }

        None
    }

    async fn is_port_available(port: u16) -> bool {
        let addr: std::net::SocketAddr = match format!("127.0.0.1:{}", port).parse() {
            Ok(a) => a,
            Err(_) => return false,
        };
        TcpListener::bind(addr).await.is_ok()
    }

    async fn find_fragment_pid(&self, fragment_id: &str) -> Result<i32> {
        let proc_dir = std::path::Path::new("/proc");

        let mut entries = tokio::fs::read_dir(proc_dir)
            .await
            .map_err(DebugError::Io)?;

        while let Some(entry) = entries.next_entry().await.map_err(DebugError::Io)? {
            if !entry.file_type().await.map_err(DebugError::Io)?.is_dir() {
                continue;
            }

            let pid_str = entry.file_name().to_string_lossy().to_string();
            let pid: i32 = match pid_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            if self.is_fragment_process(pid, fragment_id).await {
                return Ok(pid);
            }
        }

        Err(DebugError::fragment_not_found(fragment_id))
    }

    async fn is_fragment_process(&self, pid: i32, fragment_id: &str) -> bool {
        let comm_path = format!("/proc/{}/comm", pid);
        if let Ok(data) = tokio::fs::read_to_string(&comm_path).await {
            let comm = data.trim();
            if comm == "phantom-fragment" || comm == fragment_id {
                return true;
            }
        }

        let env_path = format!("/proc/{}/environ", pid);
        if let Ok(data) = tokio::fs::read_to_string(&env_path).await {
            for env_var in data.split('\0') {
                if env_var.starts_with("PHANTOM_FRAGMENT_ID=") {
                    let fragment_id_env = &env_var["PHANTOM_FRAGMENT_ID=".len()..];
                    if fragment_id_env == fragment_id {
                        return true;
                    }
                }
            }
        }

        false
    }

    fn get_debugger_backend(
        &mut self,
        debugger_type: &str,
    ) -> Result<&mut Box<dyn DebuggerBackend>> {
        if !self.debuggers.contains_key(debugger_type) {
            let backend: Box<dyn DebuggerBackend> = match debugger_type {
                "gdb" => Box::new(GDBBackend::new()),
                "dlv" => Box::new(DelveBackend::new()),
                _ => {
                    return Err(DebugError::unsupported(&format!(
                        "debugger type: {}",
                        debugger_type
                    )))
                }
            };
            self.debuggers.insert(debugger_type.to_string(), backend);
        }

        self.debuggers
            .get_mut(debugger_type)
            .ok_or_else(|| DebugError::debugger(format!("Debugger '{}' not found", debugger_type)))
    }
}

pub struct GDBBackend {
    pid: Option<i32>,
    port: Option<u16>,
    child: Option<tokio::process::Child>,
}

impl GDBBackend {
    pub fn new() -> Self {
        Self {
            pid: None,
            port: None,
            child: None,
        }
    }
}

#[async_trait]
impl DebuggerBackend for GDBBackend {
    async fn attach(&mut self, pid: i32, port: u16) -> Result<()> {
        self.pid = Some(pid);
        self.port = Some(port);

        let mut cmd = TokioCommand::new("gdb");
        cmd.arg("--batch")
            .arg("-ex")
            .arg("set pagination off")
            .arg("-ex")
            .arg(format!("attach {}", pid))
            .arg("-ex")
            .arg(format!("set remoteaddress 127.0.0.1:{}", port))
            .arg("-ex")
            .arg("set remotetimeout 30");

        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        cmd.stdin(std::process::Stdio::piped());

        let child = cmd
            .spawn()
            .map_err(|e| DebugError::debugger(format!("failed to start GDB: {}", e)))?;

        self.child = Some(child);

        Ok(())
    }

    async fn detach(&mut self) -> Result<()> {
        if let Some(ref mut child) = self.child {
            let _ = child.kill().await;
            self.child = None;
        }
        Ok(())
    }

    async fn get_state(&self) -> Result<String> {
        if self.child.is_none() {
            return Ok("detached".to_string());
        }
        Ok("attached".to_string())
    }

    async fn send_command(&mut self, cmd: &str) -> Result<String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let child = self
            .child
            .as_mut()
            .ok_or_else(|| DebugError::debugger("GDB not attached"))?;

        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| DebugError::debugger("GDB stdin not available"))?;

        let stdout = child
            .stdout
            .as_mut()
            .ok_or_else(|| DebugError::debugger("GDB stdout not available"))?;

        // Send command to GDB
        stdin
            .write_all(format!("{}\n", cmd).as_bytes())
            .await
            .map_err(|e| DebugError::debugger(format!("failed to send command to GDB: {}", e)))?;

        stdin
            .flush()
            .await
            .map_err(|e| DebugError::debugger(format!("failed to flush GDB stdin: {}", e)))?;

        // Read response (this is a simple implementation that reads a small buffer)
        // In a real implementation, we would need a proper GDB/MI parser
        let mut buffer = [0u8; 4096];
        let n = stdout
            .read(&mut buffer)
            .await
            .map_err(|e| DebugError::debugger(format!("failed to read from GDB: {}", e)))?;

        Ok(String::from_utf8_lossy(&buffer[..n]).to_string())
    }
}

pub struct DelveBackend {
    pid: Option<i32>,
    port: Option<u16>,
    child: Option<tokio::process::Child>,
}

impl DelveBackend {
    pub fn new() -> Self {
        Self {
            pid: None,
            port: None,
            child: None,
        }
    }
}

#[async_trait]
impl DebuggerBackend for DelveBackend {
    async fn attach(&mut self, pid: i32, port: u16) -> Result<()> {
        self.pid = Some(pid);
        self.port = Some(port);

        let mut cmd = TokioCommand::new("dlv");
        cmd.arg("--headless")
            .arg("--listen")
            .arg(format!("127.0.0.1:{}", port))
            .arg("--api-version")
            .arg("2")
            .arg("attach")
            .arg(pid.to_string());

        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        cmd.stdin(std::process::Stdio::piped());

        let child = cmd
            .spawn()
            .map_err(|e| DebugError::debugger(format!("failed to start Delve: {}", e)))?;

        self.child = Some(child);

        Ok(())
    }

    async fn detach(&mut self) -> Result<()> {
        if let Some(ref mut child) = self.child {
            let _ = child.kill().await;
            self.child = None;
        }
        Ok(())
    }

    async fn get_state(&self) -> Result<String> {
        if self.child.is_none() {
            return Ok("detached".to_string());
        }
        Ok("attached".to_string())
    }

    async fn send_command(&mut self, cmd: &str) -> Result<String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let child = self
            .child
            .as_mut()
            .ok_or_else(|| DebugError::debugger("Delve not attached"))?;

        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| DebugError::debugger("Delve stdin not available"))?;

        let stdout = child
            .stdout
            .as_mut()
            .ok_or_else(|| DebugError::debugger("Delve stdout not available"))?;

        // Send command to Delve
        stdin
            .write_all(format!("{}\n", cmd).as_bytes())
            .await
            .map_err(|e| DebugError::debugger(format!("failed to send command to Delve: {}", e)))?;

        stdin
            .flush()
            .await
            .map_err(|e| DebugError::debugger(format!("failed to flush Delve stdin: {}", e)))?;

        let mut buffer = [0u8; 4096];
        let n = stdout
            .read(&mut buffer)
            .await
            .map_err(|e| DebugError::debugger(format!("failed to read from Delve: {}", e)))?;

        Ok(String::from_utf8_lossy(&buffer[..n]).to_string())
    }
}
