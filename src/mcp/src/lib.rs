use anyhow::{Result, anyhow};
use rmcp::{
    model::*, tool, tool_handler, tool_router, transport::stdio, ServerHandler, ServiceExt,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::process::Command;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;

/// Allowlist of permitted commands for security
/// Only these commands can be executed via MCP to prevent command injection
pub(crate) const ALLOWED_COMMANDS: &[&str] = &[
    "echo", "cat", "ls", "pwd", "whoami", "id", "uname",
    "date", "hostname", "env", "printenv", "true", "false",
    "sleep", "head", "tail", "wc", "sort", "uniq", "grep",
    "awk", "sed", "cut", "tr", "tee", "xargs", "find",
    "du", "df", "free", "uptime", "ps", "top", "kill",
    "mkdir", "rmdir", "touch", "rm", "cp", "mv", "ln",
    "chmod", "chown", "stat", "file", "which", "type",
    "sh", "bash", "ash", "dash", "zsh",
    "python", "python3", "node", "npm", "npx",
    "cargo", "rustc", "gcc", "g++", "make", "cmake",
    "git", "curl", "wget", "ping", "netstat", "ss",
    "jq", "yq", "sed", "awk",
    // Common utilities
    "alpine", "ubuntu", "debian", "busybox",
];

/// Validate command against allowlist
pub(crate) fn is_command_allowed(cmd: &str) -> bool {
    // Extract base command (first word)
    let base_cmd = cmd.split_whitespace().next().unwrap_or("");
    ALLOWED_COMMANDS.contains(&base_cmd)
}

/// Sanitize command arguments to prevent injection
pub(crate) fn sanitize_command(cmd: &str) -> Result<String> {
    // Reject commands with shell metacharacters that could enable injection
    let dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '\n', '\r'];
    for ch in dangerous_chars {
        if cmd.contains(ch) {
            return Err(anyhow!(
                "Command contains disallowed character '{}': {}",
                ch,
                cmd
            ));
        }
    }
    
    // Reject command substitution patterns
    if cmd.contains("$(") || cmd.contains("${") {
        return Err(anyhow!("Command substitution is not allowed: {}", cmd));
    }
    
    Ok(cmd.to_string())
}

#[derive(Clone)]
pub struct PhantomService {
    tool_router: ToolRouter<PhantomService>,
}

impl PhantomService {
    pub async fn new() -> Result<Self> {
        Ok(Self {
            tool_router: Self::tool_router(),
        })
    }
}

// Tool parameter types

#[derive(Serialize, Deserialize, JsonSchema)]
struct RunInFragmentParams {
    image: String,
    command: String,
    profile: Option<String>,
    network: Option<bool>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
struct CreateFragmentParams {
    name: String,
    #[serde(default = "default_sandbox")]
    profile: String,
    #[serde(default = "default_true")]
    persist: bool,
}

fn default_sandbox() -> String {
    "sandbox".to_string()
}
fn default_true() -> bool {
    true
}

#[derive(Serialize, Deserialize, JsonSchema)]
struct DestroyFragmentParams {
    name: String,
    #[serde(default)]
    force: bool,
}

#[derive(Serialize, Deserialize, JsonSchema)]
struct ListFragmentsParams {
    #[serde(default)]
    all: bool,
}

#[tool_handler]
impl ServerHandler for PhantomService {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation::from_build_env(),
            instructions: Some(
                "Phantom Fragment MCP Server - Secure AI-native execution environment.".to_string(),
            ),
        }
    }
}

#[tool_router]
impl PhantomService {
    #[tool(description = "Execute a command inside an isolated Phantom Fragment container.")]
    async fn run_in_fragment(
        &self,
        Parameters(params): Parameters<RunInFragmentParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        // Security: Sanitize and validate command to prevent injection
        let sanitized_command = sanitize_command(&params.command)
            .map_err(|e| rmcp::ErrorData {
                code: ErrorCode(-32603),
                message: format!("Security validation failed: {}", e).into(),
                data: None,
            })?;

        // Security: Check command against allowlist
        if !is_command_allowed(&sanitized_command) {
            return Err(rmcp::ErrorData {
                code: ErrorCode(-32603),
                message: format!(
                    "Command not allowed. Permitted commands: {:?}",
                    ALLOWED_COMMANDS
                )
                .into(),
                data: None,
            });
        }

        let mut cmd = Command::new("phantom");
        cmd.arg("run");
        if let Some(profile) = params.profile {
            cmd.args(["--profile", &profile]);
        }
        if params.network.unwrap_or(false) {
            cmd.arg("--network");
        }
        cmd.arg(&params.image);
        cmd.args(sanitized_command.split_whitespace());

        match cmd.output() {
            Ok(result) => {
                let stdout = String::from_utf8_lossy(&result.stdout);
                let response = if result.status.success() {
                    format!("✓ Success:\n{}", stdout)
                } else {
                    format!("✗ Failed: {}", stdout)
                };
                Ok(CallToolResult::success(vec![Content::text(response)]))
            }
            Err(e) => Err(rmcp::ErrorData {
                code: ErrorCode(-32603),
                message: e.to_string().into(),
                data: None,
            }),
        }
    }

    #[tool(description = "Create a persistent fragment environment.")]
    async fn create_fragment(
        &self,
        Parameters(params): Parameters<CreateFragmentParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut cmd = Command::new("phantom");
        cmd.args([
            "create",
            "--name",
            &params.name,
            "--profile",
            &params.profile,
        ]);
        match cmd.output() {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                String::from_utf8_lossy(&result.stdout),
            )])),
            Err(e) => Err(rmcp::ErrorData {
                code: ErrorCode(-32603),
                message: e.to_string().into(),
                data: None,
            }),
        }
    }

    #[tool(description = "List all fragments and their current status.")]
    async fn list_fragments(
        &self,
        Parameters(params): Parameters<ListFragmentsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut cmd = Command::new("phantom");
        cmd.arg("list");
        if params.all {
            cmd.arg("--all");
        }
        match cmd.output() {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                String::from_utf8_lossy(&result.stdout),
            )])),
            Err(e) => Err(rmcp::ErrorData {
                code: ErrorCode(-32603),
                message: e.to_string().into(),
                data: None,
            }),
        }
    }

    #[tool(description = "Destroy a fragment and clean up its resources.")]
    async fn destroy_fragment(
        &self,
        Parameters(params): Parameters<DestroyFragmentParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut cmd = Command::new("phantom");
        cmd.args(["destroy", &params.name]);
        if params.force {
            cmd.arg("--force");
        }
        match cmd.output() {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                String::from_utf8_lossy(&result.stdout),
            )])),
            Err(e) => Err(rmcp::ErrorData {
                code: ErrorCode(-32603),
                message: e.to_string().into(),
                data: None,
            }),
        }
    }
}

pub async fn run_server() -> Result<()> {
    tracing::info!("Starting Phantom MCP Server...");
    let service = PhantomService::new().await?;
    let server = service.clone().serve(stdio()).await?;
    tracing::info!("Phantom MCP Server running.");
    server.waiting().await?;
    Ok(())
}

