use anyhow::Result;
use rmcp::{
    model::*, tool, tool_handler, tool_router, transport::stdio, ServerHandler, ServiceExt,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::sync::Arc;
use tokio::sync::Mutex;

// Import internal crates
use metrics_rs::MetricsCollector;
use network_rs::NetworkManager;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;

#[derive(Clone)]
pub struct PhantomService {
    metrics: Arc<MetricsCollector>,
    network: Arc<Mutex<NetworkManager>>,
    #[allow(dead_code)]
    tool_router: ToolRouter<PhantomService>,
}

impl PhantomService {
    pub async fn new() -> Result<Self> {
        let metrics = Arc::new(MetricsCollector::new());
        let network = Arc::new(Mutex::new(NetworkManager::new().await?));

        Ok(Self {
            metrics,
            network,
            tool_router: Self::tool_router(),
        })
    }
}

// Tool parameter types
#[derive(Serialize, Deserialize, JsonSchema)]
struct ListInterfacesParams {}

#[derive(Serialize, Deserialize, JsonSchema)]
struct GetMetricsParams {}

#[derive(Serialize, Deserialize, JsonSchema)]
struct RunInFragmentParams {
    /// The image to use (e.g., "alpine", "ubuntu:22.04", "python:3.11")
    image: String,
    /// The command to execute inside the fragment
    command: String,
    /// Security profile (direct, sandbox, hardened, wasm). Default: sandbox.
    profile: Option<String>,
    /// Enable network access. Default: false.
    network: Option<bool>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
struct CreateFragmentParams {
    /// Unique name for the fragment
    name: String,
    /// Security profile (direct, sandbox, hardened, wasm). Default: sandbox.
    #[serde(default = "default_sandbox")]
    profile: String,
    /// Persist fragment to storage. Default: true.
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
    /// Name of the fragment to destroy
    name: String,
    /// Force destruction even if running
    #[serde(default)]
    force: bool,
}

#[derive(Serialize, Deserialize, JsonSchema)]
struct ListFragmentsParams {
    /// Show all fragments (including stopped)
    #[serde(default)]
    all: bool,
}

#[derive(Serialize, Deserialize, JsonSchema)]
struct SearchImagesParams {
    /// Search term for Docker Hub (e.g., "python", "node", "rust")
    query: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
struct ListImagesParams {}

#[derive(Serialize, Deserialize, JsonSchema)]
struct ExecuteCodeParams {
    /// Programming language: "python", "node", "bash", "ruby", "rust"
    language: String,
    /// The code to execute
    code: String,
    /// Security profile. Default: sandbox.
    profile: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
struct BuildImageParams {
    /// Path to the Fragmentfile
    file: String,
    /// Name/tag for the resulting image
    tag: String,
    /// Enable verbose build logs
    #[serde(default)]
    verbose: bool,
}

#[derive(Serialize, Deserialize, JsonSchema)]
struct CleanImagesParams {
    /// Image name to remove (leave empty to remove all)
    image: Option<String>,
    /// Force removal without confirmation
    #[serde(default)]
    force: bool,
}

#[tool_handler]
impl ServerHandler for PhantomService {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
    }
}

#[tool_router]
impl PhantomService {
    #[tool(
        description = "Execute a command inside an isolated Phantom Fragment container. Use this for ephemeral tasks."
    )]
    async fn run_in_fragment(
        &self,
        Parameters(params): Parameters<RunInFragmentParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut cmd = Command::new("phantom");
        cmd.arg("run");

        if let Some(profile) = params.profile {
            cmd.args(["--profile", &profile]);
        }

        if params.network.unwrap_or(false) {
            cmd.arg("--network");
        }

        cmd.arg(&params.image);
        cmd.args(params.command.split_whitespace());

        match cmd.output() {
            Ok(result) => {
                let stdout = String::from_utf8_lossy(&result.stdout);
                let stderr = String::from_utf8_lossy(&result.stderr);

                let response = if result.status.success() {
                    format!("✓ Success:\n{}", stdout)
                } else {
                    format!(
                        "✗ Failed (code {:?}):\nstdout: {}\nstderr: {}",
                        result.status.code(),
                        stdout,
                        stderr
                    )
                };

                Ok(CallToolResult::success(vec![Content::text(response)]))
            }
            Err(e) => Err(rmcp::ErrorData {
                code: ErrorCode(-32603),
                message: format!("Execution failed: {}", e).into(),
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
        if !params.persist {
            cmd.arg("--no-persist"); // Assuming this exists or works mapping to persist: bool
        }

        match cmd.output() {
            Ok(result) => {
                let stdout = String::from_utf8_lossy(&result.stdout);
                Ok(CallToolResult::success(vec![Content::text(
                    stdout.to_string(),
                )]))
            }
            Err(e) => Err(rmcp::ErrorData {
                code: ErrorCode(-32603),
                message: format!("Creation failed: {}", e).into(),
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
                String::from_utf8_lossy(&result.stdout).to_string(),
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
                String::from_utf8_lossy(&result.stdout).to_string(),
            )])),
            Err(e) => Err(rmcp::ErrorData {
                code: ErrorCode(-32603),
                message: e.to_string().into(),
                data: None,
            }),
        }
    }

    #[tool(
        description = "Execute code snippets in an isolated environment. Supports python, node, bash, ruby, rust."
    )]
    async fn execute_code(
        &self,
        Parameters(params): Parameters<ExecuteCodeParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let (image, cmd_prefix) = match params.language.to_lowercase().as_str() {
            "python" | "py" => ("python:3.11-alpine", vec!["python3", "-c"]),
            "node" | "javascript" | "js" => ("node:20-alpine", vec!["node", "-e"]),
            "bash" | "sh" => ("alpine", vec!["sh", "-c"]),
            "ruby" | "rb" => ("ruby:3-alpine", vec!["ruby", "-e"]),
            "rust" | "rs" => (
                "rust:alpine",
                vec!["rustc", "-o", "/tmp/out", "-", "&&", "/tmp/out"],
            ),
            _ => {
                return Err(rmcp::ErrorData {
                    code: ErrorCode(-32602),
                    message: format!("Unsupported: {}", params.language).into(),
                    data: None,
                })
            }
        };

        let mut cmd = Command::new("phantom");
        cmd.arg("run");
        if let Some(profile) = params.profile {
            cmd.args(["--profile", &profile]);
        }
        cmd.arg(image);
        cmd.args(cmd_prefix);
        cmd.arg(&params.code);

        match cmd.output() {
            Ok(result) => {
                let out = String::from_utf8_lossy(&result.stdout);
                let err = String::from_utf8_lossy(&result.stderr);
                Ok(CallToolResult::success(vec![Content::text(format!(
                    "{}\n{}",
                    out, err
                ))]))
            }
            Err(e) => Err(rmcp::ErrorData {
                code: ErrorCode(-32603),
                message: e.to_string().into(),
                data: None,
            }),
        }
    }

    #[tool(description = "Build a new image from a Fragmentfile.")]
    async fn build_image(
        &self,
        Parameters(params): Parameters<BuildImageParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut cmd = Command::new("phantom");
        cmd.args(["build", "--file", &params.file, "--tag", &params.tag]);
        if params.verbose {
            cmd.arg("--verbose");
        }

        match cmd.output() {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                String::from_utf8_lossy(&result.stdout).to_string(),
            )])),
            Err(e) => Err(rmcp::ErrorData {
                code: ErrorCode(-32603),
                message: e.to_string().into(),
                data: None,
            }),
        }
    }

    #[tool(description = "Search Docker Hub for images.")]
    async fn search_images(
        &self,
        Parameters(params): Parameters<SearchImagesParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let output = Command::new("phantom")
            .args(["search", &params.query])
            .output();
        match output {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                String::from_utf8_lossy(&result.stdout).to_string(),
            )])),
            Err(e) => Err(rmcp::ErrorData {
                code: ErrorCode(-32603),
                message: e.to_string().into(),
                data: None,
            }),
        }
    }

    #[tool(description = "List locally cached images.")]
    async fn list_images(
        &self,
        Parameters(_params): Parameters<ListImagesParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let output = Command::new("phantom").args(["images"]).output();
        match output {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                String::from_utf8_lossy(&result.stdout).to_string(),
            )])),
            Err(e) => Err(rmcp::ErrorData {
                code: ErrorCode(-32603),
                message: e.to_string().into(),
                data: None,
            }),
        }
    }

    #[tool(description = "Remove images from local cache.")]
    async fn clean_images(
        &self,
        Parameters(params): Parameters<CleanImagesParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let mut cmd = Command::new("phantom");
        cmd.arg("clean");
        if let Some(img) = params.image {
            cmd.args(["--image", &img]);
        }
        if params.force {
            cmd.arg("--force");
        }

        match cmd.output() {
            Ok(result) => Ok(CallToolResult::success(vec![Content::text(
                String::from_utf8_lossy(&result.stdout).to_string(),
            )])),
            Err(e) => Err(rmcp::ErrorData {
                code: ErrorCode(-32603),
                message: e.to_string().into(),
                data: None,
            }),
        }
    }

    #[tool(description = "List all network interfaces on the host.")]
    async fn list_interfaces(
        &self,
        Parameters(_params): Parameters<ListInterfacesParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let network = self.network.lock().await;
        match network.list_interfaces().await {
            Ok(interfaces) => Ok(CallToolResult::success(vec![Content::text(
                interfaces.join("\n"),
            )])),
            Err(e) => Err(rmcp::ErrorData {
                code: ErrorCode(-32603),
                message: e.to_string().into(),
                data: None,
            }),
        }
    }

    #[tool(description = "Get system metrics in Prometheus format.")]
    async fn get_metrics(
        &self,
        Parameters(_params): Parameters<GetMetricsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        match self.metrics.export() {
            Ok(metrics) => Ok(CallToolResult::success(vec![Content::text(metrics)])),
            Err(e) => Err(rmcp::ErrorData {
                code: ErrorCode(-32603),
                message: format!("{:?}", e).into(),
                data: None,
            }),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    tracing::info!("Starting Phantom MCP Server...");
    let service = PhantomService::new().await?;
    let server = service.clone().serve(stdio()).await?;
    tracing::info!("Phantom MCP Server running with full CLI parity tools.");
    server.waiting().await?;
    Ok(())
}
