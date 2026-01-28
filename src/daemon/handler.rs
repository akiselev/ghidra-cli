//! Command handler for processing IPC requests.
//!
//! Translates IPC commands into Ghidra bridge operations.

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::json;
use tokio::sync::Mutex;
use tracing::debug;

use crate::daemon::analysis_queue::AnalysisQueue;
use crate::ghidra::bridge::GhidraBridge;
use crate::ipc::protocol::{Command, Response};

/// Handle an IPC command.
pub async fn handle_command(
    bridge: &Arc<Mutex<Option<GhidraBridge>>>,
    analysis_queue: &AnalysisQueue,
    id: u64,
    command: Command,
) -> Response {
    match handle_command_inner(bridge, analysis_queue, command).await {
        Ok(result) => Response::success(id, result),
        Err(e) => Response::error(id, e.to_string()),
    }
}

async fn handle_command_inner(
    bridge: &Arc<Mutex<Option<GhidraBridge>>>,
    analysis_queue: &AnalysisQueue,
    command: Command,
) -> anyhow::Result<serde_json::Value> {
    match command {
        Command::Ping => Ok(json!({"status": "ok"})),

        Command::Status => {
            let bridge_guard = bridge.lock().await;
            let bridge_running = bridge_guard
                .as_ref()
                .map(|b| b.is_running())
                .unwrap_or(false);
            Ok(json!({
                "bridge_running": bridge_running,
            }))
        }

        Command::ClearCache => {
            // TODO: Implement cache clearing
            Ok(json!({"cleared": true}))
        }

        Command::Shutdown => {
            // Shutdown is handled at a higher level
            Ok(json!({"status": "shutting_down"}))
        }

        Command::ListFunctions { limit, filter } => {
            execute_bridge_command(
                bridge,
                "list_functions",
                Some(json!({
                    "limit": limit,
                    "filter": filter,
                })),
            )
            .await
        }

        Command::Decompile { address } => {
            execute_bridge_command(
                bridge,
                "decompile",
                Some(json!({
                    "address": address,
                })),
            )
            .await
        }

        Command::ListStrings { limit } => {
            execute_bridge_command(
                bridge,
                "list_strings",
                Some(json!({
                    "limit": limit,
                })),
            )
            .await
        }

        Command::ListImports => execute_bridge_command(bridge, "list_imports", None).await,

        Command::ListExports => execute_bridge_command(bridge, "list_exports", None).await,

        Command::MemoryMap => execute_bridge_command(bridge, "memory_map", None).await,

        Command::ProgramInfo => execute_bridge_command(bridge, "program_info", None).await,

        Command::XRefsTo { address } => {
            execute_bridge_command(
                bridge,
                "xrefs_to",
                Some(json!({
                    "address": address,
                })),
            )
            .await
        }

        Command::XRefsFrom { address } => {
            execute_bridge_command(
                bridge,
                "xrefs_from",
                Some(json!({
                    "address": address,
                })),
            )
            .await
        }

        Command::Import {
            binary_path,
            project,
            program,
        } => {
            execute_bridge_command(
                bridge,
                "import",
                Some(json!({
                    "binary_path": binary_path,
                    "project": project,
                    "program": program,
                })),
            )
            .await
        }

        Command::Analyze { project, program } => {
            execute_bridge_command(
                bridge,
                "analyze",
                Some(json!({
                    "project": project,
                    "program": program,
                })),
            )
            .await
        }

        Command::QueueAdd { paths, project } => {
            let paths: Vec<PathBuf> = paths.into_iter().map(PathBuf::from).collect();
            let project = project.unwrap_or_else(|| "queue-project".to_string());
            let added = analysis_queue.add(paths, project).await;
            Ok(json!({
                "added": added,
            }))
        }

        Command::QueueList => {
            let entries = analysis_queue.list().await;
            Ok(json!({
                "entries": entries,
            }))
        }

        Command::QueueRemove { paths } => {
            let paths: Vec<PathBuf> = paths.into_iter().map(PathBuf::from).collect();
            let removed = analysis_queue.remove(&paths).await;
            Ok(json!({
                "removed": removed,
            }))
        }

        Command::QueueStatus => {
            let status = analysis_queue.status().await;
            Ok(serde_json::to_value(status)?)
        }

        Command::ExecuteCli { command_json } => {
            // Deserialize and execute CLI command through the queue handlers
            let cli_command: crate::cli::Commands = serde_json::from_str(&command_json)
                .map_err(|e| anyhow::anyhow!("Failed to deserialize CLI command: {}", e))?;

            // Execute using the queue's command execution logic
            let result = crate::daemon::queue::execute_command_direct(bridge, &cli_command).await?;

            // Parse the result as JSON (handlers return JSON strings)
            Ok(serde_json::from_str(&result).unwrap_or_else(|_| json!({"output": result})))
        }
    }
}

/// Execute a command on the Ghidra bridge.
async fn execute_bridge_command(
    bridge: &Arc<Mutex<Option<GhidraBridge>>>,
    command: &str,
    args: Option<serde_json::Value>,
) -> anyhow::Result<serde_json::Value> {
    let mut bridge_guard = bridge.lock().await;

    let bridge = bridge_guard
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("Bridge not initialized"))?;

    if !bridge.is_running() {
        anyhow::bail!("Bridge is not running");
    }

    debug!("Executing bridge command: {}", command);

    let response = bridge.send_command::<serde_json::Value>(command, args)?;

    if response.status == "success" {
        Ok(response.data.unwrap_or(json!({})))
    } else {
        let message = response
            .message
            .unwrap_or_else(|| "Unknown error".to_string());
        anyhow::bail!("{}", message)
    }
}
