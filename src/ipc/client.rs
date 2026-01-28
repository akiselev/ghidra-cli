//! CLI-side IPC client for communicating with the daemon.

#![allow(dead_code)]

use std::path::Path;

use anyhow::{Context, Result};
use tokio::io::{ReadHalf, WriteHalf};

use super::protocol::{Command, Request, Response};
use super::transport::{self, Stream};

/// Client for communicating with the Ghidra daemon.
pub struct DaemonClient {
    reader: ReadHalf<Stream>,
    writer: WriteHalf<Stream>,
    next_id: u64,
}

impl DaemonClient {
    /// Connect to the running daemon for a specific project.
    pub async fn connect(project_path: &Path) -> Result<Self> {
        let stream = transport::connect_for_project(project_path)
            .await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound
                    || e.kind() == std::io::ErrorKind::ConnectionRefused
                {
                    anyhow::anyhow!("Daemon not running for project: {}", project_path.display())
                } else {
                    anyhow::anyhow!("Failed to connect to daemon: {}", e)
                }
            })?;

        let (reader, writer) = tokio::io::split(stream);

        Ok(Self {
            reader,
            writer,
            next_id: 1,
        })
    }

    /// Send a command and wait for the response.
    pub async fn send_command(&mut self, command: Command) -> Result<serde_json::Value> {
        let id = self.next_id;
        self.next_id += 1;

        let request = Request::new(id, command);
        let json = serde_json::to_vec(&request).context("Failed to serialize request")?;

        transport::send_message(&mut self.writer, &json)
            .await
            .context("Failed to send message to daemon")?;

        let response_data = transport::recv_message(&mut self.reader)
            .await
            .context("Failed to receive message from daemon")?;

        let response: Response =
            serde_json::from_slice(&response_data).context("Failed to parse daemon response")?;

        if response.id != id {
            anyhow::bail!("Response ID mismatch: expected {}, got {}", id, response.id);
        }

        if response.success {
            Ok(response.result.unwrap_or(serde_json::json!({})))
        } else {
            let error = response
                .error
                .unwrap_or_else(|| "Unknown error".to_string());
            anyhow::bail!("{}", error)
        }
    }

    /// Check if daemon is responding.
    pub async fn ping(&mut self) -> Result<bool> {
        match self.send_command(Command::Ping).await {
            Ok(_) => Ok(true),
            Err(e) if e.to_string().contains("not running") => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Get daemon status.
    pub async fn status(&mut self) -> Result<serde_json::Value> {
        self.send_command(Command::Status).await
    }

    /// Shutdown the daemon.
    pub async fn shutdown(&mut self) -> Result<()> {
        self.send_command(Command::Shutdown).await?;
        Ok(())
    }

    /// Clear the result cache.
    pub async fn clear_cache(&mut self) -> Result<()> {
        self.send_command(Command::ClearCache).await?;
        Ok(())
    }

    /// List functions.
    pub async fn list_functions(
        &mut self,
        limit: Option<usize>,
        filter: Option<String>,
    ) -> Result<serde_json::Value> {
        self.send_command(Command::ListFunctions { limit, filter })
            .await
    }

    /// Decompile a function.
    pub async fn decompile(&mut self, address: String) -> Result<serde_json::Value> {
        self.send_command(Command::Decompile { address }).await
    }

    /// List strings.
    pub async fn list_strings(&mut self, limit: Option<usize>) -> Result<serde_json::Value> {
        self.send_command(Command::ListStrings { limit }).await
    }

    /// List imports.
    pub async fn list_imports(&mut self) -> Result<serde_json::Value> {
        self.send_command(Command::ListImports).await
    }

    /// List exports.
    pub async fn list_exports(&mut self) -> Result<serde_json::Value> {
        self.send_command(Command::ListExports).await
    }

    /// Get memory map.
    pub async fn memory_map(&mut self) -> Result<serde_json::Value> {
        self.send_command(Command::MemoryMap).await
    }

    /// Get program info.
    pub async fn program_info(&mut self) -> Result<serde_json::Value> {
        self.send_command(Command::ProgramInfo).await
    }

    /// Get cross-references to an address.
    pub async fn xrefs_to(&mut self, address: String) -> Result<serde_json::Value> {
        self.send_command(Command::XRefsTo { address }).await
    }

    /// Get cross-references from an address.
    pub async fn xrefs_from(&mut self, address: String) -> Result<serde_json::Value> {
        self.send_command(Command::XRefsFrom { address }).await
    }

    /// Add file paths to the analysis queue.
    pub async fn queue_add(
        &mut self,
        paths: Vec<String>,
        project: Option<String>,
    ) -> Result<serde_json::Value> {
        self.send_command(Command::QueueAdd { paths, project })
            .await
    }

    /// List all items in the analysis queue.
    pub async fn queue_list(&mut self) -> Result<serde_json::Value> {
        self.send_command(Command::QueueList).await
    }

    /// Remove file paths from the analysis queue.
    pub async fn queue_remove(&mut self, paths: Vec<String>) -> Result<serde_json::Value> {
        self.send_command(Command::QueueRemove { paths }).await
    }

    /// Get analysis queue status (for polling in wait).
    pub async fn queue_status(&mut self) -> Result<serde_json::Value> {
        self.send_command(Command::QueueStatus).await
    }

    /// Execute a CLI command through the daemon (takes pre-serialized JSON).
    pub async fn execute_cli_json(&mut self, command_json: String) -> Result<serde_json::Value> {
        self.send_command(Command::ExecuteCli { command_json })
            .await
    }

    /// Import a binary into a project.
    pub async fn import_binary(
        &mut self,
        binary_path: &str,
        project: &str,
        program: Option<&str>,
    ) -> Result<serde_json::Value> {
        self.send_command(Command::Import {
            binary_path: binary_path.to_string(),
            project: project.to_string(),
            program: program.map(|s| s.to_string()),
        })
        .await
    }

    /// Analyze a program in a project.
    pub async fn analyze_program(
        &mut self,
        project: &str,
        program: &str,
    ) -> Result<serde_json::Value> {
        self.send_command(Command::Analyze {
            project: project.to_string(),
            program: program.to_string(),
        })
        .await
    }
}

/// Check if daemon is running for a specific project (without establishing a full connection).
pub fn daemon_available(project_path: &Path) -> bool {
    transport::socket_exists_for_project(project_path)
}
