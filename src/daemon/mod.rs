//! Daemon core logic.
//!
//! The daemon is the main runtime that:
//! - Manages a persistent Ghidra bridge process
//! - Serves commands via local socket IPC
//! - Handles graceful shutdown

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::{broadcast, Mutex};
use tracing::{error, info, warn};

use crate::daemon::analysis_queue::AnalysisQueue;
use crate::daemon::process::{get_data_dir, remove_lock_file, write_daemon_info, DaemonInfo};
use crate::ghidra::bridge::GhidraBridge;

pub mod analysis_queue;
pub mod cache;
pub mod handler;
pub mod handlers;
pub mod ipc_server;
pub mod process;
pub mod queue;
pub mod state;

/// Daemon configuration.
pub struct DaemonConfig {
    /// Path to the project directory
    pub project_path: PathBuf,
    /// Ghidra installation directory
    pub ghidra_install_dir: Option<PathBuf>,
    /// Log file path
    pub log_file: PathBuf,
    /// Program name to load
    pub program_name: Option<String>,
}

/// Run the daemon with the new bridge architecture.
pub async fn run(config: DaemonConfig) -> Result<()> {
    info!("Starting Ghidra daemon");
    info!("Project: {}", config.project_path.display());

    // Get data directory
    let data_dir = get_data_dir().context("Failed to get data directory")?;

    // Create shutdown channel
    let (shutdown_tx, _shutdown_rx) = broadcast::channel::<()>(1);

    // Initialize the Ghidra bridge (starts as None until we have a program)
    let bridge: Arc<Mutex<Option<GhidraBridge>>> = Arc::new(Mutex::new(None));

    // If we have Ghidra install dir and program name, start the bridge
    if let (Some(ghidra_dir), Some(program_name)) =
        (&config.ghidra_install_dir, &config.program_name)
    {
        info!("Starting Ghidra bridge for program: {}", program_name);

        let project_name = config
            .project_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("project")
            .to_string();

        let mut new_bridge = GhidraBridge::new(
            ghidra_dir.clone(),
            config.project_path.clone(),
            project_name,
            program_name.clone(),
        );

        if let Err(e) = new_bridge.start() {
            warn!(
                "Failed to start Ghidra bridge: {}. Will operate without persistent connection.",
                e
            );
        } else {
            info!("Ghidra bridge started successfully");
            let mut bridge_guard = bridge.lock().await;
            *bridge_guard = Some(new_bridge);
        }
    } else {
        info!("No program specified, bridge will be started on first command");
    }

    // Write lock file
    let daemon_info = DaemonInfo::new(&config.project_path, &config.log_file);
    write_daemon_info(&data_dir, &config.project_path, &daemon_info)
        .context("Failed to write lock file")?;

    // Create and start the analysis queue
    let analysis_queue = AnalysisQueue::new(bridge.clone());
    analysis_queue.start_processor().await;

    // Start IPC server task
    let ipc_bridge = bridge.clone();
    let ipc_shutdown_tx = shutdown_tx.clone();
    let ipc_project_path = config.project_path.clone();
    let ipc_analysis_queue = analysis_queue.clone();
    let ipc_handle = tokio::spawn(async move {
        if let Err(e) = ipc_server::run_ipc_server(
            ipc_bridge,
            ipc_shutdown_tx,
            &ipc_project_path,
            ipc_analysis_queue,
        )
        .await
        {
            error!("IPC server error: {}", e);
        }
    });

    // Wait for shutdown signal
    let shutdown_reason = wait_for_shutdown(shutdown_tx.clone()).await;

    info!("Shutdown initiated: {:?}", shutdown_reason);

    // Clean up
    shutdown_tx.send(()).ok(); // Signal all tasks to stop

    // Stop the bridge
    {
        let mut bridge_guard = bridge.lock().await;
        if let Some(mut b) = bridge_guard.take() {
            info!("Stopping Ghidra bridge...");
            if let Err(e) = b.stop() {
                error!("Error stopping bridge: {}", e);
            }
        }
    }

    // Wait for IPC server to stop (with timeout)
    tokio::select! {
        _ = ipc_handle => {
            info!("IPC server stopped");
        }
        _ = tokio::time::sleep(tokio::time::Duration::from_secs(5)) => {
            warn!("IPC server did not stop in time");
        }
    }

    // Remove lock file
    remove_lock_file(&data_dir, &config.project_path).context("Failed to remove lock file")?;

    info!("Daemon stopped");
    Ok(())
}

/// The reason for shutdown.
#[derive(Debug, Clone)]
pub enum ShutdownReason {
    /// SIGINT (Ctrl+C)
    Interrupt,
    /// SIGTERM
    Terminate,
    /// RPC shutdown request
    RpcRequest,
}

/// Wait for a shutdown signal.
async fn wait_for_shutdown(shutdown_tx: broadcast::Sender<()>) -> ShutdownReason {
    let mut shutdown_rx = shutdown_tx.subscribe();

    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigint =
            signal(SignalKind::interrupt()).expect("Failed to register SIGINT handler");
        let mut sigterm =
            signal(SignalKind::terminate()).expect("Failed to register SIGTERM handler");

        tokio::select! {
            _ = sigint.recv() => {
                info!("Received SIGINT");
                ShutdownReason::Interrupt
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM");
                ShutdownReason::Terminate
            }
            _ = shutdown_rx.recv() => {
                info!("Received shutdown request via RPC");
                ShutdownReason::RpcRequest
            }
        }
    }

    #[cfg(windows)]
    {
        use tokio::signal;

        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Received Ctrl+C");
                ShutdownReason::Interrupt
            }
            _ = shutdown_rx.recv() => {
                info!("Received shutdown request via RPC");
                ShutdownReason::RpcRequest
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_config() {
        let config = DaemonConfig {
            project_path: PathBuf::from("/test/project"),
            ghidra_install_dir: None,
            log_file: PathBuf::from("/test/logs/daemon.log"),
            program_name: None,
        };

        assert_eq!(config.project_path, PathBuf::from("/test/project"));
    }
}
