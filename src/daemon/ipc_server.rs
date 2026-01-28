//! IPC server for daemon communication.
//!
//! Uses local sockets (Unix domain sockets / Windows named pipes) with
//! the new IPC layer instead of TCP.
//!
//! Each project gets its own socket for concurrent daemon operation.

#![allow(dead_code)]

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use interprocess::local_socket::traits::tokio::Listener as ListenerTrait;
use tokio::io::BufReader;
use tokio::sync::{broadcast, Mutex};
use tracing::{debug, error, info};

use crate::daemon::analysis_queue::AnalysisQueue;
use crate::ghidra::bridge::GhidraBridge;
use crate::ipc::protocol::{Command, Request, Response};
use crate::ipc::transport;

use super::handler;

/// IPC server state
pub struct IpcServer {
    /// The Ghidra bridge instance
    bridge: Arc<Mutex<Option<GhidraBridge>>>,
    /// Analysis queue
    analysis_queue: AnalysisQueue,
    /// Shutdown signal sender
    shutdown_tx: broadcast::Sender<()>,
    /// Server start time
    started_at: Instant,
}

impl IpcServer {
    /// Create a new IPC server.
    pub fn new(
        bridge: Arc<Mutex<Option<GhidraBridge>>>,
        shutdown_tx: broadcast::Sender<()>,
        analysis_queue: AnalysisQueue,
    ) -> Self {
        Self {
            bridge,
            analysis_queue,
            shutdown_tx,
            started_at: Instant::now(),
        }
    }

    /// Handle a single client connection.
    async fn handle_client(&self, stream: transport::platform::Stream) -> anyhow::Result<bool> {
        let (reader, mut writer) = tokio::io::split(stream);
        let mut reader = BufReader::new(reader);

        loop {
            // Read request with timeout
            let request_data = tokio::select! {
                result = transport::recv_message(&mut reader) => {
                    match result {
                        Ok(data) => data,
                        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                            debug!("Client disconnected");
                            return Ok(false);
                        }
                        Err(e) => {
                            error!("Error reading request: {}", e);
                            return Ok(false);
                        }
                    }
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(300)) => {
                    debug!("Client timeout");
                    return Ok(false);
                }
            };

            // Parse request
            let request: Request = match serde_json::from_slice(&request_data) {
                Ok(req) => req,
                Err(e) => {
                    error!("Invalid request: {}", e);
                    let response = Response::error(0, format!("Invalid request: {}", e));
                    let json = serde_json::to_vec(&response)?;
                    transport::send_message(&mut writer, &json).await?;
                    continue;
                }
            };

            debug!("Received command: {:?}", request.command);

            // Check for shutdown command
            if matches!(request.command, Command::Shutdown) {
                let response = Response::ok(request.id);
                let json = serde_json::to_vec(&response)?;
                transport::send_message(&mut writer, &json).await?;
                return Ok(true); // Signal shutdown
            }

            // Handle command
            let response =
                handler::handle_command(&self.bridge, &self.analysis_queue, request.id, request.command).await;

            // Send response
            let json = serde_json::to_vec(&response)?;
            transport::send_message(&mut writer, &json).await?;
        }
    }
}

/// Run the IPC server for a specific project.
pub async fn run_ipc_server(
    bridge: Arc<Mutex<Option<GhidraBridge>>>,
    shutdown_tx: broadcast::Sender<()>,
    project_path: &Path,
    analysis_queue: AnalysisQueue,
) -> anyhow::Result<()> {
    // Create the IPC listener for this project
    let listener = transport::create_listener_for_project(project_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create IPC listener: {}", e))?;

    info!(
        "IPC server listening on {}",
        transport::socket_name_for_project(project_path)
    );

    let server = Arc::new(IpcServer::new(bridge, shutdown_tx.clone(), analysis_queue));
    let mut shutdown_rx = shutdown_tx.subscribe();

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok(stream) => {
                        info!("Accepted IPC connection");
                        let server = server.clone();
                        let shutdown_tx = shutdown_tx.clone();
                        tokio::spawn(async move {
                            match server.handle_client(stream).await {
                                Ok(should_shutdown) if should_shutdown => {
                                    info!("Shutdown requested via IPC");
                                    let _ = shutdown_tx.send(());
                                }
                                Ok(_) => {}
                                Err(e) => {
                                    error!("Connection error: {}", e);
                                }
                            }
                        });
                    }
                    Err(e) => {
                        error!("Accept error: {}", e);
                    }
                }
            }
            _ = shutdown_rx.recv() => {
                info!("IPC server shutting down");
                break;
            }
        }
    }

    // Clean up socket for this project
    transport::remove_socket_for_project(project_path).ok();

    Ok(())
}
