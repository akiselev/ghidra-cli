//! Analysis queue for batch binary processing.
//!
//! Manages a queue of binaries to import and analyze through the Ghidra bridge.
//! Processes items sequentially (one at a time) since the bridge is single-threaded.
//! Supports long-running waits so agents can block until all analysis is complete.

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Notify};
use tracing::{error, info, warn};

use crate::ghidra::bridge::GhidraBridge;

/// Status of a single queue entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum QueueEntryStatus {
    /// Waiting to be processed
    Pending,
    /// Currently being imported/analyzed
    Analyzing,
    /// Analysis completed successfully
    Completed,
    /// Analysis failed
    Failed { error: String },
}

/// A single entry in the analysis queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueEntry {
    /// Absolute path to the binary
    pub path: PathBuf,
    /// Status of this entry
    pub status: QueueEntryStatus,
    /// Project name to import into
    pub project: String,
    /// Program name (derived from filename)
    pub program: Option<String>,
    /// When this entry was added
    pub added_at: DateTime<Utc>,
    /// When processing started (if applicable)
    pub started_at: Option<DateTime<Utc>>,
    /// When processing finished (if applicable)
    pub finished_at: Option<DateTime<Utc>>,
}

/// Shared state for the analysis queue.
#[derive(Clone)]
pub struct AnalysisQueue {
    /// The queue entries
    entries: Arc<Mutex<Vec<QueueEntry>>>,
    /// Notifier for when new items are added
    work_notify: Arc<Notify>,
    /// Notifier for when items complete (for wait command)
    done_notify: Arc<Notify>,
    /// The Ghidra bridge instance
    bridge: Arc<Mutex<Option<GhidraBridge>>>,
    /// Whether the processor task is running
    processor_running: Arc<Mutex<bool>>,
}

impl AnalysisQueue {
    /// Create a new analysis queue.
    pub fn new(bridge: Arc<Mutex<Option<GhidraBridge>>>) -> Self {
        Self {
            entries: Arc::new(Mutex::new(Vec::new())),
            work_notify: Arc::new(Notify::new()),
            done_notify: Arc::new(Notify::new()),
            bridge,
            processor_running: Arc::new(Mutex::new(false)),
        }
    }

    /// Add binary paths to the queue.
    /// Returns the number of new entries added (skips duplicates).
    pub async fn add(&self, paths: Vec<PathBuf>, project: String) -> usize {
        let mut entries = self.entries.lock().await;
        let mut added = 0;

        for path in paths {
            // Skip if already in queue (by path)
            let already_exists = entries.iter().any(|e| e.path == path);
            if already_exists {
                warn!("Skipping duplicate: {}", path.display());
                continue;
            }

            let program = path
                .file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.to_string());

            entries.push(QueueEntry {
                path,
                status: QueueEntryStatus::Pending,
                project: project.clone(),
                program,
                added_at: Utc::now(),
                started_at: None,
                finished_at: None,
            });
            added += 1;
        }

        if added > 0 {
            self.work_notify.notify_one();
        }

        added
    }

    /// Remove entries matching the given paths.
    /// Only removes pending entries (not currently analyzing).
    /// Returns the number of entries removed.
    pub async fn remove(&self, paths: &[PathBuf]) -> usize {
        let mut entries = self.entries.lock().await;
        let before = entries.len();

        entries.retain(|e| {
            if e.status == QueueEntryStatus::Pending && paths.contains(&e.path) {
                false // Remove it
            } else {
                true // Keep it
            }
        });

        before - entries.len()
    }

    /// List all entries.
    pub async fn list(&self) -> Vec<QueueEntry> {
        let entries = self.entries.lock().await;
        entries.clone()
    }

    /// Get queue status summary.
    pub async fn status(&self) -> QueueStatusSummary {
        let entries = self.entries.lock().await;

        let mut pending = 0;
        let mut analyzing = 0;
        let mut completed = 0;
        let mut failed = 0;

        for entry in entries.iter() {
            match &entry.status {
                QueueEntryStatus::Pending => pending += 1,
                QueueEntryStatus::Analyzing => analyzing += 1,
                QueueEntryStatus::Completed => completed += 1,
                QueueEntryStatus::Failed { .. } => failed += 1,
            }
        }

        let total = entries.len();
        let all_done = pending == 0 && analyzing == 0;

        QueueStatusSummary {
            total,
            pending,
            analyzing,
            completed,
            failed,
            all_done,
        }
    }

    /// Start the background processor task.
    /// This should be called once when the daemon starts.
    pub async fn start_processor(&self) {
        let mut running = self.processor_running.lock().await;
        if *running {
            return;
        }
        *running = true;
        drop(running);

        let queue = self.clone();
        tokio::spawn(async move {
            queue.processor_loop().await;
        });

        info!("Analysis queue processor started");
    }

    /// Get the done notifier (for wait command polling).
    pub fn done_notify(&self) -> Arc<Notify> {
        self.done_notify.clone()
    }

    /// Internal processor loop.
    async fn processor_loop(&self) {
        loop {
            // Wait for work notification
            self.work_notify.notified().await;

            // Process all pending items
            loop {
                let next = self.take_next_pending().await;
                match next {
                    Some(idx) => {
                        self.process_entry(idx).await;
                        // Notify waiters after each completion
                        self.done_notify.notify_waiters();
                    }
                    None => break, // No more pending items
                }
            }
        }
    }

    /// Find and mark the next pending entry as Analyzing. Returns its index.
    async fn take_next_pending(&self) -> Option<usize> {
        let mut entries = self.entries.lock().await;
        for (i, entry) in entries.iter_mut().enumerate() {
            if entry.status == QueueEntryStatus::Pending {
                entry.status = QueueEntryStatus::Analyzing;
                entry.started_at = Some(Utc::now());
                return Some(i);
            }
        }
        None
    }

    /// Process a single queue entry (import + analyze).
    async fn process_entry(&self, idx: usize) {
        let (path, project, program) = {
            let entries = self.entries.lock().await;
            let entry = &entries[idx];
            (
                entry.path.clone(),
                entry.project.clone(),
                entry.program.clone().unwrap_or_else(|| "program".to_string()),
            )
        };

        info!(
            "Processing queue entry: {} (project={}, program={})",
            path.display(),
            project,
            program
        );

        let result = self.import_and_analyze(&path, &project, &program).await;

        let mut entries = self.entries.lock().await;
        if idx < entries.len() {
            entries[idx].finished_at = Some(Utc::now());
            match result {
                Ok(()) => {
                    entries[idx].status = QueueEntryStatus::Completed;
                    info!("Completed analysis of: {}", path.display());
                }
                Err(e) => {
                    let error_msg = format!("{:#}", e);
                    entries[idx].status = QueueEntryStatus::Failed {
                        error: error_msg.clone(),
                    };
                    error!("Failed to analyze {}: {}", path.display(), error_msg);
                }
            }
        }
    }

    /// Import and analyze a binary through the Ghidra bridge.
    async fn import_and_analyze(
        &self,
        binary_path: &PathBuf,
        project: &str,
        program: &str,
    ) -> Result<()> {
        use serde_json::json;

        let binary_path_str = binary_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid path: {}", binary_path.display()))?;

        // Import
        {
            let mut bridge_guard = self.bridge.lock().await;
            let bridge = bridge_guard
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("Bridge not initialized"))?;

            if !bridge.is_running() {
                anyhow::bail!("Bridge is not running");
            }

            info!("Importing: {}", binary_path_str);
            let response = bridge.send_command::<serde_json::Value>(
                "import",
                Some(json!({
                    "binary_path": binary_path_str,
                    "project": project,
                    "program": program,
                })),
            )?;

            if response.status != "success" {
                let msg = response
                    .message
                    .unwrap_or_else(|| "Import failed".to_string());
                anyhow::bail!("Import failed: {}", msg);
            }
        }

        // Analyze
        {
            let mut bridge_guard = self.bridge.lock().await;
            let bridge = bridge_guard
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("Bridge not initialized"))?;

            if !bridge.is_running() {
                anyhow::bail!("Bridge is not running");
            }

            info!("Analyzing: {}", program);
            let response = bridge.send_command::<serde_json::Value>(
                "analyze",
                Some(json!({
                    "project": project,
                    "program": program,
                })),
            )?;

            if response.status != "success" {
                let msg = response
                    .message
                    .unwrap_or_else(|| "Analysis failed".to_string());
                anyhow::bail!("Analysis failed: {}", msg);
            }
        }

        Ok(())
    }
}

/// Summary of queue status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueStatusSummary {
    pub total: usize,
    pub pending: usize,
    pub analyzing: usize,
    pub completed: usize,
    pub failed: usize,
    pub all_done: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_queue_add_and_list() {
        let bridge = Arc::new(Mutex::new(None));
        let queue = AnalysisQueue::new(bridge);

        let added = queue
            .add(
                vec![PathBuf::from("/tmp/binary1"), PathBuf::from("/tmp/binary2")],
                "test-project".to_string(),
            )
            .await;
        assert_eq!(added, 2);

        let entries = queue.list().await;
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, PathBuf::from("/tmp/binary1"));
        assert_eq!(entries[1].path, PathBuf::from("/tmp/binary2"));
        assert_eq!(entries[0].status, QueueEntryStatus::Pending);
    }

    #[tokio::test]
    async fn test_queue_skip_duplicates() {
        let bridge = Arc::new(Mutex::new(None));
        let queue = AnalysisQueue::new(bridge);

        queue
            .add(
                vec![PathBuf::from("/tmp/binary1")],
                "test-project".to_string(),
            )
            .await;

        let added = queue
            .add(
                vec![PathBuf::from("/tmp/binary1")],
                "test-project".to_string(),
            )
            .await;
        assert_eq!(added, 0);

        let entries = queue.list().await;
        assert_eq!(entries.len(), 1);
    }

    #[tokio::test]
    async fn test_queue_remove() {
        let bridge = Arc::new(Mutex::new(None));
        let queue = AnalysisQueue::new(bridge);

        queue
            .add(
                vec![PathBuf::from("/tmp/binary1"), PathBuf::from("/tmp/binary2")],
                "test-project".to_string(),
            )
            .await;

        let removed = queue.remove(&[PathBuf::from("/tmp/binary1")]).await;
        assert_eq!(removed, 1);

        let entries = queue.list().await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, PathBuf::from("/tmp/binary2"));
    }

    #[tokio::test]
    async fn test_queue_status() {
        let bridge = Arc::new(Mutex::new(None));
        let queue = AnalysisQueue::new(bridge);

        let status = queue.status().await;
        assert_eq!(status.total, 0);
        assert!(status.all_done);

        queue
            .add(
                vec![PathBuf::from("/tmp/binary1")],
                "test-project".to_string(),
            )
            .await;

        let status = queue.status().await;
        assert_eq!(status.total, 1);
        assert_eq!(status.pending, 1);
        assert!(!status.all_done);
    }
}
