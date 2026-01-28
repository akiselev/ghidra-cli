//! IPC protocol message types.
//!
//! Defines the request/response format for CLI ↔ daemon communication.
//! Uses a typed command enum (not wrapping CLI Commands) for clean separation.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// IPC request from CLI to daemon.
#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    /// Request ID for matching responses
    pub id: u64,
    /// The command to execute
    pub command: Command,
}

impl Request {
    /// Create a new request with the given ID and command.
    pub fn new(id: u64, command: Command) -> Self {
        Self { id, command }
    }
}

/// IPC response from daemon to CLI.
#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    /// Request ID this response corresponds to
    pub id: u64,
    /// Whether the command succeeded
    pub success: bool,
    /// Result data on success
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Error message on failure
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Response {
    /// Create a success response.
    pub fn success(id: u64, result: serde_json::Value) -> Self {
        Self {
            id,
            success: true,
            result: Some(result),
            error: None,
        }
    }

    /// Create an error response.
    pub fn error(id: u64, message: impl Into<String>) -> Self {
        Self {
            id,
            success: false,
            result: None,
            error: Some(message.into()),
        }
    }

    /// Create a success response with no data.
    pub fn ok(id: u64) -> Self {
        Self {
            id,
            success: true,
            result: Some(serde_json::json!({})),
            error: None,
        }
    }
}

/// Commands that can be sent from CLI to daemon.
///
/// These are separate from CLI Commands to decouple IPC from argument parsing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Command {
    // === Data Queries ===
    /// List functions in the program
    ListFunctions {
        #[serde(skip_serializing_if = "Option::is_none")]
        limit: Option<usize>,
        #[serde(skip_serializing_if = "Option::is_none")]
        filter: Option<String>,
    },

    /// Decompile a function at address
    Decompile { address: String },

    /// List strings in the program
    ListStrings {
        #[serde(skip_serializing_if = "Option::is_none")]
        limit: Option<usize>,
    },

    /// List imports
    ListImports,

    /// List exports
    ListExports,

    /// Get memory map
    MemoryMap,

    /// Get program info
    ProgramInfo,

    /// Get cross-references to an address
    XRefsTo { address: String },

    /// Get cross-references from an address
    XRefsFrom { address: String },

    // === Project Management ===
    /// Import a binary into a project
    Import {
        binary_path: String,
        project: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        program: Option<String>,
    },

    /// Analyze a program in a project
    Analyze { project: String, program: String },

    // === Session Management ===
    /// Health check
    Ping,

    /// Get daemon status
    Status,

    /// Clear result cache
    ClearCache,

    /// Shutdown the daemon
    Shutdown,

    // === Analysis Queue ===
    /// Add file paths to the analysis queue
    QueueAdd {
        /// Absolute file paths to add (already glob-expanded by the client)
        paths: Vec<String>,
        /// Project name for imported binaries
        #[serde(skip_serializing_if = "Option::is_none")]
        project: Option<String>,
    },

    /// List all items in the analysis queue
    QueueList,

    /// Remove file paths from the analysis queue
    QueueRemove {
        /// Absolute file paths to remove (already glob-expanded by the client)
        paths: Vec<String>,
    },

    /// Wait until all queued analyses are complete (returns current status)
    QueueStatus,

    // === Generic CLI Command Forwarding ===
    /// Execute a CLI command through the daemon's queue
    ExecuteCli {
        /// The serialized CLI command
        command_json: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_serialization() {
        let request = Request::new(1, Command::Ping);
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: Request = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, 1);
        assert!(matches!(deserialized.command, Command::Ping));
    }

    #[test]
    fn test_response_success() {
        let response = Response::success(1, serde_json::json!({"count": 42}));
        assert!(response.success);
        assert_eq!(response.id, 1);
        assert!(response.result.is_some());
    }

    #[test]
    fn test_response_error() {
        let response = Response::error(1, "Something went wrong");
        assert!(!response.success);
        assert_eq!(response.error.as_ref().unwrap(), "Something went wrong");
    }

    #[test]
    fn test_command_serialization() {
        let cmd = Command::ListFunctions {
            limit: Some(100),
            filter: Some("main".to_string()),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("list_functions"));
        assert!(json.contains("100"));
        assert!(json.contains("main"));
    }
}
