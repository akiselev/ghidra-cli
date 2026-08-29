//! IPC protocol types for bridge communication.
//!
//! Defines the request/response format for CLI ↔ Java bridge communication.
//! Uses simple JSON: {"command":"...", "args":{...}} → {"status":"...", "data":{...}}

use serde::{Deserialize, Serialize};

/// Request to the Java bridge.
#[derive(Debug, Serialize)]
pub struct BridgeRequest {
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<serde_json::Value>,
}

/// Response from the Java bridge.
#[derive(Debug, Deserialize)]
pub struct BridgeResponse<T = serde_json::Value> {
    pub status: String,
    pub data: Option<T>,
    #[serde(default)]
    pub message: Option<String>,
    /// Structured detail attached to an error response (e.g. the containing
    /// function's name/entry/size on a "function already exists" error, or the
    /// conflicting data unit's type/range on a "type apply" conflict). Absent
    /// on success responses and on errors that carry only a message.
    #[serde(default)]
    pub detail: Option<serde_json::Value>,
}

/// An error surfaced by the bridge that carries structured detail alongside its
/// message (e.g. the containing function's name/entry/size for a "function
/// already exists" error). `Display` prints just the message, matching plain
/// bridge errors, so existing `anyhow`-based error handling is unaffected;
/// callers that want the structured detail can `downcast_ref` for it.
#[derive(Debug)]
pub struct BridgeCommandError {
    pub message: String,
    pub detail: serde_json::Value,
}

impl std::fmt::Display for BridgeCommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for BridgeCommandError {}

/// The client gave up waiting for a response within the configured read
/// timeout, distinct from the bridge actually reporting a failure: the
/// program job this request queued may still be running server-side and can
/// go on to complete normally after the client has already exited (see
/// `ghidra jobs`). Kept as a distinct error type (rather than a plain
/// `anyhow::bail!`) so callers -- `main`'s exit-code selection, or a wrapper
/// script via `downcast_ref` -- can tell "I gave up waiting" apart from "this
/// genuinely failed" without string-matching the message.
#[derive(Debug)]
pub struct BridgeTimeoutError {
    pub command: String,
    pub timeout_secs: u64,
}

impl std::fmt::Display for BridgeTimeoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Bridge did not respond within {}s while running '{}' — the program job is \
             still queued or running. Inspect `ghidra jobs`, raise the wait via \
             GHIDRA_CLI_READ_TIMEOUT (seconds; 0 = wait indefinitely), or use \
             GHIDRA_CLI_OP_TIMEOUT for long analyze/import operations.",
            self.timeout_secs, self.command
        )
    }
}

impl std::error::Error for BridgeTimeoutError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_serialization() {
        let request = BridgeRequest {
            command: "ping".to_string(),
            args: None,
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("ping"));
        assert!(!json.contains("args"));
    }

    #[test]
    fn test_request_with_args() {
        let request = BridgeRequest {
            command: "list_functions".to_string(),
            args: Some(serde_json::json!({"limit": 100})),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("list_functions"));
        assert!(json.contains("100"));
    }

    #[test]
    fn test_response_deserialization() {
        let json = r#"{"status":"success","data":{"count":42}}"#;
        let response: BridgeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.status, "success");
        assert!(response.data.is_some());
    }

    #[test]
    fn test_error_response() {
        let json = r#"{"status":"error","message":"Something went wrong"}"#;
        let response: BridgeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.status, "error");
        assert_eq!(response.message.as_ref().unwrap(), "Something went wrong");
    }
}
