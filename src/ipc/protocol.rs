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
    /// Client-chosen ID, so the client can look up or cancel its own job
    /// (`job_status`/`job_cancel` with `request_id`) after a read timeout.
    /// Bridges older than protocol 3 ignore it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Program the request must run against. A protocol-3 bridge rejects the
    /// job with [`ERR_PROGRAM_MISMATCH`] if another client switched programs
    /// while it was queued. Older bridges ignore it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expect_program: Option<String>,
}

/// Response from the Java bridge.
#[derive(Debug, Deserialize)]
pub struct BridgeResponse<T = serde_json::Value> {
    pub status: String,
    pub data: Option<T>,
    #[serde(default)]
    pub message: Option<String>,
    /// Stable machine-readable error code, present on some error responses
    /// (for example [`ERR_DECOMPILE_PAYLOAD_EXCEEDED`]).
    #[serde(default)]
    pub code: Option<String>,
}

/// Error code: the decompiler's response exceeded the payload limit. Retry with
/// a larger `--max-payload-mb` / `GHIDRA_CLI_DECOMPILE_MAX_PAYLOAD_MB`.
// Part of the library API; the `ghidra` binary only prints codes, so it never
// names this constant.
#[allow(dead_code)]
pub const ERR_DECOMPILE_PAYLOAD_EXCEEDED: &str = "decompile_payload_exceeded";

/// Error code: the bridge's current program is not the one the request named
/// in `expect_program`. The client re-opens the program and retries once.
pub const ERR_PROGRAM_MISMATCH: &str = "program_mismatch";

/// Error code: the bridge does not know the command (it predates this CLI).
pub const ERR_UNKNOWN_COMMAND: &str = "unknown_command";

/// Error code: a `--read-only` script changed the program.
#[allow(dead_code)]
pub const ERR_READ_ONLY_VIOLATION: &str = "read_only_violation";

/// A bridge error response that carried a machine-readable `code`.
///
/// Returned inside `anyhow::Error`; callers can `downcast_ref::<BridgeError>()`
/// to branch on [`BridgeError::code`]. `Display` is the bridge's message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeError {
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for BridgeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_serialization() {
        let request = BridgeRequest {
            command: "ping".to_string(),
            args: None,
            request_id: None,
            expect_program: None,
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("ping"));
        assert!(!json.contains("args"));
        assert!(!json.contains("request_id"));
        assert!(!json.contains("expect_program"));
    }

    #[test]
    fn test_request_with_request_id_and_expected_program() {
        let request = BridgeRequest {
            command: "decompile".to_string(),
            args: None,
            request_id: Some("abc".to_string()),
            expect_program: Some("ls".to_string()),
        };
        let v: serde_json::Value = serde_json::to_value(&request).unwrap();
        assert_eq!(v["request_id"], "abc");
        assert_eq!(v["expect_program"], "ls");
    }

    #[test]
    fn test_request_with_args() {
        let request = BridgeRequest {
            command: "list_functions".to_string(),
            args: Some(serde_json::json!({"limit": 100})),
            request_id: None,
            expect_program: None,
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
        assert!(response.code.is_none());
    }

    #[test]
    fn test_error_response_with_code() {
        let json = r#"{"status":"error","message":"too big","code":"decompile_payload_exceeded"}"#;
        let response: BridgeResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.status, "error");
        assert_eq!(
            response.code.as_deref(),
            Some(ERR_DECOMPILE_PAYLOAD_EXCEEDED)
        );
    }

    #[test]
    fn bridge_error_displays_message_and_downcasts() {
        let err: anyhow::Error = BridgeError {
            code: ERR_DECOMPILE_PAYLOAD_EXCEEDED.to_string(),
            message: "too big".to_string(),
        }
        .into();
        assert_eq!(err.to_string(), "too big");
        let typed = err
            .downcast_ref::<BridgeError>()
            .expect("typed bridge error");
        assert_eq!(typed.code, ERR_DECOMPILE_PAYLOAD_EXCEEDED);
    }
}
