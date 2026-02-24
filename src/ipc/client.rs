//! Bridge client for direct communication with the Java bridge.
//!
//! Connects directly to the Java GhidraCliBridge via TCP.
//! No intermediate daemon process is needed.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

use anyhow::Result;
use serde_json::json;
use tracing::debug;

use super::protocol::{BridgeRequest, BridgeResponse};

/// Client for communicating with the Ghidra Java bridge.
pub struct BridgeClient {
    port: u16,
}

impl BridgeClient {
    /// Create a client for a known port.
    pub fn new(port: u16) -> Self {
        Self { port }
    }

    /// Get the port this client connects to.
    #[allow(dead_code)]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Send a command to the bridge and return the result.
    pub fn send_command(
        &self,
        command: &str,
        args: Option<serde_json::Value>,
    ) -> Result<serde_json::Value> {
        let addr: std::net::SocketAddr = format!("127.0.0.1:{}", self.port)
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?;
        let mut stream =
            TcpStream::connect_timeout(&addr, Duration::from_secs(10)).map_err(|e| {
                anyhow::anyhow!("Failed to connect to bridge on port {}: {}", self.port, e)
            })?;
        stream.set_read_timeout(Some(Duration::from_secs(300))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(30))).ok();

        let request = BridgeRequest {
            command: command.to_string(),
            args,
        };

        let request_json = serde_json::to_string(&request)?;
        debug!("Sending: {}", request_json);

        writeln!(stream, "{}", request_json)?;
        stream.flush()?;

        let mut reader = BufReader::new(&stream);
        let mut response_line = String::new();
        reader.read_line(&mut response_line)?;

        debug!("Received: {}", response_line.trim());

        let response: BridgeResponse = serde_json::from_str(&response_line)?;

        match response.status.as_str() {
            "success" => Ok(response.data.unwrap_or(json!({}))),
            "error" => {
                let msg = response
                    .message
                    .unwrap_or_else(|| "Unknown error".to_string());
                anyhow::bail!("{}", msg)
            }
            "shutdown" => Ok(json!({"status": "shutdown"})),
            _ => Ok(response.data.unwrap_or(json!({}))),
        }
    }

    /// Check if bridge is responding.
    pub fn ping(&self) -> Result<bool> {
        match self.send_command("ping", None) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Shutdown the bridge.
    pub fn shutdown(&self) -> Result<()> {
        self.send_command("shutdown", None)?;
        Ok(())
    }

    /// Get bridge status.
    #[allow(dead_code)]
    pub fn status(&self) -> Result<serde_json::Value> {
        self.send_command("status", None)
    }

    /// Get bridge info (current program, project name, program count, uptime).
    pub fn bridge_info(&self) -> Result<serde_json::Value> {
        self.send_command("bridge_info", None)
    }

    /// List functions.
    pub fn list_functions(
        &self,
        limit: Option<usize>,
        filter: Option<String>,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "function_list",
            Some(json!({"limit": limit, "filter": filter})),
        )
    }

    /// Decompile a function.
    pub fn decompile(&self, address: String) -> Result<serde_json::Value> {
        self.send_command("decompile", Some(json!({"address": address})))
    }

    /// List strings.
    pub fn list_strings(&self, limit: Option<usize>, filter: Option<String>) -> Result<serde_json::Value> {
        self.send_command("list_strings", Some(json!({"limit": limit, "filter": filter})))
    }

    /// List imports.
    pub fn list_imports(&self) -> Result<serde_json::Value> {
        self.send_command("list_imports", None)
    }

    /// List exports.
    pub fn list_exports(&self) -> Result<serde_json::Value> {
        self.send_command("list_exports", None)
    }

    /// Get memory map.
    pub fn memory_map(&self) -> Result<serde_json::Value> {
        self.send_command("memory_map", None)
    }

    /// Get program info.
    pub fn program_info(&self) -> Result<serde_json::Value> {
        self.send_command("program_info", None)
    }

    /// Get cross-references to an address.
    pub fn xrefs_to(&self, address: String) -> Result<serde_json::Value> {
        self.send_command("xrefs_to", Some(json!({"address": address})))
    }

    /// Get cross-references from an address.
    pub fn xrefs_from(&self, address: String) -> Result<serde_json::Value> {
        self.send_command("xrefs_from", Some(json!({"address": address})))
    }

    /// Import a binary.
    pub fn import_binary(
        &self,
        binary_path: &str,
        program: Option<&str>,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "import",
            Some(json!({"binary_path": binary_path, "program": program})),
        )
    }

    /// Analyze the current program.
    pub fn analyze(&self) -> Result<serde_json::Value> {
        self.send_command("analyze", None)
    }

    /// List programs in the project.
    pub fn list_programs(&self) -> Result<serde_json::Value> {
        self.send_command("list_programs", None)
    }

    /// Open/switch to a program.
    pub fn open_program(&self, program: &str) -> Result<serde_json::Value> {
        self.send_command("open_program", Some(json!({"program": program})))
    }

    // === Extended commands (symbols, types, comments, etc.) ===

    pub fn symbol_list(&self, limit: Option<usize>, filter: Option<&str>) -> Result<serde_json::Value> {
        self.send_command("symbol_list", Some(json!({"limit": limit, "filter": filter})))
    }

    pub fn symbol_get(&self, name: &str) -> Result<serde_json::Value> {
        self.send_command("symbol_get", Some(json!({"name": name})))
    }

    pub fn symbol_create(&self, address: &str, name: &str) -> Result<serde_json::Value> {
        self.send_command(
            "symbol_create",
            Some(json!({"address": address, "name": name})),
        )
    }

    pub fn symbol_delete(&self, name: &str) -> Result<serde_json::Value> {
        self.send_command("symbol_delete", Some(json!({"name": name})))
    }

    pub fn symbol_rename(
        &self,
        target: &str,
        new_name: &str,
        namespace: Option<&str>,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "symbol_rename",
            Some(json!({"address": target, "new_name": new_name, "namespace": namespace})),
        )
    }

    pub fn type_list(&self, limit: Option<usize>, filter: Option<&str>) -> Result<serde_json::Value> {
        self.send_command("type_list", Some(json!({"limit": limit, "filter": filter})))
    }

    pub fn type_get(&self, name: &str) -> Result<serde_json::Value> {
        self.send_command("type_get", Some(json!({"name": name})))
    }

    pub fn type_create(&self, definition: &str) -> Result<serde_json::Value> {
        self.send_command("type_create", Some(json!({"definition": definition})))
    }

    pub fn type_apply(&self, address: &str, type_name: &str) -> Result<serde_json::Value> {
        self.send_command(
            "type_apply",
            Some(json!({"address": address, "type_name": type_name})),
        )
    }

    pub fn type_import_c(&self, code: &str, category: Option<&str>) -> Result<serde_json::Value> {
        self.send_command(
            "type_import_c",
            Some(json!({"code": code, "category": category})),
        )
    }

    pub fn function_set_signature(
        &self,
        target: &str,
        signature: &str,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "function_set_signature",
            Some(json!({"address": target, "signature": signature})),
        )
    }

    pub fn comment_list(&self, limit: Option<usize>, filter: Option<&str>) -> Result<serde_json::Value> {
        self.send_command("comment_list", Some(json!({"limit": limit, "filter": filter})))
    }

    pub fn comment_get(&self, address: &str) -> Result<serde_json::Value> {
        self.send_command("comment_get", Some(json!({"address": address})))
    }

    pub fn comment_set(
        &self,
        address: &str,
        text: &str,
        comment_type: Option<&str>,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "comment_set",
            Some(json!({
                "address": address,
                "text": text,
                "type": comment_type,
            })),
        )
    }

    pub fn comment_delete(&self, address: &str) -> Result<serde_json::Value> {
        self.send_command("comment_delete", Some(json!({"address": address})))
    }

    pub fn graph_calls(&self, limit: Option<usize>) -> Result<serde_json::Value> {
        self.send_command("graph_calls", Some(json!({"limit": limit})))
    }

    pub fn graph_callers(&self, function: &str, depth: Option<usize>) -> Result<serde_json::Value> {
        self.send_command(
            "graph_callers",
            Some(json!({"function": function, "depth": depth})),
        )
    }

    pub fn graph_callees(&self, function: &str, depth: Option<usize>) -> Result<serde_json::Value> {
        self.send_command(
            "graph_callees",
            Some(json!({"function": function, "depth": depth})),
        )
    }

    pub fn graph_export(&self, format: &str) -> Result<serde_json::Value> {
        self.send_command("graph_export", Some(json!({"format": format})))
    }

    pub fn find_string(&self, pattern: &str) -> Result<serde_json::Value> {
        self.send_command("find_string", Some(json!({"pattern": pattern})))
    }

    pub fn find_bytes(&self, hex: &str) -> Result<serde_json::Value> {
        self.send_command("find_bytes", Some(json!({"hex": hex})))
    }

    pub fn find_function(&self, pattern: &str) -> Result<serde_json::Value> {
        self.send_command("find_function", Some(json!({"pattern": pattern})))
    }

    pub fn find_calls(&self, function: &str) -> Result<serde_json::Value> {
        self.send_command("find_calls", Some(json!({"function": function})))
    }

    pub fn find_crypto(&self) -> Result<serde_json::Value> {
        self.send_command("find_crypto", None)
    }

    pub fn find_interesting(&self) -> Result<serde_json::Value> {
        self.send_command("find_interesting", None)
    }

    pub fn diff_programs(&self, program1: &str, program2: &str) -> Result<serde_json::Value> {
        self.send_command(
            "diff_programs",
            Some(json!({"program1": program1, "program2": program2})),
        )
    }

    pub fn diff_functions(&self, func1: &str, func2: &str) -> Result<serde_json::Value> {
        self.send_command(
            "diff_functions",
            Some(json!({"func1": func1, "func2": func2})),
        )
    }

    pub fn patch_bytes(&self, address: &str, hex: &str) -> Result<serde_json::Value> {
        self.send_command("patch_bytes", Some(json!({"address": address, "hex": hex})))
    }

    pub fn patch_nop(&self, address: &str) -> Result<serde_json::Value> {
        self.send_command("patch_nop", Some(json!({"address": address})))
    }

    pub fn patch_export(&self, output: &str) -> Result<serde_json::Value> {
        self.send_command("patch_export", Some(json!({"output": output})))
    }

    pub fn disasm(
        &self,
        address: &str,
        num_instructions: Option<usize>,
    ) -> Result<serde_json::Value> {
        self.send_command(
            "disasm",
            Some(json!({"address": address, "count": num_instructions})),
        )
    }

    pub fn stats(&self) -> Result<serde_json::Value> {
        self.send_command("stats", None)
    }

    pub fn script_run(&self, script_path: &str, args: &[String]) -> Result<serde_json::Value> {
        self.send_command(
            "script_run",
            Some(json!({"path": script_path, "args": args})),
        )
    }

    pub fn script_python(&self, code: &str) -> Result<serde_json::Value> {
        self.send_command("script_python", Some(json!({"code": code})))
    }

    pub fn script_java(&self, code: &str) -> Result<serde_json::Value> {
        self.send_command("script_java", Some(json!({"code": code})))
    }

    pub fn script_list(&self) -> Result<serde_json::Value> {
        self.send_command("script_list", None)
    }

    pub fn program_close(&self) -> Result<serde_json::Value> {
        self.send_command("close_program", None)
    }

    pub fn program_delete(&self, program: &str) -> Result<serde_json::Value> {
        self.send_command("delete_program", Some(json!({"program": program})))
    }

    pub fn program_export(&self, format: &str, output: Option<&str>) -> Result<serde_json::Value> {
        self.send_command(
            "export_program",
            Some(json!({"format": format, "output": output})),
        )
    }
}
