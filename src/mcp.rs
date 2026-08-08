//! Native MCP server for ghidra-cli (stdio + streamable HTTP).
//!
//! Tools are thin adapters over BridgeClient. Every tools/call response is a
//! stable envelope with provenance, next_steps, recovery_suggestions, and
//! optional artifacts[].

use crate::config::Config;
use crate::ghidra::bridge;
use crate::ipc::client::BridgeClient;
use serde_json::{json, Map, Value};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Run the MCP server over stdio (line-based JSON-RPC 2.0).
pub fn run_stdio_server(
    default_project: Option<String>,
    default_program: Option<String>,
    projects_dir: Option<PathBuf>,
) -> anyhow::Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let reader = stdin.lock();
    let mut cached_client: Option<(String, BridgeClient)> = None;

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let id = extract_id(&line);
                let resp = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": -32700, "message": format!("Parse error: {}", e)}
                });
                let _ = writeln!(stdout, "{}", resp);
                let _ = stdout.flush();
                continue;
            }
        };
        let resp = handle_request(
            &req,
            &mut cached_client,
            default_project.clone(),
            default_program.clone(),
            projects_dir.clone(),
        );
        if !resp.is_null() {
            writeln!(stdout, "{}", serde_json::to_string(&resp)?)?;
            stdout.flush()?;
        }
    }
    Ok(())
}

/// Streamable HTTP MCP transport. Same tool registry as stdio.
///
/// When bound to a loopback address, non-loopback peers are rejected (403).
/// Binding to `0.0.0.0` / `::` opts into accepting remote peers (use a token).
/// Optional bearer token via `token` (or env `GHIDRA_MCP_TOKEN` when wired from CLI).
pub fn run_http_server(
    listen: &str,
    default_project: Option<String>,
    default_program: Option<String>,
    projects_dir: Option<PathBuf>,
    token: Option<String>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen)
        .map_err(|e| anyhow::anyhow!("Failed to bind MCP HTTP on {}: {}", listen, e))?;
    let addr = listener.local_addr()?;
    let loopback_only = addr.ip().is_loopback();
    // Agents and tests parse this line for the ephemeral port.
    eprintln!("ghidra-mcp-http listening on {}", addr);
    println!("ghidra-mcp-http listening on {}", addr);
    let _ = io::stdout().flush();

    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let flag = shutdown.clone();
        let _ = ctrlc_install(flag);
    }

    let mut cached_client: Option<(String, BridgeClient)> = None;
    listener.set_nonblocking(false)?;

    for stream in listener.incoming() {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        match stream {
            Ok(stream) => {
                if let Err(e) = handle_http_connection(
                    stream,
                    &mut cached_client,
                    default_project.clone(),
                    default_program.clone(),
                    projects_dir.clone(),
                    token.as_deref(),
                    loopback_only,
                ) {
                    eprintln!("MCP HTTP connection error: {}", e);
                }
            }
            Err(e) => {
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }
                eprintln!("MCP HTTP accept error: {}", e);
            }
        }
    }
    eprintln!("ghidra-mcp-http shutdown");
    Ok(())
}

/// Best-effort Ctrl-C flag without adding a dependency.
fn ctrlc_install(flag: Arc<AtomicBool>) -> anyhow::Result<()> {
    // libc signal handler would be unsafe and racy; rely on process kill for
    // production and AtomicBool for cooperative shutdown in tests that call stop.
    // Keep the flag so future wiring can set it.
    let _ = flag;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tool registry (shared by stdio + HTTP + tests)
// ---------------------------------------------------------------------------

/// Schema version for tool definitions. Breaking input/output changes bump this
/// and either rename the tool or add a `_vN` suffix (see docs/MCP.md).
pub const TOOL_SCHEMA_VERSION: &str = "1";

/// Pure tool list used by `tools/list` and equivalence tests.
pub fn tool_definitions() -> Value {
    json!([
        tool("ping", "Health check. Returns a stable envelope with next_steps.", json!({})),
        tool("project_list", "List programs in the active/default project.", json!({"project": {"type": "string"}})),
        tool("function_list", "List functions. Optional limit and filter.", json!({"limit": {"type": "integer"}, "filter": {"type": "string"}})),
        tool("decompile", "Decompile a function. Always includes nearby_xrefs, callers, namespace (may be empty).", json!({"target": {"type": "string"}, "address": {"type": "string"}, "max_xrefs": {"type": "integer"}, "caller_depth": {"type": "integer"}})),
        tool("xrefs_to", "Get cross-references to a target address.", json!({"target": {"type": "string"}})),
        tool("xrefs_from", "Get cross-references from a target address.", json!({"target": {"type": "string"}})),
        tool("strings_list", "List strings.", json!({"limit": {"type": "integer"}, "filter": {"type": "string"}})),
        tool("symbols_list", "List symbols.", json!({"limit": {"type": "integer"}, "filter": {"type": "string"}})),
        tool("memory_map", "Memory map of the current program.", json!({})),
        tool("types_list", "List data types.", json!({"limit": {"type": "integer"}, "filter": {"type": "string"}})),
        tool("comments_list", "List comments.", json!({"limit": {"type": "integer"}, "filter": {"type": "string"}})),
        tool("find_string", "Find strings matching a pattern.", json!({"pattern": {"type": "string"}})),
        tool("find_bytes", "Find a hex byte pattern.", json!({"hex": {"type": "string"}})),
        tool("find_function", "Find functions by name pattern.", json!({"pattern": {"type": "string"}})),
        tool("find_calls", "Find calls to a given function.", json!({"function": {"type": "string"}})),
        tool("find_crypto", "Find crypto constants.", json!({})),
        tool("find_interesting", "Find interesting patterns/locations.", json!({})),
        tool("graph_calls", "Full call graph (limited).", json!({"limit": {"type": "integer"}})),
        tool("graph_callers", "Callers of a function (with depth).", json!({"function": {"type": "string"}, "depth": {"type": "integer"}})),
        tool("graph_callees", "Callees of a function (with depth).", json!({"function": {"type": "string"}, "depth": {"type": "integer"}})),
        tool("script_list", "List available scripts (python/java).", json!({})),
        tool("script_run", "Run a script with args, expect artifacts, allow_empty (mutation).", json!({"path": {"type": "string"}, "args": {"type": "array", "items": {"type": "string"}}, "expect": {"type": "array"}, "allow_empty": {"type": "boolean"}})),
        tool("disasm", "Disassemble instructions at target.", json!({"target": {"type": "string"}, "count": {"type": "integer"}})),
        tool("list_imports", "List imports for the current program.", json!({})),
        tool("list_exports", "List exports for the current program.", json!({})),
        tool("program_info", "Get info for the current program.", json!({})),
        tool("stats", "Get program/bridge stats.", json!({})),
        // Mutations (slice 1.4) — same job queue / transaction paths as CLI
        tool("patch_bytes", "Patch bytes at address (mutation).", json!({"address": {"type": "string"}, "hex": {"type": "string"}})),
        tool("patch_nop", "NOP out instructions (mutation).", json!({"address": {"type": "string"}, "count": {"type": "integer"}})),
        tool("patch_export", "Export patched binary (mutation).", json!({"output": {"type": "string"}})),
        tool("create_function", "Create a function at address (mutation).", json!({"address": {"type": "string"}, "name": {"type": "string"}})),
        tool("rename_function", "Rename a function (mutation). Args: old_name/target + new_name/name.", json!({"old_name": {"type": "string"}, "new_name": {"type": "string"}, "target": {"type": "string"}, "name": {"type": "string"}})),
        tool("delete_function", "Delete a function (mutation).", json!({"target": {"type": "string"}})),
        tool("function_set_signature", "Set function signature (mutation).", json!({"target": {"type": "string"}, "signature": {"type": "string"}})),
        tool("function_set_return_type", "Set function return type (mutation).", json!({"target": {"type": "string"}, "type": {"type": "string"}})),
        tool("function_set_calling_convention", "Set function calling convention (mutation).", json!({"target": {"type": "string"}, "convention": {"type": "string"}})),
        tool("set_var_type", "Set variable type in a function (mutation).", json!({"function": {"type": "string"}, "variable": {"type": "string"}, "type": {"type": "string"}})),
        tool("symbol_create", "Create a symbol (mutation).", json!({"address": {"type": "string"}, "name": {"type": "string"}})),
        tool("symbol_delete", "Delete a symbol (mutation).", json!({"name": {"type": "string"}})),
        tool("symbol_rename", "Rename a symbol (mutation).", json!({"old_name": {"type": "string"}, "new_name": {"type": "string"}})),
        tool("comment_set", "Set a comment (mutation).", json!({"address": {"type": "string"}, "text": {"type": "string"}, "comment_type": {"type": "string"}})),
        tool("comment_delete", "Delete a comment (mutation).", json!({"address": {"type": "string"}})),
        tool("type_create", "Create a data type from definition (mutation).", json!({"definition": {"type": "string"}})),
        tool("type_apply", "Apply a type at address (mutation).", json!({"address": {"type": "string"}, "type_name": {"type": "string"}})),
        tool("type_delete", "Delete a data type (mutation).", json!({"name": {"type": "string"}})),
        tool("type_rename", "Rename a data type (mutation).", json!({"old_name": {"type": "string"}, "new_name": {"type": "string"}})),
        tool("type_create_enum", "Create an enum type (mutation).", json!({"name": {"type": "string"}, "values": {"type": "object"}})),
        tool("type_typedef", "Create a typedef (mutation).", json!({"name": {"type": "string"}, "base": {"type": "string"}})),
        tool("type_add_field", "Add a field to a structure (mutation).", json!({"struct": {"type": "string"}, "name": {"type": "string"}, "type": {"type": "string"}, "offset": {"type": "integer"}})),
        tool("type_del_field", "Delete a field from a structure (mutation).", json!({"struct": {"type": "string"}, "name": {"type": "string"}})),
        tool("batch", "Execute an array of {name, arguments} tool calls; returns per-command status.", json!({"commands": {"type": "array", "items": {"type": "object", "properties": {"name": {"type": "string"}, "arguments": {"type": "object"}}}}})),
        // Diff / triage / deeper primitives (items 3–5)
        tool("diff_programs", "Diff two programs in the project (match/delta report).", json!({"program1": {"type": "string"}, "program2": {"type": "string"}})),
        tool("diff_functions", "Diff two functions.", json!({"func1": {"type": "string"}, "func2": {"type": "string"}})),
        tool("summarize", "One-shot triage/summarize report with confidence-tagged findings.", json!({"focus": {"type": "string", "description": "optional: crypto,strings,entry,imports,all"}})),
        tool("pcode", "List p-code for a function or address.", json!({"target": {"type": "string"}, "limit": {"type": "integer"}})),
        tool("transaction_begin", "Begin an explicit mutation transaction (undo boundary).", json!({"name": {"type": "string"}})),
        tool("transaction_commit", "Commit the open mutation transaction.", json!({})),
        tool("transaction_abort", "Abort/rollback the open mutation transaction.", json!({})),
        tool("capabilities", "Report CLI version, bridge/Ghidra capabilities, and feature flags.", json!({}))
    ])
}

fn tool(name: &str, description: &str, properties: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": properties
        },
        "annotations": {
            "schema_version": TOOL_SCHEMA_VERSION
        }
    })
}

// ---------------------------------------------------------------------------
// JSON-RPC dispatch
// ---------------------------------------------------------------------------

fn extract_id(line: &str) -> Option<Value> {
    if let Ok(v) = serde_json::from_str::<Value>(line) {
        return v.get("id").cloned();
    }
    None
}

fn handle_request(
    req: &Value,
    cached_client: &mut Option<(String, BridgeClient)>,
    default_project: Option<String>,
    default_program: Option<String>,
    projects_dir: Option<PathBuf>,
) -> Value {
    let jsonrpc = "2.0";
    let id = req.get("id").cloned();
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");

    match method {
        "initialize" => {
            let caps = build_server_capabilities(cached_client, default_project.clone(), default_program.clone(), projects_dir.clone());
            json!({
                "jsonrpc": jsonrpc,
                "id": id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": { "tools": {} },
                    "serverInfo": {
                        "name": "ghidra-mcp",
                        "version": env!("CARGO_PKG_VERSION"),
                        "schema_version": TOOL_SCHEMA_VERSION
                    },
                    "ghidraCapabilities": caps
                }
            })
        }

        "tools/list" => json!({
            "jsonrpc": jsonrpc,
            "id": id,
            "result": { "tools": tool_definitions() }
        }),

        "tools/call" => {
            let params = req.get("params").cloned().unwrap_or(json!({}));
            let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            dispatch_tool(
                name,
                &args,
                id,
                cached_client,
                default_project,
                default_program,
                projects_dir,
            )
        }

        _ if id.is_none() => json!(null),

        _ => json!({
            "jsonrpc": jsonrpc,
            "id": id,
            "error": { "code": -32601, "message": "Method not found" }
        }),
    }
}

fn dispatch_tool(
    name: &str,
    args: &Value,
    id: Option<Value>,
    cached_client: &mut Option<(String, BridgeClient)>,
    default_project: Option<String>,
    default_program: Option<String>,
    projects_dir: Option<PathBuf>,
) -> Value {
    match name {
        "ping" => wrap_envelope_as_content(make_ping_envelope(), id),

        "capabilities" => {
            let caps = build_server_capabilities(
                cached_client,
                default_project.clone(),
                default_program.clone(),
                projects_dir.clone(),
            );
            let env = make_envelope(
                "capabilities",
                caps,
                default_project.as_deref(),
                default_program.as_deref(),
                vec!["Use tools/list for schemas; call focused tools next.".into()],
                None,
            );
            wrap_envelope_as_content(env, id)
        }

        "project_list" => {
            let proj = args
                .get("project")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .or(default_project.clone());
            match get_bridge_client(
                cached_client,
                proj.clone(),
                default_program.clone(),
                projects_dir.clone(),
            ) {
                Ok((client, proj_name)) => {
                    match client.send_command("list_programs", None) {
                        Ok(data) => {
                            let ns = compute_next_steps("project_list", None);
                            wrap_envelope_as_content(
                                make_envelope("project_list", data, Some(&proj_name), None, ns, None),
                                id,
                            )
                        }
                        Err(e) => tool_error(id, "project_list", &e.to_string(), recovery_for("project_list", &e.to_string())),
                    }
                }
                Err(_e) => {
                    let data = list_local_projects(projects_dir.clone());
                    let ns = compute_next_steps("project_list", None);
                    wrap_envelope_as_content(
                        make_envelope("project_list", data, proj.as_deref(), None, ns, None),
                        id,
                    )
                }
            }
        }

        "function_list" => bridge_tool(
            id, "function_list", cached_client, default_project, default_program, projects_dir, false,
            |client| {
                let limit = args.get("limit").and_then(|v| v.as_u64()).map(|n| n as usize);
                let filter = args.get("filter").and_then(|v| v.as_str()).map(|s| s.to_string());
                client.list_functions(limit, filter)
            },
            None,
        ),

        "decompile" => {
            let target = args
                .get("target")
                .and_then(|v| v.as_str())
                .or_else(|| args.get("address").and_then(|v| v.as_str()))
                .unwrap_or("");
            if target.is_empty() {
                return tool_error(
                    id,
                    "decompile",
                    "target (or address) required for decompile",
                    recovery_for("decompile", "target required"),
                );
            }
            let max_xrefs = args.get("max_xrefs").and_then(|v| v.as_u64()).unwrap_or(50) as usize;
            let caller_depth = args.get("caller_depth").and_then(|v| v.as_u64()).unwrap_or(2) as usize;
            let target_owned = target.to_string();
            bridge_tool(
                id, "decompile", cached_client, default_project, default_program, projects_dir, false,
                move |client| enrich_decompile(client, &target_owned, max_xrefs, caller_depth),
                Some(target),
            )
        }

        "xrefs_to" | "xrefs_from" => {
            let target = args.get("target").and_then(|v| v.as_str()).unwrap_or("");
            if target.is_empty() {
                return tool_error(id, name, "target required", recovery_for(name, "target required"));
            }
            let t = target.to_string();
            let cmd = name.to_string();
            bridge_tool(
                id, name, cached_client, default_project, default_program, projects_dir, false,
                move |client| {
                    if cmd == "xrefs_to" {
                        client.xrefs_to(t)
                    } else {
                        client.xrefs_from(t)
                    }
                },
                Some(target),
            )
        }

        "strings_list" => bridge_tool(
            id, "strings_list", cached_client, default_project, default_program, projects_dir, false,
            |client| {
                let limit = args.get("limit").and_then(|v| v.as_u64()).map(|n| n as usize);
                let filter = args.get("filter").and_then(|v| v.as_str()).map(|s| s.to_string());
                client.list_strings(limit, filter)
            },
            None,
        ),

        "symbols_list" => bridge_tool(
            id, "symbols_list", cached_client, default_project, default_program, projects_dir, false,
            |client| {
                let limit = args.get("limit").and_then(|v| v.as_u64()).map(|n| n as usize);
                let filter = args.get("filter").and_then(|v| v.as_str());
                client.symbol_list(limit, filter)
            },
            None,
        ),

        "memory_map" => bridge_tool(
            id, "memory_map", cached_client, default_project, default_program, projects_dir, false,
            |client| client.memory_map(),
            None,
        ),

        "types_list" => bridge_tool(
            id, "types_list", cached_client, default_project, default_program, projects_dir, false,
            |client| {
                let limit = args.get("limit").and_then(|v| v.as_u64()).map(|n| n as usize);
                let filter = args.get("filter").and_then(|v| v.as_str());
                client.type_list(limit, filter)
            },
            None,
        ),

        "comments_list" => bridge_tool(
            id, "comments_list", cached_client, default_project, default_program, projects_dir, false,
            |client| {
                let limit = args.get("limit").and_then(|v| v.as_u64()).map(|n| n as usize);
                let filter = args.get("filter").and_then(|v| v.as_str());
                client.comment_list(limit, filter)
            },
            None,
        ),

        "find_string" => require_str_then(id, name, args, "pattern", |id, pat| {
            let p = pat.to_string();
            bridge_tool(
                id, name, cached_client, default_project, default_program, projects_dir, false,
                move |client| client.find_string(&p),
                Some(pat),
            )
        }),
        "find_bytes" => require_str_then(id, name, args, "hex", |id, hex| {
            let h = hex.to_string();
            bridge_tool(
                id, name, cached_client, default_project, default_program, projects_dir, false,
                move |client| client.find_bytes(&h),
                Some(hex),
            )
        }),
        "find_function" => require_str_then(id, name, args, "pattern", |id, pat| {
            let p = pat.to_string();
            bridge_tool(
                id, name, cached_client, default_project, default_program, projects_dir, false,
                move |client| client.find_function(&p),
                Some(pat),
            )
        }),
        "find_calls" => require_str_then(id, name, args, "function", |id, func| {
            let f = func.to_string();
            bridge_tool(
                id, name, cached_client, default_project, default_program, projects_dir, false,
                move |client| client.find_calls(&f),
                Some(func),
            )
        }),
        "find_crypto" => bridge_tool(
            id, "find_crypto", cached_client, default_project, default_program, projects_dir, false,
            |client| client.find_crypto(),
            None,
        ),
        "find_interesting" => bridge_tool(
            id, "find_interesting", cached_client, default_project, default_program, projects_dir, false,
            |client| client.find_interesting(),
            None,
        ),

        "graph_calls" => bridge_tool(
            id, "graph_calls", cached_client, default_project, default_program, projects_dir, false,
            |client| {
                let limit = args.get("limit").and_then(|v| v.as_u64()).map(|n| n as usize);
                client.graph_calls(limit)
            },
            None,
        ),
        "graph_callers" | "graph_callees" => {
            let function = args.get("function").and_then(|v| v.as_str()).unwrap_or("");
            if function.is_empty() {
                return tool_error(id, name, "function required", recovery_for(name, "function required"));
            }
            let depth = args.get("depth").and_then(|v| v.as_u64()).map(|n| n as usize);
            let f = function.to_string();
            let cmd = name.to_string();
            bridge_tool(
                id, name, cached_client, default_project, default_program, projects_dir, false,
                move |client| {
                    if cmd == "graph_callers" {
                        client.graph_callers(&f, depth)
                    } else {
                        client.graph_callees(&f, depth)
                    }
                },
                Some(function),
            )
        }

        "script_list" => bridge_tool(
            id, "script_list", cached_client, default_project, default_program, projects_dir, false,
            |client| client.script_list(),
            None,
        ),

        "script_run" => {
            let path = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
            if path.is_empty() {
                return tool_error(id, "script_run", "path required", recovery_for("script_run", "path required"));
            }
            let script_args: Vec<String> = args
                .get("args")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();
            let expect: Vec<Value> = args
                .get("expect")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let allow_empty = args.get("allow_empty").and_then(|v| v.as_bool()).unwrap_or(false);
            let path_owned = path.to_string();
            match get_bridge_client(
                cached_client,
                default_project.clone(),
                default_program.clone(),
                projects_dir.clone(),
            ) {
                Ok((client, proj_name)) => {
                    let canon_path = std::fs::canonicalize(&path_owned)
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_else(|_| path_owned.clone());
                    match client.script_run(&canon_path, &script_args, &expect, allow_empty) {
                        Ok(data) => {
                            let ns = compute_next_steps("script_run", Some(&path_owned));
                            let env = envelope_with_script_artifacts(
                                "script_run",
                                data,
                                Some(&proj_name),
                                default_program.as_deref(),
                                ns,
                            );
                            wrap_envelope_as_content(env, id)
                        }
                        Err(e) => tool_error(
                            id,
                            "script_run",
                            &e.to_string(),
                            recovery_for("script_run", &e.to_string()),
                        ),
                    }
                }
                Err(e) => tool_error(
                    id,
                    "script_run",
                    &format!("No bridge: {}", e),
                    recovery_for("script_run", &e.to_string()),
                ),
            }
        }

        "disasm" => {
            let target = args.get("target").and_then(|v| v.as_str()).unwrap_or("");
            if target.is_empty() {
                return tool_error(id, "disasm", "target required", recovery_for("disasm", "target required"));
            }
            let count = args.get("count").and_then(|v| v.as_u64()).map(|n| n as usize);
            let t = target.to_string();
            bridge_tool(
                id, "disasm", cached_client, default_project, default_program, projects_dir, false,
                move |client| client.disasm(&t, count),
                Some(target),
            )
        }

        "list_imports" => match get_bridge_client(
            cached_client,
            default_project.clone(),
            default_program.clone(),
            projects_dir.clone(),
        ) {
            Ok((client, proj_name)) => match client.list_imports() {
                Ok(data) => wrap_envelope_as_content(
                    make_envelope(
                        "list_imports",
                        data,
                        Some(&proj_name),
                        default_program.as_deref(),
                        compute_next_steps("list_imports", None),
                        None,
                    ),
                    id,
                ),
                Err(e) => tool_error(id, "list_imports", &e.to_string(), recovery_for("list_imports", &e.to_string())),
            },
            Err(_e) => wrap_envelope_as_content(
                make_envelope(
                    "list_imports",
                    json!({"imports": []}),
                    None,
                    None,
                    compute_next_steps("list_imports", None),
                    None,
                ),
                id,
            ),
        },

        "list_exports" => bridge_tool(
            id, "list_exports", cached_client, default_project, default_program, projects_dir, false,
            |client| client.list_exports(),
            None,
        ),
        "program_info" => bridge_tool(
            id, "program_info", cached_client, default_project, default_program, projects_dir, false,
            |client| client.program_info(),
            None,
        ),
        "stats" => match get_bridge_client(
            cached_client,
            default_project.clone(),
            default_program.clone(),
            projects_dir.clone(),
        ) {
            Ok((client, proj_name)) => match client.stats() {
                Ok(data) => wrap_envelope_as_content(
                    make_envelope(
                        "stats",
                        data,
                        Some(&proj_name),
                        default_program.as_deref(),
                        compute_next_steps("stats", None),
                        None,
                    ),
                    id,
                ),
                Err(e) => tool_error(id, "stats", &e.to_string(), recovery_for("stats", &e.to_string())),
            },
            Err(_e) => wrap_envelope_as_content(
                make_envelope(
                    "stats",
                    json!({"bridge": "not connected"}),
                    None,
                    None,
                    compute_next_steps("stats", None),
                    None,
                ),
                id,
            ),
        },

        // ---- Mutations (job queue / transaction via bridge) ----
        "patch_bytes" => {
            let address = args.get("address").and_then(|v| v.as_str()).unwrap_or("");
            let hex = args.get("hex").and_then(|v| v.as_str()).unwrap_or("");
            if address.is_empty() || hex.is_empty() {
                return tool_error(
                    id,
                    "patch_bytes",
                    "address and hex required",
                    recovery_for("patch_bytes", "missing fields"),
                );
            }
            let a = address.to_string();
            let h = hex.to_string();
            bridge_tool(
                id, "patch_bytes", cached_client, default_project, default_program, projects_dir, true,
                move |client| client.patch_bytes(&a, &h),
                Some(address),
            )
        }
        "patch_nop" => {
            let address = args.get("address").and_then(|v| v.as_str()).unwrap_or("");
            if address.is_empty() {
                return tool_error(id, "patch_nop", "address required", recovery_for("patch_nop", "address required"));
            }
            let count = args.get("count").and_then(|v| v.as_u64()).map(|n| n as usize);
            let a = address.to_string();
            bridge_tool(
                id, "patch_nop", cached_client, default_project, default_program, projects_dir, true,
                move |client| client.patch_nop(&a, count),
                Some(address),
            )
        }
        "patch_export" => {
            let output = args.get("output").and_then(|v| v.as_str()).unwrap_or("");
            if output.is_empty() {
                return tool_error(id, "patch_export", "output required", recovery_for("patch_export", "output required"));
            }
            let o = output.to_string();
            bridge_tool(
                id, "patch_export", cached_client, default_project, default_program, projects_dir, true,
                move |client| client.patch_export(&o),
                Some(output),
            )
        }
        "create_function" => {
            let address = args.get("address").and_then(|v| v.as_str()).unwrap_or("");
            if address.is_empty() {
                return tool_error(id, "create_function", "address required", recovery_for("create_function", "address required"));
            }
            let name_opt = args.get("name").and_then(|v| v.as_str()).map(|s| s.to_string());
            let a = address.to_string();
            bridge_tool(
                id, "create_function", cached_client, default_project, default_program, projects_dir, true,
                move |client| {
                    let payload = if let Some(n) = name_opt {
                        json!({"address": a, "name": n})
                    } else {
                        json!({"address": a})
                    };
                    client.send_command("create_function", Some(payload))
                },
                Some(address),
            )
        }
        "rename_function" => {
            // Bridge wire format: old_name + new_name (also accept target/name aliases).
            let target = args
                .get("old_name")
                .or_else(|| args.get("target"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let new_name = args
                .get("new_name")
                .or_else(|| args.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if target.is_empty() || new_name.is_empty() {
                return tool_error(
                    id,
                    "rename_function",
                    "old_name (or target) and new_name (or name) required",
                    recovery_for("rename_function", "missing fields"),
                );
            }
            let t = target.to_string();
            let n = new_name.to_string();
            bridge_tool(
                id, "rename_function", cached_client, default_project, default_program, projects_dir, true,
                move |client| {
                    client.send_command(
                        "rename_function",
                        Some(json!({"old_name": t, "new_name": n})),
                    )
                },
                Some(target),
            )
        }
        "delete_function" => {
            let target = args.get("target").and_then(|v| v.as_str()).unwrap_or("");
            if target.is_empty() {
                return tool_error(id, "delete_function", "target required", recovery_for("delete_function", "target required"));
            }
            let t = target.to_string();
            bridge_tool(
                id, "delete_function", cached_client, default_project, default_program, projects_dir, true,
                move |client| client.send_command("delete_function", Some(json!({"target": t}))),
                Some(target),
            )
        }
        "function_set_signature" => {
            let target = args.get("target").and_then(|v| v.as_str()).unwrap_or("");
            let sig = args.get("signature").and_then(|v| v.as_str()).unwrap_or("");
            if target.is_empty() || sig.is_empty() {
                return tool_error(id, "function_set_signature", "target and signature required", recovery_for("function_set_signature", "missing fields"));
            }
            let t = target.to_string();
            let s = sig.to_string();
            bridge_tool(
                id, "function_set_signature", cached_client, default_project, default_program, projects_dir, true,
                move |client| client.send_command("function_set_signature", Some(json!({"target": t, "signature": s}))),
                Some(target),
            )
        }
        "function_set_return_type" => {
            let target = args.get("target").and_then(|v| v.as_str()).unwrap_or("");
            let ty = args.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if target.is_empty() || ty.is_empty() {
                return tool_error(id, "function_set_return_type", "target and type required", recovery_for("function_set_return_type", "missing fields"));
            }
            let t = target.to_string();
            let ty = ty.to_string();
            bridge_tool(
                id, "function_set_return_type", cached_client, default_project, default_program, projects_dir, true,
                move |client| client.send_command("function_set_return_type", Some(json!({"target": t, "type": ty}))),
                Some(target),
            )
        }
        "function_set_calling_convention" => {
            let target = args.get("target").and_then(|v| v.as_str()).unwrap_or("");
            let conv = args.get("convention").and_then(|v| v.as_str()).unwrap_or("");
            if target.is_empty() || conv.is_empty() {
                return tool_error(id, "function_set_calling_convention", "target and convention required", recovery_for("function_set_calling_convention", "missing fields"));
            }
            let t = target.to_string();
            let c = conv.to_string();
            bridge_tool(
                id, "function_set_calling_convention", cached_client, default_project, default_program, projects_dir, true,
                move |client| client.send_command("function_set_calling_convention", Some(json!({"target": t, "convention": c}))),
                Some(target),
            )
        }
        "set_var_type" => {
            let function = args.get("function").and_then(|v| v.as_str()).unwrap_or("");
            let variable = args.get("variable").and_then(|v| v.as_str()).unwrap_or("");
            let ty = args.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if function.is_empty() || variable.is_empty() || ty.is_empty() {
                return tool_error(id, "set_var_type", "function, variable, and type required", recovery_for("set_var_type", "missing fields"));
            }
            let payload = json!({"function": function, "variable": variable, "type": ty});
            bridge_tool(
                id, "set_var_type", cached_client, default_project, default_program, projects_dir, true,
                move |client| client.send_command("set_var_type", Some(payload)),
                Some(function),
            )
        }
        "symbol_create" => {
            let address = args.get("address").and_then(|v| v.as_str()).unwrap_or("");
            let sym = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
            if address.is_empty() || sym.is_empty() {
                return tool_error(id, "symbol_create", "address and name required", recovery_for("symbol_create", "missing fields"));
            }
            let a = address.to_string();
            let n = sym.to_string();
            bridge_tool(
                id, "symbol_create", cached_client, default_project, default_program, projects_dir, true,
                move |client| client.symbol_create(&a, &n),
                Some(address),
            )
        }
        "symbol_delete" => {
            let sym = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
            if sym.is_empty() {
                return tool_error(id, "symbol_delete", "name required", recovery_for("symbol_delete", "name required"));
            }
            let n = sym.to_string();
            bridge_tool(
                id, "symbol_delete", cached_client, default_project, default_program, projects_dir, true,
                move |client| client.symbol_delete(&n),
                Some(sym),
            )
        }
        "symbol_rename" => {
            let old_name = args.get("old_name").and_then(|v| v.as_str()).unwrap_or("");
            let new_name = args.get("new_name").and_then(|v| v.as_str()).unwrap_or("");
            if old_name.is_empty() || new_name.is_empty() {
                return tool_error(id, "symbol_rename", "old_name and new_name required", recovery_for("symbol_rename", "missing fields"));
            }
            let o = old_name.to_string();
            let n = new_name.to_string();
            bridge_tool(
                id, "symbol_rename", cached_client, default_project, default_program, projects_dir, true,
                move |client| client.symbol_rename(&o, &n),
                Some(old_name),
            )
        }
        "comment_set" => {
            let address = args.get("address").and_then(|v| v.as_str()).unwrap_or("");
            let text = args.get("text").and_then(|v| v.as_str()).unwrap_or("");
            if address.is_empty() || text.is_empty() {
                return tool_error(id, "comment_set", "address and text required", recovery_for("comment_set", "missing fields"));
            }
            let ct = args.get("comment_type").and_then(|v| v.as_str());
            let a = address.to_string();
            let t = text.to_string();
            let ct_owned = ct.map(|s| s.to_string());
            bridge_tool(
                id, "comment_set", cached_client, default_project, default_program, projects_dir, true,
                move |client| client.comment_set(&a, &t, ct_owned.as_deref()),
                Some(address),
            )
        }
        "comment_delete" => {
            let address = args.get("address").and_then(|v| v.as_str()).unwrap_or("");
            if address.is_empty() {
                return tool_error(id, "comment_delete", "address required", recovery_for("comment_delete", "address required"));
            }
            let a = address.to_string();
            bridge_tool(
                id, "comment_delete", cached_client, default_project, default_program, projects_dir, true,
                move |client| client.comment_delete(&a),
                Some(address),
            )
        }
        "type_create" => {
            let definition = args.get("definition").and_then(|v| v.as_str()).unwrap_or("");
            if definition.is_empty() {
                return tool_error(id, "type_create", "definition required", recovery_for("type_create", "definition required"));
            }
            let d = definition.to_string();
            bridge_tool(
                id, "type_create", cached_client, default_project, default_program, projects_dir, true,
                move |client| client.type_create(&d),
                None,
            )
        }
        "type_apply" => {
            let address = args.get("address").and_then(|v| v.as_str()).unwrap_or("");
            let type_name = args.get("type_name").and_then(|v| v.as_str()).unwrap_or("");
            if address.is_empty() || type_name.is_empty() {
                return tool_error(id, "type_apply", "address and type_name required", recovery_for("type_apply", "missing fields"));
            }
            let a = address.to_string();
            let t = type_name.to_string();
            bridge_tool(
                id, "type_apply", cached_client, default_project, default_program, projects_dir, true,
                move |client| client.type_apply(&a, &t),
                Some(address),
            )
        }
        "type_delete" | "type_rename" | "type_create_enum" | "type_typedef" | "type_add_field" | "type_del_field" => {
            // Forward full args to bridge (same wire names as CLI).
            let payload = args.clone();
            let cmd = name.to_string();
            bridge_tool(
                id, name, cached_client, default_project, default_program, projects_dir, true,
                move |client| client.send_command(&cmd, Some(payload)),
                None,
            )
        }

        "batch" => {
            let cmds = args
                .get("commands")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let mut results = Vec::new();
            for (i, cmd) in cmds.iter().enumerate() {
                let cname = cmd.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let cargs = cmd.get("arguments").cloned().unwrap_or(json!({}));
                if cname.is_empty() {
                    results.push(json!({
                        "index": i,
                        "status": "error",
                        "message": "command name required",
                        "recovery_suggestions": recovery_for("batch", "name required")
                    }));
                    continue;
                }
                if cname == "batch" {
                    results.push(json!({
                        "index": i,
                        "name": cname,
                        "status": "error",
                        "message": "nested batch is not supported",
                        "recovery_suggestions": vec!["flatten commands into a single batch array"]
                    }));
                    continue;
                }
                let resp = dispatch_tool(
                    cname,
                    &cargs,
                    Some(json!(i)),
                    cached_client,
                    default_project.clone(),
                    default_program.clone(),
                    projects_dir.clone(),
                );
                let envelope = extract_envelope_from_rpc(&resp);
                let status = envelope
                    .get("status")
                    .and_then(|s| s.as_str())
                    .unwrap_or("error");
                results.push(json!({
                    "index": i,
                    "name": cname,
                    "status": status,
                    "envelope": envelope
                }));
            }
            let env = make_envelope(
                "batch",
                json!({"results": results, "count": cmds.len()}),
                default_project.as_deref(),
                default_program.as_deref(),
                compute_next_steps("batch", None),
                None,
            );
            wrap_envelope_as_content(env, id)
        }

        "diff_programs" => {
            let p1 = args.get("program1").and_then(|v| v.as_str()).unwrap_or("");
            let p2 = args.get("program2").and_then(|v| v.as_str()).unwrap_or("");
            if p1.is_empty() || p2.is_empty() {
                return tool_error(id, "diff_programs", "program1 and program2 required", recovery_for("diff_programs", "missing fields"));
            }
            let a = p1.to_string();
            let b = p2.to_string();
            bridge_tool(
                id, "diff_programs", cached_client, default_project, default_program, projects_dir, false,
                move |client| client.diff_programs(&a, &b),
                None,
            )
        }
        "diff_functions" => {
            let f1 = args.get("func1").and_then(|v| v.as_str()).unwrap_or("");
            let f2 = args.get("func2").and_then(|v| v.as_str()).unwrap_or("");
            if f1.is_empty() || f2.is_empty() {
                return tool_error(id, "diff_functions", "func1 and func2 required", recovery_for("diff_functions", "missing fields"));
            }
            let a = f1.to_string();
            let b = f2.to_string();
            bridge_tool(
                id, "diff_functions", cached_client, default_project, default_program, projects_dir, false,
                move |client| client.diff_functions(&a, &b),
                None,
            )
        }

        "summarize" => {
            let focus = args
                .get("focus")
                .and_then(|v| v.as_str())
                .unwrap_or("all")
                .to_string();
            match get_bridge_client(
                cached_client,
                default_project.clone(),
                default_program.clone(),
                projects_dir.clone(),
            ) {
                Ok((client, proj_name)) => match build_summarize_report(&client, &focus) {
                    Ok(data) => wrap_envelope_as_content(
                        make_envelope(
                            "summarize",
                            data,
                            Some(&proj_name),
                            default_program.as_deref(),
                            compute_next_steps("summarize", None),
                            None,
                        ),
                        id,
                    ),
                    Err(e) => tool_error(id, "summarize", &e.to_string(), recovery_for("summarize", &e.to_string())),
                },
                Err(e) => tool_error(
                    id,
                    "summarize",
                    &format!("No bridge: {}", e),
                    recovery_for("summarize", &e.to_string()),
                ),
            }
        }

        "pcode" => {
            let target = args.get("target").and_then(|v| v.as_str()).unwrap_or("");
            if target.is_empty() {
                return tool_error(id, "pcode", "target required", recovery_for("pcode", "target required"));
            }
            let limit = args.get("limit").and_then(|v| v.as_u64()).map(|n| n as usize);
            let t = target.to_string();
            bridge_tool(
                id, "pcode", cached_client, default_project, default_program, projects_dir, false,
                move |client| {
                    let mut payload = json!({"target": t});
                    if let Some(l) = limit {
                        payload["limit"] = json!(l);
                    }
                    client.send_command("pcode", Some(payload))
                },
                Some(target),
            )
        }

        "transaction_begin" => {
            let tname = args.get("name").and_then(|v| v.as_str()).unwrap_or("mcp");
            let n = tname.to_string();
            bridge_tool(
                id, "transaction_begin", cached_client, default_project, default_program, projects_dir, true,
                move |client| client.send_command("transaction_begin", Some(json!({"name": n}))),
                None,
            )
        }
        "transaction_commit" => bridge_tool(
            id, "transaction_commit", cached_client, default_project, default_program, projects_dir, true,
            |client| client.send_command("transaction_commit", None),
            None,
        ),
        "transaction_abort" => bridge_tool(
            id, "transaction_abort", cached_client, default_project, default_program, projects_dir, true,
            |client| client.send_command("transaction_abort", None),
            None,
        ),

        _ => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32601, "message": format!("Unknown tool: {}", name) }
        }),
    }
}

// ---------------------------------------------------------------------------
// Bridge helpers
// ---------------------------------------------------------------------------

fn require_str_then<F>(id: Option<Value>, command: &str, args: &Value, field: &str, f: F) -> Value
where
    F: FnOnce(Option<Value>, &str) -> Value,
{
    let v = args.get(field).and_then(|x| x.as_str()).unwrap_or("");
    if v.is_empty() {
        return tool_error(
            id,
            command,
            &format!("{} required", field),
            recovery_for(command, &format!("{} required", field)),
        );
    }
    f(id, v)
}

fn bridge_tool<F>(
    id: Option<Value>,
    command: &str,
    cached_client: &mut Option<(String, BridgeClient)>,
    default_project: Option<String>,
    default_program: Option<String>,
    projects_dir: Option<PathBuf>,
    is_mutation: bool,
    f: F,
    target: Option<&str>,
) -> Value
where
    F: FnOnce(&BridgeClient) -> anyhow::Result<Value>,
{
    match get_bridge_client(
        cached_client,
        default_project.clone(),
        default_program.clone(),
        projects_dir,
    ) {
        Ok((client, proj_name)) => match f(&client) {
            Ok(data) => {
                // Bridge may return {error: ...} in body for domain failures.
                if let Some(err) = data.get("error").and_then(|e| e.as_str()) {
                    let mut recovery = recovery_for(command, err);
                    if is_mutation {
                        recovery.extend(mutation_recovery(err));
                    }
                    return tool_error(id, command, err, recovery);
                }
                let artifacts = data.get("artifacts").cloned();
                let ns = compute_next_steps(command, target);
                wrap_envelope_as_content(
                    make_envelope(
                        command,
                        data,
                        Some(&proj_name),
                        default_program.as_deref(),
                        ns,
                        artifacts,
                    ),
                    id,
                )
            }
            Err(e) => {
                let msg = e.to_string();
                let mut recovery = recovery_for(command, &msg);
                if is_mutation {
                    recovery.extend(mutation_recovery(&msg));
                }
                tool_error(id, command, &msg, recovery)
            }
        },
        Err(e) => {
            let msg = format!("No bridge: {}", e);
            let mut recovery = recovery_for(command, &msg);
            if is_mutation {
                recovery.extend(mutation_recovery(&msg));
            }
            tool_error(id, command, &msg, recovery)
        }
    }
}

fn enrich_decompile(
    client: &BridgeClient,
    target: &str,
    max_xrefs: usize,
    caller_depth: usize,
) -> anyhow::Result<Value> {
    let mut base = client.decompile(target.to_string(), false, false)?;
    let addr = base
        .get("address")
        .and_then(|a| a.as_str())
        .unwrap_or(target)
        .to_string();

    // Guaranteed fields (even if empty) — item 2 / slice 1.2 contract.
    match client.xrefs_to(addr) {
        Ok(mut x) => {
            if let Some(arr) = x.get_mut("xrefs").and_then(|v| v.as_array_mut()) {
                if arr.len() > max_xrefs {
                    arr.truncate(max_xrefs);
                }
            }
            base["nearby_xrefs"] = x;
        }
        Err(_) => {
            base["nearby_xrefs"] = json!({"xrefs": [], "count": 0});
        }
    }
    match client.graph_callers(target, Some(caller_depth)) {
        Ok(c) => base["callers"] = c,
        Err(_) => base["callers"] = json!({"callers": [], "count": 0}),
    }
    match client.send_command("get_function", Some(json!({"address": target}))) {
        Ok(finfo) => {
            if let Some(ns) = finfo.get("namespace").or(finfo.get("parent_namespace")) {
                base["namespace"] = ns.clone();
            } else {
                base["namespace"] = json!("");
            }
        }
        Err(_) => {
            if base.get("namespace").is_none() {
                base["namespace"] = json!("");
            }
        }
    }
    if base.get("nearby_xrefs").is_none() {
        base["nearby_xrefs"] = json!({"xrefs": [], "count": 0});
    }
    if base.get("callers").is_none() {
        base["callers"] = json!({"callers": [], "count": 0});
    }
    if base.get("namespace").is_none() {
        base["namespace"] = json!("");
    }
    Ok(base)
}

/// High-level triage report assembled from existing bridge queries.
pub fn build_summarize_report(client: &BridgeClient, focus: &str) -> anyhow::Result<Value> {
    let focus = focus.to_lowercase();
    let want_all = focus == "all" || focus.is_empty();
    let mut sections = Map::new();

    if want_all || focus.contains("entry") || focus.contains("import") {
        if let Ok(info) = client.program_info() {
            sections.insert("program".into(), info);
        }
        if let Ok(imps) = client.list_imports() {
            sections.insert("imports".into(), imps);
        }
        if let Ok(exps) = client.list_exports() {
            sections.insert("exports".into(), exps);
        }
    }

    if want_all || focus.contains("crypto") {
        if let Ok(crypto) = client.find_crypto() {
            sections.insert("crypto".into(), crypto);
        }
    }

    if want_all || focus.contains("string") {
        if let Ok(interesting) = client.find_interesting() {
            sections.insert("interesting".into(), interesting);
        }
        if let Ok(strings) = client.list_strings(Some(20), None) {
            sections.insert("top_strings".into(), strings);
        }
    }

    if want_all || focus.contains("function") {
        if let Ok(funcs) = client.list_functions(Some(15), None) {
            sections.insert("top_functions".into(), funcs);
        }
        if let Ok(st) = client.stats() {
            sections.insert("stats".into(), st);
        }
    }

    Ok(assemble_summarize_report(&focus, sections))
}

/// Pure assembly of summarize report + confidence-tagged findings (unit-testable).
pub fn assemble_summarize_report(focus: &str, sections: Map<String, Value>) -> Value {
    let mut findings = Vec::new();

    if let Some(info) = sections.get("program") {
        if let Some(name) = info.get("name").or(info.get("program")).and_then(|v| v.as_str()) {
            findings.push(json!({
                "kind": "program",
                "summary": format!("program {}", name),
                "confidence": 1.0
            }));
        }
    }
    if let Some(imps) = sections.get("imports") {
        let count = imps
            .get("imports")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .or_else(|| imps.get("count").and_then(|c| c.as_u64()).map(|n| n as usize))
            .unwrap_or(0);
        findings.push(json!({
            "kind": "imports",
            "summary": format!("{} imports", count),
            "confidence": 0.9
        }));
    }
    if let Some(crypto) = sections.get("crypto") {
        let count = crypto
            .get("matches")
            .or(crypto.get("results"))
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        findings.push(json!({
            "kind": "crypto",
            "summary": format!("{} crypto-related hits", count),
            "confidence": if count > 0 { 0.75 } else { 0.4 }
        }));
    }
    if sections.contains_key("interesting") {
        findings.push(json!({
            "kind": "interesting",
            "summary": "interesting locations scanned",
            "confidence": 0.6
        }));
    }
    if let Some(funcs) = sections.get("top_functions") {
        let count = funcs
            .get("functions")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        if count > 0 {
            findings.push(json!({
                "kind": "functions",
                "summary": format!("{} sample functions", count),
                "confidence": 0.7
            }));
        }
    }

    json!({
        "focus": focus,
        "sections": Value::Object(sections),
        "findings": findings,
        "confidence_note": "Scores are heuristic tags for agent prioritization, not formal proofs."
    })
}

/// Promote script_run data.artifacts into the envelope artifacts[] slot.
pub fn envelope_with_script_artifacts(
    command: &str,
    data: Value,
    project: Option<&str>,
    program: Option<&str>,
    next_steps: Vec<String>,
) -> Value {
    let artifacts = data.get("artifacts").cloned();
    make_envelope(command, data, project, program, next_steps, artifacts)
}

fn get_bridge_client(
    cached: &mut Option<(String, BridgeClient)>,
    project: Option<String>,
    program: Option<String>,
    projects_dir: Option<PathBuf>,
) -> anyhow::Result<(BridgeClient, String)> {
    if let Some((ref name, ref client)) = *cached {
        if let Some(p) = &project {
            if name == p {
                return Ok((client.clone(), name.clone()));
            }
        } else {
            return Ok((client.clone(), name.clone()));
        }
    }

    let mut config = Config::load()?;
    if let Some(pd) = projects_dir {
        std::env::set_var("GHIDRA_CLI_PROJECTS_DIR", pd.to_string_lossy().to_string());
        config = Config::load()?;
    }

    let project_name = project
        .clone()
        .or_else(|| config.default_project.clone())
        .ok_or_else(|| anyhow::anyhow!("No project specified and no default project configured"))?;

    let project_path = if std::path::Path::new(&project_name).is_absolute() {
        std::path::PathBuf::from(&project_name)
    } else {
        let base = config.get_project_dir()?;
        base.join(&project_name)
    };

    let port = bridge::is_bridge_running(&project_path).ok_or_else(|| {
        anyhow::anyhow!("No bridge running for project: {}", project_path.display())
    })?;

    let client = BridgeClient::new(port);

    if let Some(prog) = program.clone().or_else(|| config.get_default_program()) {
        let _ = client.open_program(&prog);
    }

    cached.replace((project_name.clone(), client.clone()));
    Ok((client, project_name))
}

fn list_local_projects(projects_dir: Option<PathBuf>) -> Value {
    let dir = match projects_dir {
        Some(d) => d,
        None => {
            if let Ok(c) = Config::load() {
                if let Ok(d) = c.get_project_dir() {
                    d
                } else {
                    return json!({"projects": []});
                }
            } else {
                return json!({"projects": []});
            }
        }
    };
    let mut out = vec![];
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            if e.path().is_dir() {
                if let Some(name) = e.file_name().to_str() {
                    out.push(json!({"name": name}));
                }
            }
        }
    }
    json!({ "projects": out })
}

fn build_server_capabilities(
    cached_client: &mut Option<(String, BridgeClient)>,
    default_project: Option<String>,
    default_program: Option<String>,
    projects_dir: Option<PathBuf>,
) -> Value {
    let mut caps = json!({
        "cli_version": env!("CARGO_PKG_VERSION"),
        "tool_schema_version": TOOL_SCHEMA_VERSION,
        "transports": ["stdio", "http"],
        "features": {
            "job_queue": true,
            "cancellation": true,
            "script_run": true,
            "script_expect_artifacts": true,
            "batch": true,
            "mutations": true,
            "decompile_extra_context": true,
            "diff": true,
            "summarize": true,
            "pcode": true,
            "transactions": true
        },
        "bridge_connected": false,
        "ghidra_version": Value::Null,
        "binary_sha256": Value::Null
    });

    if let Ok((client, _proj)) = get_bridge_client(
        cached_client,
        default_project,
        default_program,
        projects_dir,
    ) {
        caps["bridge_connected"] = json!(true);
        if let Ok(info) = client.bridge_info() {
            if let Some(v) = info.get("ghidra_version").or(info.get("version")) {
                caps["ghidra_version"] = v.clone();
            }
            if let Some(feats) = info.get("capabilities") {
                caps["bridge_capabilities"] = feats.clone();
            }
        }
        if let Ok(pinfo) = client.program_info() {
            if let Some(h) = pinfo
                .get("sha256")
                .or(pinfo.get("binary_sha256"))
                .or(pinfo.get("md5"))
            {
                caps["binary_sha256"] = h.clone();
            }
            if let Some(v) = pinfo.get("ghidra_version") {
                caps["ghidra_version"] = v.clone();
            }
        }
    }
    caps
}

// ---------------------------------------------------------------------------
// Envelopes, next_steps, recovery
// ---------------------------------------------------------------------------

fn wrap_envelope_as_content(envelope: Value, id: Option<Value>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [ {
                "type": "text",
                "text": serde_json::to_string(&envelope).unwrap_or_else(|_| "{}".to_string())
            } ]
        }
    })
}

fn extract_envelope_from_rpc(resp: &Value) -> Value {
    if let Some(text) = resp
        .pointer("/result/content/0/text")
        .and_then(|t| t.as_str())
    {
        if let Ok(v) = serde_json::from_str::<Value>(text) {
            return v;
        }
    }
    if let Some(err) = resp.get("error") {
        return json!({
            "status": "error",
            "message": err.get("message").cloned().unwrap_or(json!("rpc error")),
            "recovery_suggestions": []
        });
    }
    json!({"status": "error", "message": "unrecognized response", "recovery_suggestions": []})
}

/// Domain error as a tools/call result with stable error envelope.
fn tool_error(id: Option<Value>, command: &str, message: &str, recovery: Vec<String>) -> Value {
    let env = make_error_envelope(command, message, recovery);
    wrap_envelope_as_content(env, id)
}

/// Public for unit tests: stable error envelope shape.
pub fn make_error_envelope(command: &str, message: &str, recovery: Vec<String>) -> Value {
    let now = chrono::Utc::now().to_rfc3339();
    json!({
        "status": "error",
        "command": command,
        "provenance": full_provenance(None, None),
        "message": message,
        "data": null,
        "next_steps": [],
        "recovery_suggestions": recovery,
        "artifacts": []
    }).as_object().map(|m| {
        let mut o = m.clone();
        o.insert("provenance".into(), full_provenance(None, None));
        // ensure timestamp is now (full_provenance already has it)
        let _ = now;
        Value::Object(o)
    }).unwrap_or_else(|| json!({
        "status": "error",
        "command": command,
        "message": message,
        "provenance": { "tool_version": env!("CARGO_PKG_VERSION"), "timestamp": now },
        "next_steps": [],
        "recovery_suggestions": recovery,
        "artifacts": []
    }))
}

fn make_ping_envelope() -> Value {
    let now = chrono::Utc::now().to_rfc3339();
    json!({
        "status": "success",
        "command": "mcp_ping",
        "provenance": {
            "tool_version": env!("CARGO_PKG_VERSION"),
            "timestamp": now,
            "project": null,
            "program": null,
            "binary_sha256": null,
            "ghidra_version": null
        },
        "data": { "message": "pong" },
        "next_steps": [
            "Use ghidra mcp stdio then call project_list / function_list after connecting a bridge."
        ],
        "recovery_suggestions": [],
        "artifacts": []
    })
}

fn full_provenance(project: Option<&str>, program: Option<&str>) -> Value {
    let now = chrono::Utc::now().to_rfc3339();
    json!({
        "tool_version": env!("CARGO_PKG_VERSION"),
        "timestamp": now,
        "project": project,
        "program": program,
        "binary_sha256": null,
        "ghidra_version": null
    })
}

/// Construct the standard envelope with provenance for every MCP response.
pub fn make_envelope(
    command: &str,
    data: Value,
    project: Option<&str>,
    program: Option<&str>,
    next_steps: Vec<String>,
    artifacts: Option<Value>,
) -> Value {
    let mut prov = full_provenance(project, program);
    // Lift hashes/versions from data when present.
    if let Some(obj) = prov.as_object_mut() {
        if let Some(h) = data
            .get("binary_sha256")
            .or(data.get("sha256"))
            .or(data.pointer("/program/sha256"))
        {
            obj.insert("binary_sha256".into(), h.clone());
        }
        if let Some(v) = data.get("ghidra_version").or(data.pointer("/program/ghidra_version")) {
            obj.insert("ghidra_version".into(), v.clone());
        }
    }
    json!({
        "status": "success",
        "command": command,
        "provenance": prov,
        "data": data,
        "next_steps": next_steps,
        "recovery_suggestions": [],
        "artifacts": artifacts.unwrap_or_else(|| json!([]))
    })
}

/// Actionable recovery suggestions for conflict / verification / bridge failures.
pub fn recovery_for(command: &str, message: &str) -> Vec<String> {
    let m = message.to_lowercase();
    let mut out = Vec::new();

    if m.contains("no bridge") || m.contains("not running") || m.contains("connection refused") {
        out.push("Start the bridge: `ghidra start --project <name>` (or import/analyze first).".into());
        out.push("Check `ghidra status --project <name>` and `ghidra doctor`.".into());
    }
    if m.contains("conflict") || m.contains("locked") || m.contains("busy") {
        out.push("Inspect `ghidra jobs` and wait for the active job, or cancel it.".into());
        out.push("Reopen the program in a fresh process and re-verify the invariant.".into());
    }
    if m.contains("verif") || m.contains("expect") || m.contains("artifact") {
        out.push("Inspect declared artifacts and paths; use allow_empty only when empty is valid.".into());
        out.push("Re-run with expect and confirm binary_sha256 / row counts in the manifest.".into());
    }
    if m.contains("transaction") || m.contains("undo") {
        out.push("Call transaction_abort to roll back, or transaction_commit if partial work is good.".into());
        out.push("Check the bridge transaction log if present in status.".into());
    }
    if m.contains("not found") || m.contains("unknown") {
        out.push(format!("Confirm the target exists via a list/get tool before retrying {}.", command));
    }
    if m.contains("required") || m.contains("missing") {
        out.push("Check the tool inputSchema from tools/list and supply required fields.".into());
    }
    if out.is_empty() {
        out.push("Retry after confirming project/program context and bridge health (`ping`).".into());
        out.push("If the failure persists, reopen in a fresh process and re-verify.".into());
    }
    out
}

fn mutation_recovery(message: &str) -> Vec<String> {
    let mut out = vec![
        "Mutations use the same job queue and transaction model as the CLI.".into(),
        "After a write, re-read the target (disasm/decompile/get) and, for durability, reopen in a fresh process.".into(),
    ];
    let m = message.to_lowercase();
    if m.contains("fail") || m.contains("error") {
        out.push("If verification failed, do not trust partial state; abort the transaction if one is open.".into());
    }
    out
}

fn compute_next_steps(command: &str, target: Option<&str>) -> Vec<String> {
    match command {
        "project_list" => vec![
            "function_list -- to explore functions".into(),
            "decompile main -- if main exists".into(),
        ],
        "function_list" => vec![
            "decompile <name-or-addr> -- decompile a specific function".into(),
            "xrefs_to <addr> -- find what references a location".into(),
        ],
        "decompile" => {
            let t = target.unwrap_or("<addr>");
            vec![
                format!("xrefs_to {} -- see callers and references", t),
                "graph_callers <name> -- explore call graph".into(),
            ]
        }
        "xrefs_to" => vec![
            "decompile <from_function> -- follow a reference to its function".into(),
            "function_list -- list more functions".into(),
        ],
        "strings_list" => vec![
            "find_string <pat> -- search for specific strings".into(),
            "xrefs_to <addr> -- follow a string reference".into(),
        ],
        "symbols_list" => vec!["xrefs_to <addr> -- find references to a symbol".into()],
        "memory_map" => vec!["xrefs_to or decompile to explore code in segments".into()],
        "types_list" => vec!["decompile or xrefs_to to see type usage".into()],
        "comments_list" => vec!["comment_get / set on specific addresses".into()],
        "find_string" => {
            let p = target.unwrap_or("<pat>");
            vec![
                format!("xrefs_to on a result address from find_string {}", p),
                "decompile nearby functions".into(),
            ]
        }
        "find_bytes" => vec!["xrefs_to or decompile near the match".into()],
        "find_function" => vec!["decompile <name> or graph_callers".into()],
        "find_calls" => vec!["decompile the caller or use graph".into()],
        "find_crypto" | "find_interesting" => vec!["decompile or xrefs_to on results".into()],
        "graph_calls" => vec!["graph_callers or graph_callees on a specific function".into()],
        "graph_callers" => vec!["decompile the caller".into()],
        "graph_callees" => vec!["decompile the callee".into()],
        "script_list" => vec!["script_run <path> (with expect) for execution".into()],
        "script_run" => vec!["review script output and artifacts".into()],
        "disasm" => vec!["xrefs_to or decompile near the address".into()],
        "patch_bytes" | "patch_nop" | "patch_export" => {
            vec!["disasm or xrefs_to to verify change; reopen fresh process for durability".into()]
        }
        "create_function" | "rename_function" | "delete_function" => {
            vec!["function_list or xrefs_to to verify".into()]
        }
        "function_set_signature"
        | "function_set_return_type"
        | "function_set_calling_convention"
        | "set_var_type" => vec!["decompile to verify signature/types".into()],
        "symbol_create" | "symbol_delete" | "symbol_rename" => {
            vec!["symbols_list or xrefs_to to verify".into()]
        }
        "comment_set" | "comment_delete" => vec!["comments_list to verify".into()],
        "type_create" | "type_apply" | "type_delete" | "type_rename" | "type_create_enum"
        | "type_typedef" | "type_add_field" | "type_del_field" => {
            vec!["types_list or decompile to verify".into()]
        }
        "batch" => vec!["inspect individual results".into()],
        "xrefs_from" => vec!["decompile or xrefs_to to explore references".into()],
        "list_imports" | "list_exports" => vec!["xrefs_to on an import/export address".into()],
        "program_info" => vec!["function_list or strings_list".into()],
        "stats" => vec!["program_info for context".into()],
        "diff_programs" | "diff_functions" => {
            vec!["review delta; transfer labels via rename/comment tools if needed".into()]
        }
        "summarize" => vec![
            "decompile high-confidence findings".into(),
            "xrefs_to on interesting addresses".into(),
        ],
        "pcode" => vec!["decompile for C view; use data-flow notes in pcode ops".into()],
        "transaction_begin" => vec!["run mutations, then transaction_commit or transaction_abort".into()],
        "transaction_commit" | "transaction_abort" => {
            vec!["verify state with decompile/list tools".into()]
        }
        "capabilities" => vec!["tools/list then call a focused tool".into()],
        _ => vec![],
    }
}

// ---------------------------------------------------------------------------
// HTTP transport
// ---------------------------------------------------------------------------

fn handle_http_connection(
    mut stream: TcpStream,
    cached_client: &mut Option<(String, BridgeClient)>,
    default_project: Option<String>,
    default_program: Option<String>,
    projects_dir: Option<PathBuf>,
    token: Option<&str>,
    loopback_only: bool,
) -> anyhow::Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(60)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(60)))?;

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    if request_line.is_empty() {
        return Ok(());
    }
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        write_http_response(&mut stream, 400, "text/plain", b"bad request")?;
        return Ok(());
    }
    let method = parts[0];
    let path = parts[1];

    let mut headers = Map::new();
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            if key == "content-length" {
                content_length = val.parse().unwrap_or(0);
            }
            headers.insert(key, json!(val));
        }
    }

    if let Some(expected) = token {
        let auth = headers
            .get("authorization")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let ok = auth == format!("Bearer {}", expected) || auth == expected;
        if !ok {
            write_http_response(&mut stream, 401, "application/json", br#"{"error":"unauthorized"}"#)?;
            return Ok(());
        }
    }

    // Localhost-only when bound to loopback; binding 0.0.0.0 opts into remote.
    if loopback_only {
        if let Ok(peer) = stream.peer_addr() {
            if !peer.ip().is_loopback() {
                write_http_response(
                    &mut stream,
                    403,
                    "application/json",
                    br#"{"error":"localhost only"}"#,
                )?;
                return Ok(());
            }
        }
    }

    match (method, path) {
        ("GET", "/health") | ("GET", "/healthz") => {
            write_http_response(&mut stream, 200, "application/json", br#"{"status":"ok"}"#)?;
        }
        ("GET", "/tools") | ("GET", "/mcp/tools") => {
            let body = serde_json::to_vec(&json!({"tools": tool_definitions()}))?;
            write_http_response(&mut stream, 200, "application/json", &body)?;
        }
        ("POST", "/") | ("POST", "/mcp") | ("POST", "/message") => {
            let mut body = vec![0u8; content_length.min(16 * 1024 * 1024)];
            if content_length > 0 {
                reader.read_exact(&mut body)?;
            } else {
                body.clear();
            }
            let req: Value = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(e) => {
                    let err = json!({
                        "jsonrpc": "2.0",
                        "id": null,
                        "error": {"code": -32700, "message": format!("Parse error: {}", e)}
                    });
                    let bytes = serde_json::to_vec(&err)?;
                    write_http_response(&mut stream, 200, "application/json", &bytes)?;
                    return Ok(());
                }
            };
            let resp = handle_request(
                &req,
                cached_client,
                default_project,
                default_program,
                projects_dir,
            );
            let bytes = serde_json::to_vec(&resp)?;
            write_http_response(&mut stream, 200, "application/json", &bytes)?;
        }
        ("OPTIONS", _) => {
            write_http_response(&mut stream, 204, "text/plain", b"")?;
        }
        _ => {
            write_http_response(
                &mut stream,
                404,
                "application/json",
                br#"{"error":"not found; POST JSON-RPC to /mcp or /"}"#,
            )?;
        }
    }
    Ok(())
}

fn write_http_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> anyhow::Result<()> {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Error",
    };
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n",
        status,
        reason,
        content_type,
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests (no Ghidra)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ping_envelope_has_required_fields() {
        let env = make_ping_envelope();
        assert_eq!(env["status"], "success");
        assert!(env["provenance"]["tool_version"].is_string());
        assert!(env["provenance"]["timestamp"].is_string());
        assert!(env["provenance"].get("binary_sha256").is_some());
        assert!(env["provenance"].get("ghidra_version").is_some());
        assert_eq!(env["data"]["message"], "pong");
        assert!(env.get("next_steps").is_some());
        assert!(env.get("recovery_suggestions").is_some());
    }

    #[test]
    fn tools_list_contains_ping_and_schema() {
        let req = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
        let mut cached: Option<(String, BridgeClient)> = None;
        let resp = handle_request(&req, &mut cached, None, None, None);
        let tools = &resp["result"]["tools"];
        assert!(tools.is_array());
        let ping_tool = tools
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t.get("name").and_then(|n| n.as_str()) == Some("ping"))
            .expect("ping tool must be listed");
        assert!(ping_tool.get("inputSchema").is_some());
        assert_eq!(ping_tool["inputSchema"]["type"], "object");
    }

    #[test]
    fn ping_tool_call_returns_envelope_text() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tools/call",
            "params": { "name": "ping" }
        });
        let mut cached: Option<(String, BridgeClient)> = None;
        let resp = handle_request(&req, &mut cached, None, None, None);
        let text = &resp["result"]["content"][0]["text"];
        assert!(text.is_string());
        let parsed: Value = serde_json::from_str(text.as_str().unwrap()).unwrap();
        assert_eq!(parsed["status"], "success");
        assert_eq!(parsed["command"], "mcp_ping");
    }

    #[test]
    fn project_list_without_bridge_returns_envelope_with_next_steps() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": { "name": "project_list", "arguments": {} }
        });
        let mut cached: Option<(String, BridgeClient)> = None;
        let resp = handle_request(&req, &mut cached, None, None, None);
        let content_text = resp["result"]["content"][0]["text"].as_str().expect("text");
        let env: Value = serde_json::from_str(content_text).expect("envelope json");
        assert_eq!(env["status"], "success");
        assert_eq!(env["command"], "project_list");
        assert!(env["provenance"].get("tool_version").is_some());
        assert!(env.get("next_steps").and_then(|v| v.as_array()).is_some());
    }

    #[test]
    fn tools_list_includes_all_slice13_tools() {
        let names = tool_names();
        for expected in [
            "strings_list",
            "symbols_list",
            "memory_map",
            "types_list",
            "comments_list",
            "find_string",
            "find_bytes",
            "find_function",
            "find_calls",
            "find_crypto",
            "find_interesting",
            "graph_calls",
            "graph_callers",
            "graph_callees",
        ] {
            assert!(names.contains(&expected), "missing tool in list: {}", expected);
        }
    }

    #[test]
    fn compute_next_steps_covers_new_commands() {
        assert!(!compute_next_steps("strings_list", None).is_empty());
        assert!(!compute_next_steps("symbols_list", None).is_empty());
        assert!(!compute_next_steps("memory_map", None).is_empty());
        assert!(!compute_next_steps("find_string", Some("pw")).is_empty());
        assert!(!compute_next_steps("graph_callers", Some("main")).is_empty());
        assert!(!compute_next_steps("graph_callees", Some("main")).is_empty());
        assert!(!compute_next_steps("script_list", None).is_empty());
        assert!(!compute_next_steps("script_run", Some("foo.py")).is_empty());
        assert!(!compute_next_steps("summarize", None).is_empty());
        assert!(!compute_next_steps("patch_bytes", Some("0x1000")).is_empty());
    }

    #[test]
    fn tools_list_includes_script_tools() {
        let names = tool_names();
        assert!(names.contains(&"script_list"));
        assert!(names.contains(&"script_run"));
    }

    #[test]
    fn tools_list_includes_mutation_and_batch_tools() {
        let names = tool_names();
        for t in [
            "create_function",
            "rename_function",
            "delete_function",
            "function_set_signature",
            "function_set_return_type",
            "function_set_calling_convention",
            "batch",
            "disasm",
            "patch_bytes",
            "patch_nop",
            "patch_export",
            "xrefs_from",
            "list_imports",
            "list_exports",
            "program_info",
            "stats",
            "symbol_create",
            "symbol_rename",
            "symbol_delete",
            "comment_set",
            "comment_delete",
            "type_create",
            "type_apply",
        ] {
            assert!(names.contains(&t), "missing {}", t);
        }
    }

    #[test]
    fn list_imports_without_bridge_returns_envelope() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 13,
            "method": "tools/call",
            "params": { "name": "list_imports", "arguments": {} }
        });
        let mut cached: Option<(String, BridgeClient)> = None;
        let resp = handle_request(&req, &mut cached, None, None, None);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        let env: Value = serde_json::from_str(text).unwrap();
        assert_eq!(env["status"], "success");
        assert_eq!(env["command"], "list_imports");
        assert!(env.get("next_steps").is_some());
    }

    #[test]
    fn stats_without_bridge_returns_envelope_with_next_steps() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 14,
            "method": "tools/call",
            "params": { "name": "stats", "arguments": {} }
        });
        let mut cached: Option<(String, BridgeClient)> = None;
        let resp = handle_request(&req, &mut cached, None, None, None);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        let env: Value = serde_json::from_str(text).unwrap();
        assert_eq!(env["status"], "success");
        assert_eq!(env["command"], "stats");
        assert!(env.get("next_steps").is_some());
    }

    #[test]
    fn mutation_error_envelope_has_recovery_and_provenance() {
        let env = make_error_envelope(
            "patch_bytes",
            "conflict: program locked by another job",
            recovery_for("patch_bytes", "conflict: program locked by another job"),
        );
        assert_eq!(env["status"], "error");
        assert_eq!(env["command"], "patch_bytes");
        let recovery = env["recovery_suggestions"].as_array().expect("recovery array");
        assert!(!recovery.is_empty(), "recovery_suggestions must be non-empty");
        let prov = &env["provenance"];
        assert!(prov.get("tool_version").is_some());
        assert!(prov.get("timestamp").is_some());
        assert!(prov.get("binary_sha256").is_some());
        assert!(prov.get("ghidra_version").is_some());
        assert!(prov.get("project").is_some());
        assert!(prov.get("program").is_some());
    }

    #[test]
    fn mutation_tool_missing_args_returns_envelope_with_recovery() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": { "name": "patch_bytes", "arguments": { "address": "0x1000" } }
        });
        let mut cached: Option<(String, BridgeClient)> = None;
        let resp = handle_request(&req, &mut cached, None, None, None);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        let env: Value = serde_json::from_str(text).unwrap();
        assert_eq!(env["status"], "error");
        assert_eq!(env["command"], "patch_bytes");
        let rec = env["recovery_suggestions"].as_array().unwrap();
        assert!(!rec.is_empty());
        assert!(env["provenance"]["tool_version"].is_string());
    }

    #[test]
    fn symbol_and_comment_mutations_listed() {
        let names = tool_names();
        assert!(names.contains(&"symbol_create"));
        assert!(names.contains(&"comment_set"));
        assert!(names.contains(&"type_delete"));
        assert!(names.contains(&"set_var_type"));
    }

    #[test]
    fn initialize_reports_capabilities_and_version() {
        let req = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}});
        let mut cached: Option<(String, BridgeClient)> = None;
        let resp = handle_request(&req, &mut cached, None, None, None);
        let result = &resp["result"];
        assert_eq!(result["serverInfo"]["name"], "ghidra-mcp");
        assert!(result["serverInfo"]["version"].as_str().unwrap().len() > 0);
        assert_eq!(result["serverInfo"]["schema_version"], TOOL_SCHEMA_VERSION);
        let caps = &result["ghidraCapabilities"];
        assert_eq!(caps["cli_version"], env!("CARGO_PKG_VERSION"));
        assert!(caps["features"]["mutations"].as_bool().unwrap());
        assert!(caps["features"]["job_queue"].as_bool().unwrap());
        assert!(caps["features"]["decompile_extra_context"].as_bool().unwrap());
        assert!(caps["transports"].as_array().unwrap().len() >= 2);
    }

    #[test]
    fn batch_without_bridge_returns_per_command_status() {
        // ping works offline; unknown still errors per item
        let req = json!({
            "jsonrpc": "2.0",
            "id": 50,
            "method": "tools/call",
            "params": {
                "name": "batch",
                "arguments": {
                    "commands": [
                        {"name": "ping", "arguments": {}},
                        {"name": "patch_bytes", "arguments": {}}
                    ]
                }
            }
        });
        let mut cached: Option<(String, BridgeClient)> = None;
        let resp = handle_request(&req, &mut cached, None, None, None);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        let env: Value = serde_json::from_str(text).unwrap();
        assert_eq!(env["status"], "success");
        assert_eq!(env["command"], "batch");
        let results = env["data"]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["status"], "success");
        assert_eq!(results[0]["name"], "ping");
        assert_eq!(results[1]["status"], "error");
        assert!(results[1]["envelope"]["recovery_suggestions"].as_array().unwrap().len() > 0);
    }

    #[test]
    fn tool_definitions_shared_registry_stable() {
        let a = tool_definitions();
        let b = tool_definitions();
        assert_eq!(a, b);
        let names = tool_names();
        assert!(names.contains(&"diff_programs"));
        assert!(names.contains(&"summarize"));
        assert!(names.contains(&"pcode"));
        assert!(names.contains(&"transaction_begin"));
        assert!(names.contains(&"capabilities"));
    }

    #[test]
    fn http_handler_tools_list_equivalence() {
        // Same handle_request used by HTTP path
        let req = json!({"jsonrpc":"2.0","id":1,"method":"tools/list"});
        let mut cached: Option<(String, BridgeClient)> = None;
        let resp = handle_request(&req, &mut cached, None, None, None);
        let tools = resp["result"]["tools"].as_array().unwrap();
        let from_def = tool_definitions().as_array().unwrap().clone();
        assert_eq!(tools.len(), from_def.len());
        for (t, d) in tools.iter().zip(from_def.iter()) {
            assert_eq!(t["name"], d["name"]);
            assert_eq!(t["inputSchema"], d["inputSchema"]);
        }
    }

    #[test]
    fn http_bind_ephemeral_and_tools_list() {
        use std::io::Write as _;
        use std::net::TcpStream;
        use std::thread;
        use std::time::Duration;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let listen = addr.to_string();
        let handle = thread::spawn(move || {
            // Re-bind inside server; race possible so use a channel-like retry via run that binds itself.
            let _ = run_http_server(&listen, None, None, None, None);
        });

        // The above is racy because we dropped the port. Instead test handler in-process:
        let _ = handle; // abandon racy test path
        // In-process: bind real server on 0 and POST
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let listen_str = format!("{}", addr);
        // Use a dedicated port by binding inside thread with port 0 and writing to a file
        let port_file = std::env::temp_dir().join(format!("ghidra-mcp-test-port-{}", std::process::id()));
        let port_file2 = port_file.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let thr = thread::spawn(move || {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let a = listener.local_addr().unwrap();
            std::fs::write(&port_file2, format!("{}", a.port())).unwrap();
            listener.set_nonblocking(false).ok();
            let mut cached: Option<(String, BridgeClient)> = None;
            // Accept a few connections then exit when stop set or after idle
            listener.set_nonblocking(true).ok();
            for _ in 0..200 {
                if stop2.load(Ordering::SeqCst) {
                    break;
                }
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = handle_http_connection(
                            stream,
                            &mut cached,
                            None,
                            None,
                            None,
                            None,
                            true,
                        );
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });

        // wait for port file
        let mut port = 0u16;
        for _ in 0..50 {
            if let Ok(s) = std::fs::read_to_string(&port_file) {
                if let Ok(p) = s.trim().parse() {
                    port = p;
                    break;
                }
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert!(port > 0, "server did not publish port");

        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        let req = format!(
            "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(req.as_bytes()).unwrap();
        stream.write_all(body).unwrap();
        let mut resp = String::new();
        let mut reader = BufReader::new(stream);
        reader.read_to_string(&mut resp).ok();
        assert!(resp.contains("HTTP/1.1 200"), "resp={}", resp);
        assert!(resp.contains("\"tools\""), "resp={}", resp);
        assert!(resp.contains("ping"), "resp={}", resp);
        // envelope keys present via tools/list schema path
        assert!(resp.contains("patch_bytes"));

        stop.store(true, Ordering::SeqCst);
        let _ = thr.join();
        let _ = std::fs::remove_file(port_file);
        let _ = listen_str;
    }

    #[test]
    fn recovery_for_conflict_is_actionable() {
        let r = recovery_for("rename_function", "conflict: verification failed on expect");
        assert!(r.len() >= 2);
        let joined = r.join(" ");
        assert!(
            joined.to_lowercase().contains("fresh")
                || joined.to_lowercase().contains("artifact")
                || joined.to_lowercase().contains("job")
        );
    }

    #[test]
    fn script_run_expect_elevates_artifacts_onto_envelope() {
        // Simulate bridge data after validateArtifacts: artifacts with path + sha256.
        let data = json!({
            "script": "export.py",
            "stdout": "ok",
            "artifacts": [
                {
                    "path": "/tmp/out.csv",
                    "sha256": "abc123def456",
                    "rows": 3,
                    "binary_sha256": "deadbeef",
                    "exists": true
                }
            ]
        });
        let env = envelope_with_script_artifacts(
            "script_run",
            data.clone(),
            Some("proj"),
            Some("prog"),
            vec!["review artifacts".into()],
        );
        assert_eq!(env["status"], "success");
        assert_eq!(env["command"], "script_run");
        let arts = env["artifacts"].as_array().expect("artifacts array");
        assert_eq!(arts.len(), 1);
        assert_eq!(arts[0]["path"], "/tmp/out.csv");
        assert_eq!(arts[0]["sha256"], "abc123def456");
        assert!(arts[0].get("binary_sha256").is_some() || arts[0].get("rows").is_some());
        // Provenance keys always present
        assert!(env["provenance"]["tool_version"].is_string());
        assert!(env["provenance"]["timestamp"].is_string());
        assert_eq!(env["provenance"]["project"], "proj");
        // data still carries the same artifacts for nested consumers
        assert_eq!(env["data"]["artifacts"][0]["path"], "/tmp/out.csv");
    }

    #[test]
    fn assemble_summarize_report_tags_confidence() {
        let mut sections = Map::new();
        sections.insert(
            "program".into(),
            json!({"name": "sample_binary", "language": "x86"}),
        );
        sections.insert(
            "imports".into(),
            json!({"imports": [{"name": "printf"}, {"name": "malloc"}], "count": 2}),
        );
        sections.insert(
            "crypto".into(),
            json!({"matches": [{"const": "AES"}], "results": [{"const": "AES"}]}),
        );
        sections.insert("interesting".into(), json!({"hits": []}));
        sections.insert(
            "top_functions".into(),
            json!({"functions": [{"name": "main"}, {"name": "foo"}]}),
        );
        let report = assemble_summarize_report("all", sections);
        assert_eq!(report["focus"], "all");
        let findings = report["findings"].as_array().expect("findings");
        assert!(!findings.is_empty());
        let kinds: Vec<_> = findings
            .iter()
            .filter_map(|f| f.get("kind").and_then(|k| k.as_str()))
            .collect();
        assert!(kinds.contains(&"program"));
        assert!(kinds.contains(&"imports"));
        assert!(kinds.contains(&"crypto"));
        for f in findings {
            let conf = f["confidence"].as_f64().expect("confidence number");
            assert!((0.0..=1.0).contains(&conf), "confidence out of range: {}", conf);
        }
        // crypto with hits should be higher confidence than empty
        let crypto = findings.iter().find(|f| f["kind"] == "crypto").unwrap();
        assert!(crypto["confidence"].as_f64().unwrap() >= 0.75);
    }

    #[test]
    fn tools_list_includes_summarize_pcode_transaction() {
        let names = tool_names_owned();
        for t in [
            "summarize",
            "pcode",
            "transaction_begin",
            "transaction_commit",
            "transaction_abort",
            "diff_programs",
            "diff_functions",
        ] {
            assert!(names.iter().any(|n| n == t), "missing tool {}", t);
        }
    }

    #[test]
    fn transaction_and_pcode_without_bridge_return_recovery_envelope() {
        for (name, args) in [
            ("pcode", json!({"target": "main"})),
            ("transaction_begin", json!({"name": "t1"})),
            ("transaction_commit", json!({})),
            ("transaction_abort", json!({})),
            ("summarize", json!({"focus": "crypto"})),
        ] {
            let req = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": name, "arguments": args }
            });
            let mut cached: Option<(String, BridgeClient)> = None;
            let resp = handle_request(&req, &mut cached, None, None, None);
            let text = resp["result"]["content"][0]["text"].as_str().expect("text");
            let env: Value = serde_json::from_str(text).unwrap();
            assert_eq!(env["status"], "error", "tool {}", name);
            assert_eq!(env["command"], name);
            let rec = env["recovery_suggestions"].as_array().unwrap();
            assert!(!rec.is_empty(), "recovery empty for {}", name);
            assert!(env["provenance"]["tool_version"].is_string());
        }
    }

    fn tool_names() -> Vec<&'static str> {
        // static names from definitions for convenience
        let defs = tool_definitions();
        // leak is fine in tests; convert owned strings
        // Actually return owned via thread-local pattern — use String and map in callers
        // Simpler: reimplement as Vec<String> and adjust tests... keep helper returning Vec<String>
        let _ = defs;
        tool_names_owned().iter().map(|s| {
            // cannot return &str from owned easily without leak:
            Box::leak(s.clone().into_boxed_str()) as &'static str
        }).collect()
    }

    fn tool_names_owned() -> Vec<String> {
        tool_definitions()
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(|s| s.to_string()))
            .collect()
    }
}
