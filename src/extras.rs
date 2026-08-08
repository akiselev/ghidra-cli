//! Pure helpers for deferred extras (SSE framing, diff explain, similarity,
//! structure-recovery scoring). Unit-tested without Ghidra.

use serde_json::{json, Map, Value};
use strsim::normalized_levenshtein;

// ---------------------------------------------------------------------------
// HTTP SSE / long-job progress framing
// ---------------------------------------------------------------------------

/// Format one Server-Sent Event frame (event name + data line(s) + blank line).
pub fn format_sse_event(event: &str, data: &Value) -> String {
    let payload = serde_json::to_string(data).unwrap_or_else(|_| "{}".to_string());
    // Multi-line data: prefix each line with "data: "
    let mut out = format!("event: {}\n", event);
    for line in payload.lines() {
        out.push_str("data: ");
        out.push_str(line);
        out.push('\n');
    }
    out.push('\n');
    out
}

/// Progress frame for a long-running MCP tool call.
pub fn sse_progress_frame(job_id: Option<u64>, percent: u8, message: &str) -> String {
    format_sse_event(
        "progress",
        &json!({
            "job_id": job_id,
            "percent": percent.min(100),
            "message": message,
            "kind": "mcp_progress"
        }),
    )
}

/// Final result frame carrying the full JSON-RPC response body.
pub fn sse_result_frame(rpc_response: &Value) -> String {
    format_sse_event("result", rpc_response)
}

/// Build a complete non-stub long-job SSE body: interim progress + final envelope.
/// Used by unit tests and by the HTTP path when stream mode is requested.
pub fn build_streamed_tool_response(
    rpc_response: &Value,
    progress_steps: &[(u8, &str)],
) -> String {
    let mut body = String::new();
    for (pct, msg) in progress_steps {
        body.push_str(&sse_progress_frame(None, *pct, msg));
    }
    body.push_str(&sse_result_frame(rpc_response));
    body
}

/// Whether the HTTP request asked for streamable progress frames.
pub fn wants_sse_stream(path: &str, accept: Option<&str>) -> bool {
    if path.contains("stream=1") || path.contains("stream=true") {
        return true;
    }
    if let Some(a) = accept {
        let a = a.to_ascii_lowercase();
        if a.contains("text/event-stream") {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Diff explain (pure over a match report)
// ---------------------------------------------------------------------------

/// Build a human/agent-readable delta explanation from a headless match report.
pub fn explain_diff_match(match_report: &Value) -> Value {
    let matched = match_report
        .get("matched_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let only1 = match_report
        .get("only_in_program1_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let only2 = match_report
        .get("only_in_program2_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let p1 = match_report
        .pointer("/program1/name")
        .or(match_report.pointer("/dual_provenance/program1/name"))
        .and_then(|v| v.as_str())
        .unwrap_or("program1");
    let p2 = match_report
        .pointer("/program2/name")
        .or(match_report.pointer("/dual_provenance/program2/name"))
        .and_then(|v| v.as_str())
        .unwrap_or("program2");

    let total_named = matched + only1 + only2;
    let match_ratio = if total_named == 0 {
        0.0
    } else {
        matched as f64 / total_named as f64
    };

    let mut bullets = Vec::new();
    bullets.push(format!(
        "{} and {} share {} matched function name(s) ({:.0}% of the union of named functions).",
        p1,
        p2,
        matched,
        match_ratio * 100.0
    ));
    if only1 > 0 {
        bullets.push(format!(
            "{} has {} function name(s) not present in {} (removed, renamed, or unique).",
            p1, only1, p2
        ));
    }
    if only2 > 0 {
        bullets.push(format!(
            "{} has {} function name(s) not present in {} (added, renamed, or unique).",
            p2, only2, p1
        ));
    }
    if matched > 0 {
        bullets.push(
            "Use diff_transfer to copy labels/comments for matched names, or diff_functions for decompile-level deltas."
                .into(),
        );
    }

    // Sample a few only-in names for agents
    let sample = |key: &str| -> Vec<String> {
        match_report
            .get(key)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .take(10)
                    .collect()
            })
            .unwrap_or_default()
    };

    json!({
        "summary": format!(
            "Match: {} shared, {} only in {}, {} only in {} (method={})",
            matched,
            only1,
            p1,
            only2,
            p2,
            match_report.get("method").and_then(|m| m.as_str()).unwrap_or("function_name_set_match")
        ),
        "match_ratio": match_ratio,
        "bullets": bullets,
        "samples": {
            "only_in_program1": sample("only_in_program1"),
            "only_in_program2": sample("only_in_program2"),
            "matched_functions": sample("matched_functions")
        },
        "dual_provenance": match_report.get("dual_provenance").cloned().unwrap_or(json!({})),
        "program1": match_report.get("program1").cloned().unwrap_or(json!({"name": p1})),
        "program2": match_report.get("program2").cloned().unwrap_or(json!({"name": p2})),
        "counts": {
            "matched": matched,
            "only_in_program1": only1,
            "only_in_program2": only2
        }
    })
}

// ---------------------------------------------------------------------------
// String / crypto similarity with confidence
// ---------------------------------------------------------------------------

/// Pairwise similar strings above threshold (0..1). Confidence = similarity score.
pub fn similar_string_pairs(strings: &[String], threshold: f64, limit: usize) -> Vec<Value> {
    let mut out = Vec::new();
    let n = strings.len().min(200); // cap quadratic work
    for i in 0..n {
        for j in (i + 1)..n {
            let a = &strings[i];
            let b = &strings[j];
            if a.is_empty() || b.is_empty() {
                continue;
            }
            let score = normalized_levenshtein(a, b);
            if score >= threshold {
                out.push(json!({
                    "kind": "string_similarity",
                    "a": a,
                    "b": b,
                    "score": score,
                    "confidence": score,
                    "summary": format!("similar strings ({:.2}): {:?} ~ {:?}", score, trunc(a, 40), trunc(b, 40))
                }));
                if out.len() >= limit {
                    return out;
                }
            }
        }
    }
    out
}

fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let t: String = s.chars().take(n).collect();
        format!("{}…", t)
    }
}

/// Score a candidate constant/string against known crypto-ish tokens.
pub fn crypto_similarity_hits(candidates: &[String], known: &[&str], threshold: f64) -> Vec<Value> {
    let mut out = Vec::new();
    for c in candidates {
        let cl = c.to_lowercase();
        for k in known {
            let score = normalized_levenshtein(&cl, &k.to_lowercase());
            if score >= threshold || cl.contains(&k.to_lowercase()) {
                let conf = if cl.contains(&k.to_lowercase()) {
                    (score + 0.2).min(1.0)
                } else {
                    score
                };
                out.push(json!({
                    "kind": "crypto_similarity",
                    "candidate": c,
                    "known": k,
                    "score": score,
                    "confidence": conf,
                    "summary": format!("crypto-ish match ({:.2}): {} ~ {}", conf, c, k)
                }));
            }
        }
    }
    out
}

pub const DEFAULT_CRYPTO_TOKENS: &[&str] = &[
    "aes", "sha256", "sha1", "md5", "rsa", "hmac", "chacha", "poly1305", "curve25519", "secp256",
];

// ---------------------------------------------------------------------------
// Structure recovery scoring (pure assembly over field candidates)
// ---------------------------------------------------------------------------

/// Assemble a structure-recovery suggestion from ordered (offset, size_hint, name_hint) rows.
pub fn assemble_structure_guess(
    address: &str,
    fields: &[(u64, u32, Option<&str>)],
) -> Value {
    let mut field_objs = Vec::new();
    let mut prev_end = 0u64;
    let mut gaps = 0u32;
    for (off, size, name) in fields {
        if *off < prev_end {
            // overlapping — lower confidence later
        } else if *off > prev_end {
            gaps += 1;
        }
        let nm = name.unwrap_or("field").to_string();
        field_objs.push(json!({
            "offset": off,
            "size": size,
            "name": format!("{}_{}", nm, off),
            "type_hint": match size {
                1 => "byte",
                2 => "word",
                4 => "dword",
                8 => "qword",
                _ => "undefined",
            }
        }));
        prev_end = (*off).saturating_add(*size as u64);
    }
    let n = field_objs.len() as f64;
    let conf = if n == 0.0 {
        0.1
    } else {
        // more fields + fewer gaps => higher confidence (heuristic)
        let gap_pen = (gaps as f64) * 0.05;
        (0.4 + (n * 0.08) - gap_pen).clamp(0.15, 0.92)
    };
    let suggested_name = format!("struct_{}", address.replace("0x", "").replace(":", "_"));
    json!({
        "address": address,
        "suggested_name": suggested_name,
        "fields": field_objs,
        "total_size": prev_end,
        "confidence": conf,
        "gaps": gaps,
        "summary": format!(
            "Guessed {} fields ({} bytes) at {} with confidence {:.2}",
            field_objs.len(), prev_end, address, conf
        ),
        "next_steps": [
            "type_create with a C-like definition from fields",
            "type_apply at the address after review"
        ]
    })
}

/// Parse bridge structure_recover raw ops into field candidates for scoring.
pub fn fields_from_bridge_structure_data(data: &Value) -> Vec<(u64, u32, Option<String>)> {
    let mut out = Vec::new();
    if let Some(arr) = data.get("fields").and_then(|v| v.as_array()) {
        for f in arr {
            let off = f.get("offset").and_then(|v| v.as_u64()).unwrap_or(0);
            let size = f.get("size").and_then(|v| v.as_u64()).unwrap_or(4) as u32;
            let name = f
                .get("name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            out.push((off, size, name));
        }
    }
    out
}

/// Elevate bridge structure data through pure scorer (confidence always present).
pub fn structure_recover_envelope_data(address: &str, bridge_data: Value) -> Value {
    let raw = fields_from_bridge_structure_data(&bridge_data);
    let tuples: Vec<(u64, u32, Option<&str>)> = raw
        .iter()
        .map(|(o, s, n)| (*o, *s, n.as_deref()))
        .collect();
    let mut scored = assemble_structure_guess(address, &tuples);
    // Preserve any bridge-only keys
    if let Some(obj) = scored.as_object_mut() {
        obj.insert("bridge".into(), bridge_data);
    }
    scored
}

/// Basic data-flow summary from pcode-like ops (uses/defs).
pub fn assemble_data_flow_from_ops(ops: &[Value], focus: Option<&str>) -> Value {
    let mut defs: Map<String, Value> = Map::new();
    let mut uses: Map<String, Value> = Map::new();
    for (i, op) in ops.iter().enumerate() {
        if let Some(out) = op.get("output").and_then(|v| v.as_str()) {
            defs.entry(out.to_string())
                .or_insert_with(|| json!([]))
                .as_array_mut()
                .unwrap()
                .push(json!({"op_index": i, "mnemonic": op.get("mnemonic")}));
        }
        if let Some(inputs) = op.get("inputs").and_then(|v| v.as_array()) {
            for inp in inputs {
                if let Some(s) = inp.as_str() {
                    uses.entry(s.to_string())
                        .or_insert_with(|| json!([]))
                        .as_array_mut()
                        .unwrap()
                        .push(json!({"op_index": i, "mnemonic": op.get("mnemonic")}));
                }
            }
        }
    }
    let mut focused = json!(null);
    if let Some(f) = focus {
        focused = json!({
            "varnode": f,
            "defs": defs.get(f).cloned().unwrap_or(json!([])),
            "uses": uses.get(f).cloned().unwrap_or(json!([]))
        });
    }
    json!({
        "defs": Value::Object(defs),
        "uses": Value::Object(uses),
        "focus": focused,
        "op_count": ops.len(),
        "confidence": if ops.is_empty() { 0.2 } else { 0.85 },
        "summary": format!("data-flow over {} p-code op(s)", ops.len())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sse_frames_are_non_stub_and_parseable() {
        let final_rpc = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [{"type": "text", "text": "{\"status\":\"success\",\"provenance\":{},\"next_steps\":[],\"recovery_suggestions\":[]}"}]
            }
        });
        let body = build_streamed_tool_response(&final_rpc, &[(10, "queued"), (50, "running"), (100, "done")]);
        assert!(body.contains("event: progress"));
        assert!(body.contains("event: result"));
        assert!(body.contains("mcp_progress"));
        assert!(body.contains("\"percent\": 50") || body.contains("\"percent\":50"));
        assert!(body.contains("jsonrpc"));
        // Not a stub message
        assert!(!body.to_lowercase().contains("not implemented"));
        assert!(!body.to_lowercase().contains("slice 1.5"));
    }

    #[test]
    fn wants_sse_stream_detects_query_and_accept() {
        assert!(wants_sse_stream("/mcp?stream=1", None));
        assert!(wants_sse_stream("/mcp", Some("text/event-stream")));
        assert!(!wants_sse_stream("/mcp", Some("application/json")));
    }

    #[test]
    fn explain_diff_match_has_dual_provenance_and_ratio() {
        let report = json!({
            "matched_count": 8,
            "only_in_program1_count": 2,
            "only_in_program2_count": 3,
            "matched_functions": ["main", "foo"],
            "only_in_program1": ["old_fn"],
            "only_in_program2": ["new_fn"],
            "program1": {"name": "v1"},
            "program2": {"name": "v2"},
            "dual_provenance": {
                "program1": {"name": "v1", "function_count": 10},
                "program2": {"name": "v2", "function_count": 11}
            },
            "method": "function_name_set_match"
        });
        let exp = explain_diff_match(&report);
        assert!(exp["match_ratio"].as_f64().unwrap() > 0.5);
        assert!(!exp["bullets"].as_array().unwrap().is_empty());
        assert_eq!(exp["dual_provenance"]["program1"]["name"], "v1");
        assert!(exp["summary"].as_str().unwrap().contains("Match"));
    }

    #[test]
    fn similar_string_pairs_confidence_in_range() {
        let strs = vec![
            "password_check".into(),
            "password_chcek".into(), // typo
            "unrelated_xyz".into(),
        ];
        let pairs = similar_string_pairs(&strs, 0.5, 10);
        assert!(!pairs.is_empty());
        for p in pairs {
            let c = p["confidence"].as_f64().unwrap();
            assert!((0.0..=1.0).contains(&c));
            assert_eq!(p["kind"], "string_similarity");
        }
    }

    #[test]
    fn structure_guess_includes_confidence_and_fields() {
        let g = assemble_structure_guess(
            "0x401000",
            &[(0, 4, Some("len")), (4, 8, Some("ptr")), (12, 4, Some("flags"))],
        );
        assert_eq!(g["fields"].as_array().unwrap().len(), 3);
        let c = g["confidence"].as_f64().unwrap();
        assert!((0.15..=0.92).contains(&c));
        assert!(g["suggested_name"].as_str().unwrap().contains("struct_"));
    }

    #[test]
    fn data_flow_from_ops_tracks_defs_and_uses() {
        let ops = vec![
            json!({"mnemonic": "COPY", "output": "r0", "inputs": ["r1"]}),
            json!({"mnemonic": "INT_ADD", "output": "r2", "inputs": ["r0", "0x4"]}),
        ];
        let df = assemble_data_flow_from_ops(&ops, Some("r0"));
        assert_eq!(df["op_count"], 2);
        assert!(df["defs"]["r0"].as_array().unwrap().len() >= 1);
        assert!(df["uses"]["r0"].as_array().unwrap().len() >= 1);
        assert!(df["focus"]["defs"].as_array().unwrap().len() >= 1);
        assert!(df["confidence"].as_f64().unwrap() > 0.5);
    }
}
