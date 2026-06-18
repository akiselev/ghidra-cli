use crate::error::{GhidraError, Result};
use comfy_table::{presets::UTF8_FULL, Table};
use serde::Serialize;
use serde_json::Value as JsonValue;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Full,
    Compact,
    Minimal,
    Json,
    JsonCompact,
    JsonStream,
    Csv,
    Tsv,
    Table,
    Ids,
    Count,
    Tree,
    Hex,
    Asm,
    C,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "full" => Ok(Self::Full),
            "compact" => Ok(Self::Compact),
            "minimal" => Ok(Self::Minimal),
            "json" => Ok(Self::Json),
            "json-compact" => Ok(Self::JsonCompact),
            "json-stream" | "ndjson" => Ok(Self::JsonStream),
            "csv" => Ok(Self::Csv),
            "tsv" => Ok(Self::Tsv),
            "table" => Ok(Self::Table),
            "ids" => Ok(Self::Ids),
            "count" => Ok(Self::Count),
            "tree" => Ok(Self::Tree),
            "hex" => Ok(Self::Hex),
            "asm" => Ok(Self::Asm),
            "c" => Ok(Self::C),
            _ => Err(GhidraError::InvalidFormat(format!("Unknown format: {}", s))),
        }
    }
}

pub trait Formatter {
    fn format<T: Serialize>(&self, data: &[T], format: OutputFormat) -> Result<String>;
}

pub struct DefaultFormatter;

impl Formatter for DefaultFormatter {
    fn format<T: Serialize>(&self, data: &[T], format: OutputFormat) -> Result<String> {
        match format {
            OutputFormat::Json => serde_json::to_string_pretty(data).map_err(|e| e.into()),
            OutputFormat::JsonCompact => serde_json::to_string(data).map_err(|e| e.into()),
            OutputFormat::JsonStream => {
                let mut result = String::new();
                for item in data {
                    let json = serde_json::to_string(item)?;
                    result.push_str(&json);
                    result.push('\n');
                }
                Ok(result)
            }
            OutputFormat::Count => Ok(format!("{}", data.len())),
            OutputFormat::Table => format_table(data),
            OutputFormat::Csv => format_csv(data, ','),
            OutputFormat::Tsv => format_csv(data, '\t'),
            OutputFormat::Compact => format_compact(data),
            OutputFormat::Full => format_full(data),
            OutputFormat::Minimal | OutputFormat::Ids => format_minimal(data),
            _ => {
                // For other formats, default to JSON
                serde_json::to_string_pretty(data).map_err(|e| e.into())
            }
        }
    }
}

fn format_table<T: Serialize>(data: &[T]) -> Result<String> {
    if data.is_empty() {
        return Ok("No results".to_string());
    }

    // Convert to JSON values to inspect structure
    let json_data: Vec<JsonValue> = data
        .iter()
        .map(serde_json::to_value)
        .collect::<std::result::Result<Vec<_>, _>>()?;

    if json_data.is_empty() {
        return Ok("No results".to_string());
    }

    // Get all keys from first object
    let keys = if let Some(JsonValue::Object(map)) = json_data.first() {
        map.keys().cloned().collect::<Vec<_>>()
    } else {
        return Ok(format!("{} results", data.len()));
    };

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);

    // Add header
    table.set_header(&keys);

    // Add rows
    for item in &json_data {
        if let JsonValue::Object(map) = item {
            let row: Vec<String> = keys
                .iter()
                .map(|k| {
                    map.get(k)
                        .map(format_json_value)
                        .unwrap_or_else(|| "".to_string())
                })
                .collect();
            table.add_row(row);
        }
    }

    Ok(table.to_string())
}

fn format_csv<T: Serialize>(data: &[T], delimiter: char) -> Result<String> {
    if data.is_empty() {
        return Ok(String::new());
    }

    let json_data: Vec<JsonValue> = data
        .iter()
        .map(serde_json::to_value)
        .collect::<std::result::Result<Vec<_>, _>>()?;

    if json_data.is_empty() {
        return Ok(String::new());
    }

    let keys = if let Some(JsonValue::Object(map)) = json_data.first() {
        map.keys().cloned().collect::<Vec<_>>()
    } else {
        return Ok(String::new());
    };

    let mut result = String::new();

    // Header
    result.push_str(&keys.join(&delimiter.to_string()));
    result.push('\n');

    // Rows
    for item in &json_data {
        if let JsonValue::Object(map) = item {
            let row: Vec<String> = keys
                .iter()
                .map(|k| {
                    map.get(k)
                        .map(format_json_value)
                        .unwrap_or_else(|| "".to_string())
                })
                .collect();
            result.push_str(&row.join(&delimiter.to_string()));
            result.push('\n');
        }
    }

    Ok(result)
}

/// Compact human-readable format: one line per item with key fields.
fn format_compact<T: Serialize>(data: &[T]) -> Result<String> {
    let json_data: Vec<JsonValue> = data
        .iter()
        .map(serde_json::to_value)
        .collect::<std::result::Result<Vec<_>, _>>()?;

    if json_data.is_empty() {
        return Ok("No results".to_string());
    }

    let mut result = String::new();

    for item in &json_data {
        match item {
            JsonValue::Object(map) => {
                // Special case: decompile response with "code" key
                if let Some(code) = map.get("code").and_then(|v| v.as_str()) {
                    if let Some(sig) = map.get("signature").and_then(|v| v.as_str()) {
                        result.push_str(sig);
                        result.push('\n');
                    }
                    result.push_str(code);
                    if !code.ends_with('\n') {
                        result.push('\n');
                    }
                    continue;
                }

                // Special case: disasm instruction with mnemonic
                if let (Some(addr), Some(mnem)) = (
                    map.get("address").and_then(|v| v.as_str()),
                    map.get("mnemonic").and_then(|v| v.as_str()),
                ) {
                    let bytes = map.get("bytes").and_then(|v| v.as_str()).unwrap_or("");
                    let operands = match map.get("operands") {
                        Some(JsonValue::Array(ops)) => ops
                            .iter()
                            .map(format_json_value)
                            .collect::<Vec<_>>()
                            .join(", "),
                        _ => String::new(),
                    };
                    result.push_str(&format!(
                        "{:<12} {:<16} {} {}\n",
                        addr, bytes, mnem, operands
                    ));
                    continue;
                }

                // General object: render primary fields in a compact line
                let address = map.get("address").and_then(|v| v.as_str());
                let name = map.get("name").and_then(|v| v.as_str());
                let size = map.get("size").and_then(|v| v.as_u64());
                let value_str = map.get("value").and_then(|v| v.as_str());

                // Build compact line from available fields
                let mut parts: Vec<String> = Vec::new();

                if let Some(addr) = address {
                    parts.push(addr.to_string());
                }
                if let Some(n) = name {
                    parts.push(n.to_string());
                }
                if let Some(s) = size {
                    parts.push(format!("({})", s));
                }
                if let Some(v) = value_str {
                    // Truncate long strings
                    if v.len() > 80 {
                        parts.push(format!("\"{}...\"", &v[..77]));
                    } else {
                        parts.push(format!("\"{}\"", v));
                    }
                }

                // If we only have unknown fields, render as key=value pairs
                if parts.is_empty() {
                    let kv: Vec<String> = map
                        .iter()
                        .map(|(k, v)| format!("{}={}", k, format_json_value(v)))
                        .collect();
                    result.push_str(&kv.join("  "));
                } else {
                    result.push_str(&parts.join("  "));
                }

                // Add extra context from secondary fields
                let secondary: Vec<String> = map
                    .iter()
                    .filter(|(k, _)| {
                        !matches!(
                            k.as_str(),
                            "address"
                                | "name"
                                | "size"
                                | "value"
                                | "mnemonic"
                                | "bytes"
                                | "operands"
                                | "code"
                                | "signature"
                        )
                    })
                    .filter_map(|(k, v)| {
                        let s = format_json_value(v);
                        if s.is_empty() || s == "null" || s == "\"\"" {
                            None
                        } else {
                            Some(format!("{}={}", k, s))
                        }
                    })
                    .collect();

                if !secondary.is_empty() {
                    result.push_str("  ");
                    result.push_str(&secondary.join("  "));
                }

                result.push('\n');
            }
            _ => {
                result.push_str(&format_json_value(item));
                result.push('\n');
            }
        }
    }

    Ok(result)
}

/// Full human-readable format: multi-line labeled blocks per item.
fn format_full<T: Serialize>(data: &[T]) -> Result<String> {
    let json_data: Vec<JsonValue> = data
        .iter()
        .map(serde_json::to_value)
        .collect::<std::result::Result<Vec<_>, _>>()?;

    if json_data.is_empty() {
        return Ok("No results".to_string());
    }

    let mut result = String::new();

    for (i, item) in json_data.iter().enumerate() {
        if i > 0 {
            result.push_str("---\n");
        }

        match item {
            JsonValue::Object(map) => {
                // Special case: decompile response
                if let Some(code) = map.get("code").and_then(|v| v.as_str()) {
                    if let Some(sig) = map.get("signature").and_then(|v| v.as_str()) {
                        result.push_str(&format!("Signature: {}\n", sig));
                    }
                    if let Some(name) = map.get("name").and_then(|v| v.as_str()) {
                        result.push_str(&format!("Function:  {}\n", name));
                    }
                    result.push('\n');
                    result.push_str(code);
                    if !code.ends_with('\n') {
                        result.push('\n');
                    }
                    if let Some(JsonValue::Array(params)) = map.get("params") {
                        if !params.is_empty() {
                            result.push_str("\nParameters:\n");
                            for p in params {
                                if let JsonValue::Object(obj) = p {
                                    let name =
                                        obj.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                                    let typ =
                                        obj.get("type").and_then(|v| v.as_str()).unwrap_or("?");
                                    let storage =
                                        obj.get("storage").and_then(|v| v.as_str()).unwrap_or("?");
                                    result.push_str(&format!("  {} {} ({})\n", typ, name, storage));
                                }
                            }
                        }
                    }
                    if let Some(JsonValue::Array(vars)) = map.get("variables") {
                        if !vars.is_empty() {
                            result.push_str("\nVariables:\n");
                            for v in vars {
                                if let JsonValue::Object(obj) = v {
                                    let name =
                                        obj.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                                    let typ =
                                        obj.get("type").and_then(|v| v.as_str()).unwrap_or("?");
                                    let storage =
                                        obj.get("storage").and_then(|v| v.as_str()).unwrap_or("?");
                                    result.push_str(&format!("  {} {} ({})\n", typ, name, storage));
                                }
                            }
                        }
                    }
                    continue;
                }

                // Calculate max key width for alignment
                let max_key = map.keys().map(|k| k.len()).max().unwrap_or(0);

                for (key, val) in map {
                    let formatted = format_json_value(val);
                    result.push_str(&format!(
                        "{:width$}  {}\n",
                        format!("{}:", key),
                        formatted,
                        width = max_key + 1
                    ));
                }
            }
            _ => {
                result.push_str(&format_json_value(item));
                result.push('\n');
            }
        }
    }

    Ok(result)
}

fn format_minimal<T: Serialize>(data: &[T]) -> Result<String> {
    let json_data: Vec<JsonValue> = data
        .iter()
        .map(serde_json::to_value)
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let mut result = String::new();

    for item in &json_data {
        if let JsonValue::Object(map) = item {
            // Try to get address or name or first field
            let value = map
                .get("address")
                .or_else(|| map.get("name"))
                .or_else(|| map.get("id"))
                .or_else(|| map.values().next())
                .map(format_json_value)
                .unwrap_or_else(|| "".to_string());

            result.push_str(&value);
            result.push('\n');
        } else {
            result.push_str(&format_json_value(item));
            result.push('\n');
        }
    }

    Ok(result)
}

fn format_json_value(value: &JsonValue) -> String {
    match value {
        JsonValue::Null => "null".to_string(),
        JsonValue::Bool(b) => b.to_string(),
        JsonValue::Number(n) => n.to_string(),
        JsonValue::String(s) => s.clone(),
        JsonValue::Array(arr) => {
            format!(
                "[{}]",
                arr.iter()
                    .map(format_json_value)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
        JsonValue::Object(_) => serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string()),
    }
}

pub fn auto_detect_format(is_tty: bool) -> OutputFormat {
    if is_tty {
        OutputFormat::Compact
    } else {
        OutputFormat::JsonCompact
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_format_json() {
        let data = vec![json!({"name": "test", "value": 123})];
        let formatter = DefaultFormatter;
        let result = formatter.format(&data, OutputFormat::Json).unwrap();
        assert!(result.contains("test"));
    }

    #[test]
    fn test_format_count() {
        let data = vec![json!({"name": "test1"}), json!({"name": "test2"})];
        let formatter = DefaultFormatter;
        let result = formatter.format(&data, OutputFormat::Count).unwrap();
        assert_eq!(result, "2");
    }
}
