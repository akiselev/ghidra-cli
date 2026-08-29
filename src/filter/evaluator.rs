use super::{CompareOp, ExistenceCheck, FilterExpr, LogicalOp, StringOp, Value};
use crate::error::{GhidraError, Result};
use regex::RegexBuilder;
use serde_json::Value as JsonValue;

pub fn evaluate(expr: &FilterExpr, data: &JsonValue) -> Result<bool> {
    match expr {
        FilterExpr::Compare { field, op, value } => evaluate_compare(field, *op, value, data),
        FilterExpr::StringOp { field, op, value } => evaluate_string_op(field, *op, value, data),
        FilterExpr::Logical { op, exprs } => evaluate_logical(*op, exprs, data),
        FilterExpr::Not(inner) => Ok(!evaluate(inner, data)?),
        FilterExpr::Exists { field, check } => evaluate_exists(field, *check, data),
        FilterExpr::In { field, values } => evaluate_in(field, values, data),
    }
}

fn get_field_value<'a>(field: &str, data: &'a JsonValue) -> Option<&'a JsonValue> {
    let parts: Vec<&str> = field.split('.').collect();
    let mut current = data;

    for part in parts {
        // Check for array index like "field[0]"
        if let Some(bracket_pos) = part.find('[') {
            let field_name = &part[..bracket_pos];
            let index_str = &part[bracket_pos + 1..part.len() - 1];

            current = current.get(field_name)?;

            if let Ok(index) = index_str.parse::<usize>() {
                current = current.get(index)?;
            } else {
                return None;
            }
        } else {
            current = current.get(part)?;
        }
    }

    Some(current)
}

fn evaluate_compare(field: &str, op: CompareOp, value: &Value, data: &JsonValue) -> Result<bool> {
    let field_value = get_field_value(field, data);

    if field_value.is_none() {
        return Ok(false);
    }

    let field_value = field_value.unwrap();

    match (field_value, value) {
        (JsonValue::Number(n), val) => {
            let field_num = n.as_f64().unwrap();
            let compare_num = val.as_f64().ok_or_else(|| {
                GhidraError::InvalidFilter(format!("Cannot compare number with {:?}", val))
            })?;

            Ok(match op {
                CompareOp::Equal => (field_num - compare_num).abs() < f64::EPSILON,
                CompareOp::NotEqual => (field_num - compare_num).abs() >= f64::EPSILON,
                CompareOp::Greater => field_num > compare_num,
                CompareOp::GreaterEqual => field_num >= compare_num,
                CompareOp::Less => field_num < compare_num,
                CompareOp::LessEqual => field_num <= compare_num,
            })
        }
        (JsonValue::String(s), val) if val.as_f64().is_some() => {
            // Ghidra addresses come back from the bridge as hex strings
            // (e.g. "002dad4c", or "ram:002dad4c" for multi-space
            // programs), never as JSON numbers. A numeric filter value
            // (0x..., a bare int) against such a field used to fall
            // through to the catch-all `Ok(false)` below -- silently
            // matching nothing instead of comparing addresses. Parse the
            // field as hex (falling back to decimal) so `address >= 0x...`
            // works the way it looks like it should.
            let compare_num = val.as_f64().unwrap();
            match parse_numeric_field(s) {
                Some(field_num) => Ok(match op {
                    CompareOp::Equal => (field_num - compare_num).abs() < f64::EPSILON,
                    CompareOp::NotEqual => (field_num - compare_num).abs() >= f64::EPSILON,
                    CompareOp::Greater => field_num > compare_num,
                    CompareOp::GreaterEqual => field_num >= compare_num,
                    CompareOp::Less => field_num < compare_num,
                    CompareOp::LessEqual => field_num <= compare_num,
                }),
                None => Err(GhidraError::InvalidFilter(format!(
                    "Cannot compare non-numeric string field {:?} numerically",
                    s
                ))),
            }
        }
        (JsonValue::String(s), Value::String(val)) => Ok(match op {
            CompareOp::Equal => strings_equal_lenient(field, s, val),
            CompareOp::NotEqual => !strings_equal_lenient(field, s, val),
            _ => {
                return Err(GhidraError::InvalidFilter(
                    "Cannot use numeric comparison on strings".to_string(),
                ))
            }
        }),
        (JsonValue::Bool(b), Value::Boolean(val)) => Ok(match op {
            CompareOp::Equal => *b == *val,
            CompareOp::NotEqual => *b != *val,
            _ => {
                return Err(GhidraError::InvalidFilter(
                    "Cannot use numeric comparison on booleans".to_string(),
                ))
            }
        }),
        _ => Ok(false),
    }
}

/// Equal/NotEqual on two string values for `evaluate_compare`: exact match,
/// or -- for address-shaped fields -- tolerant of a `0x`/`0X` prefix on the
/// filter's value. Ghidra addresses are stored and returned as bare hex
/// (e.g. "ff90"), but every other place in this CLI's own docs/output uses
/// `0xADDR` freely (`ghidra decompile 0x0331`, `ghidra x-ref to 0xff90`),
/// so a quoted `--filter "address = '0xff90'"` used to silently match
/// nothing instead of comparing the same way those other commands do.
fn strings_equal_lenient(field: &str, field_val: &str, filter_val: &str) -> bool {
    if field_val == filter_val {
        return true;
    }
    if !is_address_field(field) {
        return false;
    }
    let stripped = filter_val
        .strip_prefix("0x")
        .or_else(|| filter_val.strip_prefix("0X"));
    match stripped {
        Some(stripped) => field_val.eq_ignore_ascii_case(stripped),
        None => false,
    }
}

/// Field names (last path segment) that hold a Ghidra address as a bare hex
/// string, per the JSON the bridge emits (`address`, `entry_point`, xref
/// `from`/`to`, `min_address`/`max_address`).
fn is_address_field(field: &str) -> bool {
    matches!(
        field.rsplit('.').next().unwrap_or(field),
        "address" | "entry_point" | "from" | "to" | "min_address" | "max_address"
    )
}

/// Parse a JSON string field as a number for numeric comparison. Ghidra
/// address strings are unprefixed hex (optionally with an address-space
/// prefix like "ram:"), so hex is tried first; plain decimal is the
/// fallback for other numeric-looking string fields.
fn parse_numeric_field(s: &str) -> Option<f64> {
    let hex_part = s.rsplit(':').next().unwrap_or(s);
    let hex_part = hex_part
        .strip_prefix("0x")
        .or_else(|| hex_part.strip_prefix("0X"))
        .unwrap_or(hex_part);
    if !hex_part.is_empty() {
        if let Ok(n) = u64::from_str_radix(hex_part, 16) {
            return Some(n as f64);
        }
    }
    s.parse::<f64>().ok()
}

fn evaluate_string_op(field: &str, op: StringOp, value: &str, data: &JsonValue) -> Result<bool> {
    let field_value = get_field_value(field, data);

    if field_value.is_none() {
        return Ok(false);
    }

    let field_str = match field_value.unwrap() {
        JsonValue::String(s) => s.to_lowercase(),
        JsonValue::Number(n) => n.to_string(),
        JsonValue::Bool(b) => b.to_string(),
        _ => return Ok(false),
    };

    let value_lower = value.to_lowercase();

    Ok(match op {
        StringOp::Contains => field_str.contains(&value_lower),
        StringOp::StartsWith => field_str.starts_with(&value_lower),
        StringOp::EndsWith => field_str.ends_with(&value_lower),
        StringOp::Regex => compiled_regex(value)?.is_match(&field_str),
    })
}

/// Compile a filter regex once per pattern; `evaluate` runs per row, and
/// recompiling on every row dominates runtime on large datasets.
/// Case-insensitive because field values are lowercased before matching —
/// an uppercase pattern like `^PK_` could otherwise never match.
fn compiled_regex(pattern: &str) -> Result<std::rc::Rc<regex::Regex>> {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    thread_local! {
        static CACHE: RefCell<HashMap<String, Rc<regex::Regex>>> = RefCell::new(HashMap::new());
    }

    CACHE.with(|cache| {
        if let Some(re) = cache.borrow().get(pattern) {
            return Ok(re.clone());
        }
        let re = Rc::new(
            RegexBuilder::new(pattern)
                .case_insensitive(true)
                .build()
                .map_err(|e| GhidraError::InvalidFilter(format!("Invalid regex: {}", e)))?,
        );
        cache.borrow_mut().insert(pattern.to_string(), re.clone());
        Ok(re)
    })
}

fn evaluate_logical(op: LogicalOp, exprs: &[FilterExpr], data: &JsonValue) -> Result<bool> {
    match op {
        LogicalOp::And => {
            for expr in exprs {
                if !evaluate(expr, data)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        LogicalOp::Or => {
            for expr in exprs {
                if evaluate(expr, data)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

fn evaluate_exists(field: &str, check: ExistenceCheck, data: &JsonValue) -> Result<bool> {
    let field_value = get_field_value(field, data);

    Ok(match check {
        ExistenceCheck::Exists => field_value.is_some(),
        ExistenceCheck::Empty => match field_value {
            None => true,
            Some(JsonValue::Null) => true,
            Some(JsonValue::String(s)) => s.is_empty(),
            Some(JsonValue::Array(a)) => a.is_empty(),
            Some(JsonValue::Object(o)) => o.is_empty(),
            _ => false,
        },
        ExistenceCheck::Null => {
            matches!(field_value, None | Some(JsonValue::Null))
        }
    })
}

fn evaluate_in(field: &str, values: &[Value], data: &JsonValue) -> Result<bool> {
    let field_value = get_field_value(field, data);

    if field_value.is_none() {
        return Ok(false);
    }

    let field_value = field_value.unwrap();

    for val in values {
        match (field_value, val) {
            (JsonValue::String(s), Value::String(v)) => {
                if s.eq_ignore_ascii_case(v) {
                    return Ok(true);
                }
            }
            (JsonValue::Number(n), v) => {
                if let Some(compare_num) = v.as_f64() {
                    if (n.as_f64().unwrap() - compare_num).abs() < f64::EPSILON {
                        return Ok(true);
                    }
                }
            }
            (JsonValue::Bool(b), Value::Boolean(v)) if *b == *v => {
                return Ok(true);
            }
            _ => {}
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_evaluate_compare() {
        let data = json!({
            "name": "test",
            "size": 100
        });

        let expr = FilterExpr::Compare {
            field: "size".to_string(),
            op: CompareOp::Greater,
            value: Value::Integer(50),
        };

        assert!(evaluate(&expr, &data).unwrap());
    }

    #[test]
    fn test_evaluate_string_op() {
        let data = json!({
            "name": "test_function"
        });

        let expr = FilterExpr::StringOp {
            field: "name".to_string(),
            op: StringOp::Contains,
            value: "func".to_string(),
        };

        assert!(evaluate(&expr, &data).unwrap());
    }

    #[test]
    fn test_evaluate_address_range_filter() {
        // Regression: Ghidra addresses come back as hex strings (e.g.
        // "002dad4c"), never JSON numbers. A numeric filter against that
        // field used to silently fall through to `Ok(false)` for every
        // row instead of comparing addresses.
        let in_range = json!({ "name": "f1", "address": "002df100" });
        let below_range = json!({ "name": "f2", "address": "002d0000" });

        let expr = FilterExpr::Logical {
            op: LogicalOp::And,
            exprs: vec![
                FilterExpr::Compare {
                    field: "address".to_string(),
                    op: CompareOp::GreaterEqual,
                    value: Value::Hex(0x002df000),
                },
                FilterExpr::Compare {
                    field: "address".to_string(),
                    op: CompareOp::LessEqual,
                    value: Value::Hex(0x002e3600),
                },
            ],
        };

        assert!(evaluate(&expr, &in_range).unwrap());
        assert!(!evaluate(&expr, &below_range).unwrap());
    }

    #[test]
    fn test_evaluate_quoted_hex_address_equality() {
        // Regression: a quoted filter value ('0xff90') parses as
        // Value::String, not Value::Hex, so it used to fall into plain
        // string equality against the bare-hex stored field and never
        // match, even though every other command in this CLI accepts
        // 0x-prefixed addresses freely.
        let data = json!({ "name": "g_game_state", "address": "ff90" });

        let expr = FilterExpr::Compare {
            field: "address".to_string(),
            op: CompareOp::Equal,
            value: Value::String("0xff90".to_string()),
        };
        assert!(evaluate(&expr, &data).unwrap());

        let expr_ne = FilterExpr::Compare {
            field: "address".to_string(),
            op: CompareOp::NotEqual,
            value: Value::String("0xff90".to_string()),
        };
        assert!(!evaluate(&expr_ne, &data).unwrap());

        // Non-address string fields are unaffected by 0x-stripping.
        let name_expr = FilterExpr::Compare {
            field: "name".to_string(),
            op: CompareOp::Equal,
            value: Value::String("0xff90".to_string()),
        };
        assert!(!evaluate(&name_expr, &data).unwrap());
    }

    #[test]
    fn test_evaluate_regex_is_case_insensitive() {
        // Regression: fields are lowercased before matching, so an uppercase
        // pattern like ^PK_ silently matched nothing.
        let data = json!({ "name": "PK_APPITEM_ask" });

        let expr = FilterExpr::StringOp {
            field: "name".to_string(),
            op: StringOp::Regex,
            value: "^PK_".to_string(),
        };

        assert!(evaluate(&expr, &data).unwrap());
    }

    #[test]
    fn test_evaluate_nested_field() {
        let data = json!({
            "function": {
                "name": "test",
                "xrefs": {
                    "count": 10
                }
            }
        });

        let expr = FilterExpr::Compare {
            field: "function.xrefs.count".to_string(),
            op: CompareOp::Greater,
            value: Value::Integer(5),
        };

        assert!(evaluate(&expr, &data).unwrap());
    }
}
