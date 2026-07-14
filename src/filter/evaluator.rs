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
        (JsonValue::String(s), Value::String(val)) => Ok(match op {
            CompareOp::Equal => s == val,
            CompareOp::NotEqual => s != val,
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
