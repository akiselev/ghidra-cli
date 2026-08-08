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
        (JsonValue::Array(elems), val) => {
            // Array fields (e.g. `tags`): `=` is any-element-equals; `!=` is
            // NO-element-equals (i.e. `tags != 'x'` ≡ `NOT(tags = 'x')` —
            // naive any-element `!=` would be true for nearly every
            // multi-element array). Ordering comparisons on arrays are false.
            match op {
                CompareOp::Equal | CompareOp::NotEqual => {
                    let any_equal = elems.iter().any(|elem| scalar_equals(elem, val));
                    Ok(if matches!(op, CompareOp::Equal) {
                        any_equal
                    } else {
                        !any_equal
                    })
                }
                _ => Ok(false),
            }
        }
        _ => Ok(false),
    }
}

/// Element-vs-value equality for array-field filters. Mirrors the scalar `=`
/// semantics (exact, case-sensitive for strings); type mismatches are simply
/// not-equal rather than errors, since arrays can hold mixed content.
fn scalar_equals(elem: &JsonValue, val: &Value) -> bool {
    match (elem, val) {
        (JsonValue::String(s), Value::String(v)) => s == v,
        (JsonValue::Number(n), v) => v
            .as_f64()
            .is_some_and(|c| (n.as_f64().unwrap() - c).abs() < f64::EPSILON),
        (JsonValue::Bool(b), Value::Boolean(v)) => *b == *v,
        _ => false,
    }
}

fn evaluate_string_op(field: &str, op: StringOp, value: &str, data: &JsonValue) -> Result<bool> {
    let field_value = get_field_value(field, data);

    if field_value.is_none() {
        return Ok(false);
    }

    let value_lower = value.to_lowercase();
    let matches_str = |field_str: &str| -> Result<bool> {
        Ok(match op {
            StringOp::Contains => field_str.contains(&value_lower),
            StringOp::StartsWith => field_str.starts_with(&value_lower),
            StringOp::EndsWith => field_str.ends_with(&value_lower),
            StringOp::Regex => compiled_regex(value)?.is_match(field_str),
        })
    };

    match field_value.unwrap() {
        // Array fields (e.g. `tags`): any-element semantics — match if any
        // element satisfies the predicate.
        JsonValue::Array(elems) => {
            for elem in elems {
                if let Some(s) = scalar_to_lower_string(elem) {
                    if matches_str(&s)? {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }
        other => match scalar_to_lower_string(other) {
            Some(s) => matches_str(&s),
            None => Ok(false),
        },
    }
}

fn scalar_to_lower_string(v: &JsonValue) -> Option<String> {
    match v {
        JsonValue::String(s) => Some(s.to_lowercase()),
        JsonValue::Number(n) => Some(n.to_string()),
        JsonValue::Bool(b) => Some(b.to_string()),
        _ => None,
    }
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

    // Array fields (e.g. `tags`): any-element semantics.
    if let JsonValue::Array(elems) = field_value {
        return Ok(elems
            .iter()
            .any(|elem| values.iter().any(|v| scalar_matches_in(elem, v))));
    }

    Ok(values.iter().any(|v| scalar_matches_in(field_value, v)))
}

/// `IN`-list membership for one scalar. Strings compare case-insensitively,
/// matching the operator's pre-existing scalar semantics.
fn scalar_matches_in(field_value: &JsonValue, val: &Value) -> bool {
    match (field_value, val) {
        (JsonValue::String(s), Value::String(v)) => s.eq_ignore_ascii_case(v),
        (JsonValue::Number(n), v) => v
            .as_f64()
            .is_some_and(|c| (n.as_f64().unwrap() - c).abs() < f64::EPSILON),
        (JsonValue::Bool(b), Value::Boolean(v)) => *b == *v,
        _ => false,
    }
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
    fn test_array_field_contains_any_element() {
        let data = json!({ "tags": ["Crypto", "reviewed"] });

        // ~ is case-insensitive and matches any element
        let expr = FilterExpr::StringOp {
            field: "tags".to_string(),
            op: StringOp::Contains,
            value: "crypto".to_string(),
        };
        assert!(evaluate(&expr, &data).unwrap());

        let expr = FilterExpr::StringOp {
            field: "tags".to_string(),
            op: StringOp::Contains,
            value: "network".to_string(),
        };
        assert!(!evaluate(&expr, &data).unwrap());
    }

    #[test]
    fn test_array_field_equals_is_exact_any_element() {
        let data = json!({ "tags": ["Crypto", "reviewed"] });

        // = is exact-match (case-sensitive), any element
        let eq = |v: &str| FilterExpr::Compare {
            field: "tags".to_string(),
            op: CompareOp::Equal,
            value: Value::String(v.to_string()),
        };
        assert!(evaluate(&eq("Crypto"), &data).unwrap());
        assert!(!evaluate(&eq("crypto"), &data).unwrap());
    }

    #[test]
    fn test_array_field_not_equal_is_no_element_equals() {
        // tags != 'x' must mean NO element equals x, not "some element differs".
        let data = json!({ "tags": ["crypto", "reviewed"] });

        let ne = |v: &str| FilterExpr::Compare {
            field: "tags".to_string(),
            op: CompareOp::NotEqual,
            value: Value::String(v.to_string()),
        };
        assert!(!evaluate(&ne("crypto"), &data).unwrap());
        assert!(evaluate(&ne("network"), &data).unwrap());
    }

    #[test]
    fn test_array_field_ordering_comparison_is_false() {
        let data = json!({ "tags": ["crypto"] });
        let expr = FilterExpr::Compare {
            field: "tags".to_string(),
            op: CompareOp::Greater,
            value: Value::Integer(1),
        };
        assert!(!evaluate(&expr, &data).unwrap());
    }

    #[test]
    fn test_array_field_in_any_element() {
        let data = json!({ "tags": ["crypto", "reviewed"] });
        let expr = FilterExpr::In {
            field: "tags".to_string(),
            values: vec![
                Value::String("network".to_string()),
                Value::String("CRYPTO".to_string()), // IN is case-insensitive
            ],
        };
        assert!(evaluate(&expr, &data).unwrap());

        let expr = FilterExpr::In {
            field: "tags".to_string(),
            values: vec![Value::String("network".to_string())],
        };
        assert!(!evaluate(&expr, &data).unwrap());
    }

    #[test]
    fn test_empty_array_field() {
        let data = json!({ "tags": [] });
        let expr = FilterExpr::StringOp {
            field: "tags".to_string(),
            op: StringOp::Contains,
            value: "x".to_string(),
        };
        assert!(!evaluate(&expr, &data).unwrap());

        // tags != 'x' on an empty array: no element equals x → true
        let expr = FilterExpr::Compare {
            field: "tags".to_string(),
            op: CompareOp::NotEqual,
            value: Value::String("x".to_string()),
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
