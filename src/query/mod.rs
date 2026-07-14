use crate::cli::QueryOptions;
use crate::error::{GhidraError, Result};
use crate::filter::Filter;
use crate::format::{DefaultFormatter, Formatter, OutputFormat};
use serde_json::Value as JsonValue;

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum DataType {
    Functions,
    Strings,
    Symbols,
    Imports,
    Exports,
    XRefs,
    Memory,
    Sections,
    Comments,
    Types,
    Instructions,
    BasicBlocks,
    CallGraph,
    Data,
    References,
}

#[allow(dead_code)]
impl DataType {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "functions" | "function" | "fn" => Ok(Self::Functions),
            "strings" | "string" | "str" => Ok(Self::Strings),
            "symbols" | "symbol" | "sym" => Ok(Self::Symbols),
            "imports" | "import" => Ok(Self::Imports),
            "exports" | "export" => Ok(Self::Exports),
            "xrefs" | "xref" | "crossrefs" => Ok(Self::XRefs),
            "memory" | "mem" => Ok(Self::Memory),
            "sections" | "section" => Ok(Self::Sections),
            "comments" | "comment" => Ok(Self::Comments),
            "types" | "type" => Ok(Self::Types),
            "instructions" | "instruction" | "insn" => Ok(Self::Instructions),
            "basicblocks" | "basic-blocks" | "blocks" => Ok(Self::BasicBlocks),
            "callgraph" | "call-graph" => Ok(Self::CallGraph),
            "data" => Ok(Self::Data),
            "references" | "refs" => Ok(Self::References),
            _ => Err(GhidraError::InvalidDataType(format!(
                "Unknown data type: {}",
                s
            ))),
        }
    }
}

pub struct Query {
    #[allow(dead_code)]
    pub data_type: DataType,
    pub filter: Option<Filter>,
    pub fields: Option<FieldSelector>,
    pub format: OutputFormat,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub sort: Option<Vec<SortKey>>,
    pub count_only: bool,
}

impl Query {
    #[allow(dead_code)]
    pub fn new(data_type: DataType) -> Self {
        Self {
            data_type,
            filter: None,
            fields: None,
            format: OutputFormat::Json,
            limit: None,
            offset: None,
            sort: None,
            count_only: false,
        }
    }

    /// Build a Query from CLI QueryOptions. Returns None if no query processing is needed.
    pub fn from_options(opts: &QueryOptions, format: OutputFormat) -> Result<Option<Self>> {
        let has_filter = opts.filter.is_some();
        let has_fields = opts.fields.is_some();
        let has_sort = opts.sort.is_some();
        let has_count = opts.count;
        let has_offset = opts.offset.is_some();
        let has_limit = opts.limit.is_some();

        // No query processing needed if no filter/fields/sort/count/offset/limit.
        // Offset and limit must be handled here because some bridge list handlers
        // (e.g. imports/exports) never paginate — when either is set,
        // `bridge_list_params` (main.rs) may fetch the full dataset and this Query
        // must apply the real offset/limit itself. Applying the limit again on a
        // dataset the bridge already capped is idempotent, so this is safe.
        if !has_filter && !has_fields && !has_sort && !has_count && !has_offset && !has_limit {
            return Ok(None);
        }

        let filter = opts.filter.as_ref().map(|f| Filter::parse(f)).transpose()?;
        let fields = opts
            .fields
            .as_ref()
            .map(|f| FieldSelector::parse(f))
            .transpose()?;
        let sort = opts.sort.as_ref().map(|s| SortKey::parse(s));

        Ok(Some(Self {
            data_type: DataType::Functions, // placeholder, not used in process_results
            filter,
            fields,
            format,
            // The bridge only skips limit/filter when filter/sort/count/offset is
            // requested (see `bridge_list_params` in main.rs) — in that case it
            // returns the full dataset and we must paginate here ourselves.
            limit: opts.limit,
            offset: opts.offset,
            sort,
            count_only: has_count,
        }))
    }

    #[allow(dead_code)]
    pub fn with_filter(mut self, filter: Filter) -> Self {
        self.filter = Some(filter);
        self
    }

    #[allow(dead_code)]
    pub fn with_format(mut self, format: OutputFormat) -> Self {
        self.format = format;
        self
    }

    #[allow(dead_code)]
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    #[allow(dead_code)]
    pub fn with_offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }

    #[allow(dead_code)]
    pub fn count_only(mut self) -> Self {
        self.count_only = true;
        self
    }

    /// Process query results from pre-fetched data.
    ///
    /// Note: Data fetching is now handled by the daemon via IPC.
    /// This method only handles filtering, field selection, sorting, and formatting.
    pub fn process_results(&self, data: Vec<JsonValue>) -> Result<String> {
        // Apply filter
        let filtered = if let Some(filter) = &self.filter {
            self.apply_filter(&data, filter)?
        } else {
            data
        };

        // Apply field selection
        let selected = if let Some(fields) = &self.fields {
            self.select_fields(&filtered, fields)?
        } else {
            filtered
        };

        // Apply sorting
        let sorted = if let Some(sort) = &self.sort {
            self.apply_sort(&selected, sort)?
        } else {
            selected
        };

        // Apply pagination
        let paginated = self.apply_pagination(&sorted);

        // Return count if requested
        if self.count_only {
            return Ok(paginated.len().to_string());
        }

        // Format output
        let formatter = DefaultFormatter;
        formatter.format(&paginated, self.format)
    }

    fn apply_filter(&self, data: &[JsonValue], filter: &Filter) -> Result<Vec<JsonValue>> {
        let mut result = Vec::new();

        for item in data {
            if filter.evaluate(item)? {
                result.push(item.clone());
            }
        }

        Ok(result)
    }

    fn select_fields(
        &self,
        data: &[JsonValue],
        selector: &FieldSelector,
    ) -> Result<Vec<JsonValue>> {
        let mut result = Vec::new();

        for item in data {
            if let JsonValue::Object(map) = item {
                let mut new_map = serde_json::Map::new();

                if let Some(include) = &selector.include {
                    for field in include {
                        if let Some(value) = map.get(field) {
                            new_map.insert(field.clone(), value.clone());
                        }
                    }
                } else if let Some(exclude) = &selector.exclude {
                    for (key, value) in map {
                        if !exclude.contains(key) {
                            new_map.insert(key.clone(), value.clone());
                        }
                    }
                } else {
                    new_map = map.clone();
                }

                result.push(JsonValue::Object(new_map));
            } else {
                result.push(item.clone());
            }
        }

        Ok(result)
    }

    fn apply_sort(&self, data: &[JsonValue], sort_keys: &[SortKey]) -> Result<Vec<JsonValue>> {
        let mut result = data.to_vec();

        result.sort_by(|a, b| {
            for sort_key in sort_keys {
                let a_val = self.get_field_for_sort(a, &sort_key.field);
                let b_val = self.get_field_for_sort(b, &sort_key.field);

                let cmp = match (&a_val, &b_val) {
                    (Some(JsonValue::Number(a)), Some(JsonValue::Number(b))) => a
                        .as_f64()
                        .partial_cmp(&b.as_f64())
                        .unwrap_or(std::cmp::Ordering::Equal),
                    (Some(JsonValue::String(a)), Some(JsonValue::String(b))) => a.cmp(b),
                    _ => std::cmp::Ordering::Equal,
                };

                let final_cmp = if sort_key.descending {
                    cmp.reverse()
                } else {
                    cmp
                };

                if final_cmp != std::cmp::Ordering::Equal {
                    return final_cmp;
                }
            }

            std::cmp::Ordering::Equal
        });

        Ok(result)
    }

    fn get_field_for_sort(&self, value: &JsonValue, field: &str) -> Option<JsonValue> {
        if let JsonValue::Object(map) = value {
            map.get(field).cloned()
        } else {
            None
        }
    }

    fn apply_pagination(&self, data: &[JsonValue]) -> Vec<JsonValue> {
        let offset = self.offset.unwrap_or(0);
        // `--limit 0` means "no limit", matching the bridge's convention
        // (its list handlers only cap when limit > 0).
        let limit = match self.limit {
            None | Some(0) => usize::MAX,
            Some(n) => n,
        };

        data.iter().skip(offset).take(limit).cloned().collect()
    }
}

pub struct FieldSelector {
    pub include: Option<Vec<String>>,
    pub exclude: Option<Vec<String>>,
}

impl FieldSelector {
    pub fn include(fields: Vec<String>) -> Self {
        Self {
            include: Some(fields),
            exclude: None,
        }
    }

    pub fn exclude(fields: Vec<String>) -> Self {
        Self {
            include: None,
            exclude: Some(fields),
        }
    }

    pub fn parse(input: &str) -> Result<Self> {
        if input.starts_with('-') {
            // Exclude fields
            let fields: Vec<String> = input
                .trim_start_matches('-')
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();
            Ok(Self::exclude(fields))
        } else {
            // Include fields
            let fields: Vec<String> = input.split(',').map(|s| s.trim().to_string()).collect();
            Ok(Self::include(fields))
        }
    }
}

pub struct SortKey {
    pub field: String,
    pub descending: bool,
}

impl SortKey {
    pub fn parse(input: &str) -> Vec<Self> {
        input
            .split(',')
            .map(|s| {
                let s = s.trim();
                if s.starts_with('-') {
                    SortKey {
                        field: s.trim_start_matches('-').to_string(),
                        descending: true,
                    }
                } else {
                    SortKey {
                        field: s.to_string(),
                        descending: false,
                    }
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_type_parsing() {
        assert_eq!(
            DataType::from_str("functions").unwrap(),
            DataType::Functions
        );
        assert_eq!(DataType::from_str("fn").unwrap(), DataType::Functions);
        assert_eq!(DataType::from_str("strings").unwrap(), DataType::Strings);
    }

    #[test]
    fn test_field_selector_parse() {
        let selector = FieldSelector::parse("name,address,size").unwrap();
        assert!(selector.include.is_some());
        assert_eq!(selector.include.unwrap().len(), 3);

        let selector = FieldSelector::parse("-metadata,internal").unwrap();
        assert!(selector.exclude.is_some());
    }

    #[test]
    fn test_sort_key_parse() {
        let keys = SortKey::parse("name,-size");
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].field, "name");
        assert!(!keys[0].descending);
        assert_eq!(keys[1].field, "size");
        assert!(keys[1].descending);
    }

    fn rows(n: usize) -> Vec<JsonValue> {
        (0..n).map(|i| serde_json::json!({ "id": i })).collect()
    }

    #[test]
    fn test_limit_zero_means_all_rows() {
        // Regression: `--limit 0` used to produce take(0) => empty output
        let mut query = Query::new(DataType::Functions);
        query.limit = Some(0);
        assert_eq!(query.apply_pagination(&rows(5)).len(), 5);
    }

    #[test]
    fn test_limit_none_means_all_rows() {
        let query = Query::new(DataType::Functions);
        assert_eq!(query.apply_pagination(&rows(5)).len(), 5);
    }

    #[test]
    fn test_limit_applies_after_offset() {
        let mut query = Query::new(DataType::Functions);
        query.limit = Some(2);
        query.offset = Some(1);
        let page = query.apply_pagination(&rows(5));
        assert_eq!(page.len(), 2);
        assert_eq!(page[0]["id"], 1);
    }

    #[test]
    fn test_limit_zero_with_offset_returns_remainder() {
        let mut query = Query::new(DataType::Functions);
        query.limit = Some(0);
        query.offset = Some(2);
        assert_eq!(query.apply_pagination(&rows(5)).len(), 3);
    }
}
