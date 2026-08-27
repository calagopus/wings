use crate::io::SafeSliceExt;
use rusqlite::fallible_iterator::FallibleIterator;
use serde::Serialize;
use std::time::Duration;
use utoipa::ToSchema;

pub const QUERY_MAX_LENGTH: usize = 65535;
pub const QUERY_DEFAULT_ROWS: u32 = 100;
pub const QUERY_MAX_ROWS: u32 = 1000;
const QUERY_MAX_BYTES: usize = 4 * 1024 * 1024;
const QUERY_MAX_VALUE_BYTES: usize = 256 * 1024;
pub const QUERY_DEADLINE: Duration = Duration::from_secs(15);
pub const QUERY_BUSY_TIMEOUT: Duration = Duration::from_millis(3000);

#[derive(ToSchema, Serialize, Clone)]
pub struct QueryColumn {
    pub name: String,
    pub type_name: String,
    pub binary: bool,
}

#[derive(ToSchema, Serialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum QueryValue {
    Null,
    Text { value: String, truncated: bool },
    Binary { value: String, truncated: bool },
}

impl QueryValue {
    fn text(value: &str) -> Self {
        Self::Text {
            value: crate::utils::slice_up_to(value, QUERY_MAX_VALUE_BYTES).to_owned(),
            truncated: value.len() > QUERY_MAX_VALUE_BYTES,
        }
    }

    fn binary(bytes: &[u8]) -> Self {
        let max = QUERY_MAX_VALUE_BYTES / 2;

        Self::Binary {
            value: match bytes.get_slice(..bytes.len().min(max)) {
                Ok(slice) => hex::encode(slice),
                Err(_) => String::new(),
            },
            truncated: bytes.len() > max,
        }
    }

    fn byte_len(&self) -> usize {
        match self {
            Self::Null => 0,
            Self::Text { value, .. } | Self::Binary { value, .. } => value.len(),
        }
    }
}

#[derive(ToSchema, Serialize, Clone)]
pub struct QueryResultSet {
    pub columns: Vec<QueryColumn>,
    pub rows: Vec<Vec<QueryValue>>,
    pub rows_affected: u64,
    pub truncated: bool,
}

pub fn run_query(
    connection: &rusqlite::Connection,
    sql: &str,
    max_rows: usize,
) -> Result<Vec<QueryResultSet>, rusqlite::Error> {
    let mut results = Vec::new();
    let mut batch = rusqlite::Batch::new(connection, sql);
    let mut bytes = 0usize;

    while let Some(mut statement) = batch.next()? {
        if statement.column_count() == 0 {
            let affected = statement.raw_execute()?;
            results.push(QueryResultSet {
                columns: Vec::new(),
                rows: Vec::new(),
                rows_affected: affected as u64,
                truncated: false,
            });

            continue;
        }

        let columns: Vec<QueryColumn> = statement
            .columns()
            .iter()
            .map(|column| {
                let type_name = column.decl_type().unwrap_or_default();

                QueryColumn {
                    name: column.name().to_owned(),
                    binary: type_name.to_ascii_uppercase().contains("BLOB"),
                    type_name: type_name.to_owned(),
                }
            })
            .collect();

        let mut rows = Vec::new();
        let mut truncated = false;

        let mut raw_rows = statement.raw_query();
        while let Some(row) = raw_rows.next()? {
            if rows.len() >= max_rows || bytes >= QUERY_MAX_BYTES {
                truncated = true;
                break;
            }

            let values = (0..columns.len())
                .map(|index| {
                    Ok(match row.get_ref(index)? {
                        rusqlite::types::ValueRef::Null => QueryValue::Null,
                        rusqlite::types::ValueRef::Integer(value) => QueryValue::Text {
                            value: value.to_string(),
                            truncated: false,
                        },
                        rusqlite::types::ValueRef::Real(value) => QueryValue::Text {
                            value: value.to_string(),
                            truncated: false,
                        },
                        rusqlite::types::ValueRef::Text(value) => {
                            QueryValue::text(&String::from_utf8_lossy(value))
                        }
                        rusqlite::types::ValueRef::Blob(value) => QueryValue::binary(value),
                    })
                })
                .collect::<Result<Vec<_>, rusqlite::Error>>()?;

            let len = values.iter().map(QueryValue::byte_len).sum::<usize>();
            if bytes + len > QUERY_MAX_BYTES {
                bytes = QUERY_MAX_BYTES;
                truncated = true;
                break;
            }

            bytes += len;
            rows.push(values);
        }
        drop(raw_rows);

        results.push(QueryResultSet {
            columns,
            rows,
            rows_affected: 0,
            truncated,
        });
    }

    Ok(results)
}
