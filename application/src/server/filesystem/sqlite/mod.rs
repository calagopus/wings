use crate::io::SafeSliceExt;
use rusqlite::{
    Connection, OpenFlags,
    config::DbConfig,
    fallible_iterator::FallibleIterator,
    ffi,
    hooks::{AuthAction, AuthContext, Authorization},
};
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Once, time::Duration};
use utoipa::ToSchema;

#[cfg(target_os = "linux")]
pub mod helper;
#[cfg(target_os = "linux")]
pub mod sandbox;

#[cfg(target_os = "linux")]
pub use helper::{HELPER_ARG, helper_main};

pub const QUERY_MAX_LENGTH: usize = 65535;
pub const QUERY_DEFAULT_ROWS: u32 = 100;
pub const QUERY_MAX_ROWS: u32 = 1000;
/// Queries one server may run at the same time, each in its own helper process.
pub const QUERY_MAX_CONCURRENT: usize = 2;
const QUERY_MAX_BYTES: usize = 4 * 1024 * 1024;
const QUERY_MAX_VALUE_BYTES: usize = 256 * 1024;
const QUERY_SQLITE_LENGTH_LIMIT: i32 = 32 * 1024 * 1024;
/// Room for a few values of [`QUERY_SQLITE_LENGTH_LIMIT`] plus working memory.
pub const QUERY_MEMORY_LIMIT: u64 = 128 * 1024 * 1024;
pub const QUERY_DEADLINE: Duration = Duration::from_secs(15);
pub const QUERY_BUSY_TIMEOUT: Duration = Duration::from_millis(3000);
const DENIED_PRAGMAS: &[&str] = &[
    "temp_store_directory",
    "data_store_directory",
    "hard_heap_limit",
    "soft_heap_limit",
    "mmap_size",
    "temp_store",
];

#[derive(ToSchema, Serialize, Deserialize, Clone)]
pub struct QueryColumn {
    pub name: String,
    pub type_name: String,
    pub binary: bool,
}

#[derive(ToSchema, Serialize, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum QueryValue {
    Null,
    Text { value: String, truncated: bool },
    Binary { value: String, truncated: bool },
}

impl QueryValue {
    fn text(bytes: &[u8]) -> Self {
        // the last char that can start inside the preview ends at most 3 bytes past it
        let prefix = bytes.len().min(QUERY_MAX_VALUE_BYTES + 3);
        let value = String::from_utf8_lossy(match bytes.get_slice(..prefix) {
            Ok(slice) => slice,
            Err(_) => &[],
        });

        Self::Text {
            value: crate::utils::slice_up_to(&value, QUERY_MAX_VALUE_BYTES).to_owned(),
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

#[derive(ToSchema, Serialize, Deserialize, Clone)]
pub struct QueryResultSet {
    pub columns: Vec<QueryColumn>,
    pub rows: Vec<Vec<QueryValue>>,
    pub rows_affected: u64,
    pub truncated: bool,
}

static DISABLE_MMAP: Once = Once::new();

pub fn open(path: &Path, flags: OpenFlags) -> Result<Connection, rusqlite::Error> {
    DISABLE_MMAP.call_once(|| {
        // SAFETY: SQLITE_CONFIG_MMAP_SIZE takes two i64 arguments, and is refused with
        // SQLITE_MISUSE once SQLite is initialized, which leaves the default in place.
        unsafe { ffi::sqlite3_config(ffi::SQLITE_CONFIG_MMAP_SIZE, 0_i64, 0_i64) };
    });

    let connection = Connection::open_with_flags(path, flags)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    connection.pragma_update(None, "temp_store", "MEMORY")?;

    Ok(connection)
}

fn authorize(context: AuthContext<'_>) -> Authorization {
    match context.action {
        AuthAction::Attach {
            filename: "" | ":memory:",
        } => Authorization::Allow,
        AuthAction::Attach { .. }
        | AuthAction::Unknown {
            code: ffi::SQLITE_ATTACH,
            ..
        } => Authorization::Deny,
        AuthAction::Pragma {
            pragma_name,
            pragma_value: Some(_),
        } if DENIED_PRAGMAS
            .iter()
            .any(|denied| pragma_name.eq_ignore_ascii_case(denied)) =>
        {
            Authorization::Deny
        }
        AuthAction::Pragma {
            pragma_name,
            pragma_value: Some(_),
        } if pragma_name.eq_ignore_ascii_case("threads") => Authorization::Ignore,
        _ => Authorization::Allow,
    }
}

pub fn run_query(
    connection: &Connection,
    sql: &str,
    max_rows: usize,
) -> Result<Vec<QueryResultSet>, rusqlite::Error> {
    execute_query(connection, sql, max_rows).map_err(truncate_error)
}

fn truncate_error(error: rusqlite::Error) -> rusqlite::Error {
    match error {
        rusqlite::Error::SqliteFailure(code, Some(message))
            if message.len() > QUERY_MAX_VALUE_BYTES =>
        {
            rusqlite::Error::SqliteFailure(
                code,
                Some(crate::utils::slice_up_to(&message, QUERY_MAX_VALUE_BYTES).to_owned()),
            )
        }
        error => error,
    }
}

fn execute_query(
    connection: &Connection,
    sql: &str,
    max_rows: usize,
) -> Result<Vec<QueryResultSet>, rusqlite::Error> {
    connection.authorizer(Some(authorize))?;
    connection.set_limit(
        rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
        QUERY_SQLITE_LENGTH_LIMIT,
    )?;

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
                        rusqlite::types::ValueRef::Text(value) => QueryValue::text(value),
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

#[cfg(all(test, target_os = "linux"))]
fn reexec_supported() -> bool {
    static SUPPORTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

    let supported = *SUPPORTED.get_or_init(|| {
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--list", "--exact", "server::filesystem::sqlite"])
            .output()
            .is_ok_and(|output| output.status.success())
    });
    if !supported {
        eprintln!("skipping: the test binary cannot re-exec itself");
    }

    supported
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::ErrorCode;
    use std::path::PathBuf;

    fn seeded_db(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        open(&path, OpenFlags::default())
            .unwrap()
            .execute_batch("CREATE TABLE seed(x); INSERT INTO seed VALUES (1);")
            .unwrap();

        path
    }

    fn open_db(path: &Path, flags: OpenFlags) -> Connection {
        open(
            path,
            flags | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .unwrap()
    }

    fn query(
        connection: &Connection,
        sql: &str,
        max_rows: usize,
    ) -> Result<Vec<QueryResultSet>, rusqlite::Error> {
        run_query(connection, sql, max_rows)
    }

    fn assert_denied(connection: &Connection, sql: &str) {
        match query(connection, sql, 100) {
            Err(rusqlite::Error::SqliteFailure(error, _)) => {
                assert_eq!(
                    error.code,
                    ErrorCode::AuthorizationForStatementDenied,
                    "{sql}"
                );
            }
            Err(error) => panic!("{sql}: {error}"),
            Ok(_) => panic!("{sql}: allowed"),
        }
    }

    fn values(set: &QueryResultSet) -> Vec<Vec<Option<&str>>> {
        set.rows
            .iter()
            .map(|row| {
                row.iter()
                    .map(|value| match value {
                        QueryValue::Null => None,
                        QueryValue::Text { value, .. } | QueryValue::Binary { value, .. } => {
                            Some(value.as_str())
                        }
                    })
                    .collect()
            })
            .collect()
    }

    // open

    #[test]
    fn hardens_every_connection() {
        let dir = tempfile::tempdir().unwrap();
        let path = seeded_db(dir.path(), "main.db");

        for flags in [
            OpenFlags::SQLITE_OPEN_READ_ONLY,
            OpenFlags::SQLITE_OPEN_READ_WRITE,
        ] {
            let connection = open_db(&path, flags);
            assert!(
                connection
                    .db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE)
                    .unwrap()
            );
            assert!(
                !connection
                    .db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA)
                    .unwrap()
            );

            let results = query(&connection, "PRAGMA mmap_size", 100).unwrap();
            assert_eq!(values(results.last().unwrap()), [[Some("0")]]);
            let results = query(&connection, "PRAGMA temp_store", 100).unwrap();
            assert_eq!(values(results.last().unwrap()), [[Some("2")]]);
        }

        let connection = open_db(&path, OpenFlags::SQLITE_OPEN_READ_WRITE);
        assert!(
            query(
                &connection,
                "PRAGMA writable_schema = ON; \
                 UPDATE sqlite_schema SET sql = 'CREATE TABLE seed(y)' WHERE name = 'seed'",
                100,
            )
            .is_err()
        );
        let results = query(&connection, "SELECT sql FROM sqlite_schema", 100).unwrap();
        assert_eq!(
            values(results.last().unwrap()),
            [[Some("CREATE TABLE seed(x)")]]
        );
    }

    #[test]
    fn rejects_mmap_and_temp_store_pragmas() {
        let dir = tempfile::tempdir().unwrap();
        let path = seeded_db(dir.path(), "main.db");
        let connection = open_db(&path, OpenFlags::SQLITE_OPEN_READ_WRITE);

        for sql in [
            "PRAGMA mmap_size = 268435456",
            "PRAGMA MMAP_SIZE(1048576)",
            "PRAGMA main.mmap_size = 0",
            "PRAGMA temp_store = FILE",
            "PRAGMA temp_store = 1",
            "PRAGMA Temp_Store(DEFAULT)",
        ] {
            assert_denied(&connection, sql);
        }

        let results = query(&connection, "PRAGMA mmap_size", 100).unwrap();
        assert_eq!(values(results.last().unwrap()), [[Some("0")]]);
        let results = query(&connection, "PRAGMA temp_store", 100).unwrap();
        assert_eq!(values(results.last().unwrap()), [[Some("2")]]);
    }

    // run_query

    #[test]
    fn allows_normal_read_write_workflow() {
        let dir = tempfile::tempdir().unwrap();
        let path = seeded_db(dir.path(), "main.db");
        let connection = open_db(&path, OpenFlags::SQLITE_OPEN_READ_WRITE);

        let results = query(
            &connection,
            "CREATE TABLE t(id INTEGER PRIMARY KEY, name TEXT); \
             INSERT INTO t(name) VALUES ('a'), ('b'); \
             SELECT id, name FROM t ORDER BY id",
            100,
        )
        .unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results.get(1).unwrap().rows_affected, 2);
        let select = results.last().unwrap();
        assert_eq!(
            select
                .columns
                .iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>(),
            ["id", "name"]
        );
        assert_eq!(
            values(select),
            [[Some("1"), Some("a")], [Some("2"), Some("b")]]
        );
        assert!(!select.truncated);

        let results = query(
            &connection,
            "PRAGMA user_version = 3; PRAGMA user_version",
            100,
        )
        .unwrap();
        assert_eq!(values(results.last().unwrap()), [[Some("3")]]);

        drop(connection);
        let reader = open_db(&path, OpenFlags::SQLITE_OPEN_READ_ONLY);
        let results = query(&reader, "SELECT name FROM t ORDER BY id", 100).unwrap();
        assert_eq!(values(results.last().unwrap()), [[Some("a")], [Some("b")]]);
    }

    #[test]
    fn heavy_legitimate_queries_return_correct_results() {
        const ROWS: i64 = 300_000;

        let dir = tempfile::tempdir().unwrap();
        let path = seeded_db(dir.path(), "main.db");
        let connection = open_db(&path, OpenFlags::SQLITE_OPEN_READ_WRITE);
        let v_of = |id: i64| (id * 7919) % 100_003;

        query(
            &connection,
            "CREATE TABLE t(id INTEGER PRIMARY KEY, g INTEGER, v INTEGER, s TEXT); \
             WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM c WHERE i < 300000) \
             INSERT INTO t SELECT i, i % 100, (i * 7919) % 100003, printf('%06d', i) FROM c",
            100,
        )
        .unwrap();

        let mut sorted: Vec<(i64, i64)> = (1..=ROWS).map(|id| (v_of(id), id)).collect();
        sorted.sort_unstable_by(|a, b| b.cmp(a));
        let expected: Vec<Vec<Option<String>>> = sorted
            .iter()
            .take(3)
            .map(|(_, id)| vec![Some(id.to_string())])
            .collect();
        let results = query(&connection, "SELECT id FROM t ORDER BY v DESC, id DESC", 3).unwrap();
        let select = results.last().unwrap();
        assert!(select.truncated);
        assert_eq!(
            values(select),
            expected
                .iter()
                .map(|row| row.iter().map(Option::as_deref).collect::<Vec<_>>())
                .collect::<Vec<_>>()
        );

        let mut groups = vec![(0_i64, 0_i64, i64::MAX, i64::MIN, 0_i64); 100];
        for id in 1..=ROWS {
            let v = v_of(id);
            let group = groups.get_mut((id % 100) as usize).unwrap();
            group.0 += 1;
            group.1 += v;
            group.2 = group.2.min(v);
            group.3 = group.3.max(v);
            group.4 = v;
        }
        let expected: Vec<Vec<String>> = groups
            .iter()
            .enumerate()
            .map(|(g, (count, sum, min, max, _))| {
                [g as i64, *count, *sum, *min, *max]
                    .iter()
                    .map(i64::to_string)
                    .collect()
            })
            .collect();
        let results = query(
            &connection,
            "SELECT g, count(*), sum(v), min(v), max(v) FROM t GROUP BY g ORDER BY g",
            1000,
        )
        .unwrap();
        assert_eq!(
            values(results.last().unwrap()),
            expected
                .iter()
                .map(|row| row
                    .iter()
                    .map(|value| Some(value.as_str()))
                    .collect::<Vec<_>>())
                .collect::<Vec<_>>()
        );

        let last_per_group: i64 = groups.iter().map(|group| group.4).sum();
        let results = query(
            &connection,
            "SELECT sum(v - prev) FROM \
             (SELECT v, lag(v, 1, 0) OVER (PARTITION BY g ORDER BY id) AS prev FROM t)",
            100,
        )
        .unwrap();
        assert_eq!(
            values(results.last().unwrap()),
            [[Some(last_per_group.to_string().as_str())]]
        );

        let distinct = (1..=ROWS)
            .map(v_of)
            .collect::<std::collections::HashSet<_>>()
            .len();
        let results = query(&connection, "SELECT count(DISTINCT v) FROM t", 100).unwrap();
        assert_eq!(
            values(results.last().unwrap()),
            [[Some(distinct.to_string().as_str())]]
        );

        let concat_len = ROWS * 6 + (ROWS - 1);
        let results = query(
            &connection,
            "SELECT length(group_concat(s, ',')) FROM (SELECT s FROM t ORDER BY s DESC)",
            100,
        )
        .unwrap();
        assert_eq!(
            values(results.last().unwrap()),
            [[Some(concat_len.to_string().as_str())]]
        );
    }

    #[test]
    fn caps_huge_error_messages_on_a_char_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let path = seeded_db(dir.path(), "main.db");
        let raised = format!("x{}", "é".repeat(500_000));

        let result = run_query(
            &open_db(&path, OpenFlags::SQLITE_OPEN_READ_WRITE),
            "CREATE TABLE t(x); \
             CREATE TRIGGER boom BEFORE INSERT ON t BEGIN \
             SELECT RAISE(ABORT, 'x' || replace(hex(zeroblob(500000)), '00', 'é')); END; \
             INSERT INTO t VALUES (1)",
            100,
        );
        match result {
            Err(rusqlite::Error::SqliteFailure(_, Some(message))) => {
                assert!(message.len() <= QUERY_MAX_VALUE_BYTES);
                assert!(message.len() >= QUERY_MAX_VALUE_BYTES - 3);
                assert!(raised.starts_with(&message));
            }
            Err(error) => panic!("{error}"),
            Ok(_) => panic!("allowed"),
        }

        let result = run_query(
            &open_db(&path, OpenFlags::SQLITE_OPEN_READ_WRITE),
            "SELECT * FROM missing",
            100,
        );
        match result {
            Err(rusqlite::Error::SqliteFailure(_, Some(message))) => {
                assert_eq!(message, "no such table: missing");
            }
            Err(error) => panic!("{error}"),
            Ok(_) => panic!("allowed"),
        }
    }

    // authorize

    #[test]
    fn rejects_directory_pragmas() {
        let dir = tempfile::tempdir().unwrap();
        let path = seeded_db(dir.path(), "main.db");
        let target = dir.path().join("tmp");
        std::fs::create_dir(&target).unwrap();
        let target = target.to_str().unwrap();
        let connection = open_db(&path, OpenFlags::SQLITE_OPEN_READ_WRITE);

        for sql in [
            format!("PRAGMA temp_store_directory = '{target}'"),
            format!("PRAGMA temp_store_directory('{target}')"),
            format!("PRAGMA TEMP_STORE_DIRECTORY = '{target}'"),
            format!("PRAGMA Temp_Store_Directory('{target}')"),
            format!("PRAGMA data_store_directory = '{target}'"),
        ] {
            assert_denied(&connection, &sql);
        }

        query(&connection, "PRAGMA temp_store_directory", 100).unwrap();
    }

    #[test]
    fn rejects_file_attach_but_allows_in_memory_attach_and_detach() {
        let dir = tempfile::tempdir().unwrap();
        let path = seeded_db(dir.path(), "main.db");
        let other = seeded_db(dir.path(), "other.db");
        let other = other.to_str().unwrap();
        let created = dir.path().join("created.db");
        let created_str = created.to_str().unwrap();
        let relative = "wings-sqlite-attach-test.db";
        let connection = open_db(&path, OpenFlags::SQLITE_OPEN_READ_WRITE);

        for sql in [
            format!("ATTACH '{other}' AS o"),
            format!("ATTACH '{other}' || '' AS o"),
            format!("ATTACH 'file:{other}' AS o"),
            format!("ATTACH '{created_str}' AS c"),
            format!("ATTACH 'file:{created_str}?mode=rwc' AS c"),
            format!("ATTACH '{relative}' AS r"),
            "ATTACH 'file::memory:' AS m".to_string(),
            "ATTACH 'file::memory:?cache=shared' AS m".to_string(),
            "ATTACH 'file:x?vfs=memdb' AS m".to_string(),
        ] {
            assert_denied(&connection, &sql);
        }

        assert!(!created.exists());
        assert!(!Path::new(relative).exists());

        query(&connection, "ATTACH '' AS s; DETACH s", 100).unwrap();
        let results = query(
            &connection,
            "ATTACH ':memory:' AS m; CREATE TABLE m.t(x); INSERT INTO m.t VALUES (7); \
             SELECT x FROM m.t; DETACH m",
            100,
        )
        .unwrap();
        assert!(results.iter().any(|set| values(set) == [[Some("7")]]));
    }

    #[test]
    fn rejects_vacuum_into_even_when_read_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = seeded_db(dir.path(), "main.db");
        let target = dir.path().join("copy.db");
        let target_str = target.to_str().unwrap();

        for flags in [
            OpenFlags::SQLITE_OPEN_READ_ONLY,
            OpenFlags::SQLITE_OPEN_READ_WRITE,
        ] {
            let connection = open_db(&path, flags);
            assert_denied(&connection, &format!("VACUUM INTO '{target_str}'"));
            assert_denied(
                &connection,
                &format!("VACUUM main INTO 'file:{target_str}'"),
            );
            assert!(!target.exists());
        }

        query(
            &open_db(&path, OpenFlags::SQLITE_OPEN_READ_WRITE),
            "VACUUM",
            100,
        )
        .unwrap();
    }

    #[test]
    fn ignores_raising_sort_worker_threads() {
        let dir = tempfile::tempdir().unwrap();
        let path = seeded_db(dir.path(), "main.db");
        let connection = open_db(&path, OpenFlags::SQLITE_OPEN_READ_WRITE);

        for sql in [
            "PRAGMA threads = 8",
            "PRAGMA THREADS(2)",
            "PRAGMA main.threads = 1",
        ] {
            query(&connection, sql, 100).unwrap_or_else(|error| panic!("{sql}: {error}"));
            let results = query(&connection, "PRAGMA threads", 100).unwrap();
            assert_eq!(values(results.last().unwrap()), [[Some("0")]], "{sql}");
        }

        for sql in [
            "PRAGMA threads",
            "PRAGMA threads = 0",
            "PRAGMA hard_heap_limit",
            "PRAGMA mmap_size",
            "PRAGMA cache_size = 5000",
            "PRAGMA temp_store",
            "PRAGMA journal_mode = DELETE",
            "ATTACH ':memory:' AS m",
        ] {
            query(&connection, sql, 100).unwrap_or_else(|error| panic!("{sql}: {error}"));
        }
    }

    #[test]
    fn denies_setting_process_wide_heap_limits() {
        let dir = tempfile::tempdir().unwrap();
        let path = seeded_db(dir.path(), "main.db");
        let connection = open_db(&path, OpenFlags::SQLITE_OPEN_READ_WRITE);

        // SAFETY: a negative argument only queries the current limit.
        let limits = || unsafe {
            (
                ffi::sqlite3_hard_heap_limit64(-1),
                ffi::sqlite3_soft_heap_limit64(-1),
            )
        };
        let before = limits();

        for sql in [
            "PRAGMA hard_heap_limit = 1",
            "PRAGMA HARD_HEAP_LIMIT(0)",
            "pragma main.hard_heap_limit = 65536",
            "PRAGMA soft_heap_limit = 1",
            "PRAGMA Soft_Heap_Limit(0)",
            "PRAGMA soft_heap_limit = 65536",
        ] {
            assert_denied(&connection, sql);
            assert_eq!(limits(), before, "{sql}");
        }

        for sql in ["PRAGMA hard_heap_limit", "PRAGMA soft_heap_limit"] {
            query(&connection, sql, 100).unwrap_or_else(|error| panic!("{sql}: {error}"));
        }

        for sql in [
            "SELECT * FROM pragma_hard_heap_limit(1)",
            "SELECT * FROM pragma_soft_heap_limit(1)",
        ] {
            let _ = query(&connection, sql, 100);
            assert_eq!(limits(), before, "{sql}");
        }
    }
}
