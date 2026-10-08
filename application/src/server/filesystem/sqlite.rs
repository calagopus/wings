use crate::io::SafeSliceExt;
use rusqlite::{
    Connection, OpenFlags,
    fallible_iterator::FallibleIterator,
    ffi,
    hooks::{AuthAction, AuthContext, Authorization},
};
use serde::Serialize;
use std::{
    cell::Cell,
    ffi::{c_int, c_void},
    marker::PhantomData,
    path::Path,
    sync::{
        OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use utoipa::ToSchema;

pub const QUERY_MAX_LENGTH: usize = 65535;
pub const QUERY_DEFAULT_ROWS: u32 = 100;
pub const QUERY_MAX_ROWS: u32 = 1000;
const QUERY_MAX_BYTES: usize = 4 * 1024 * 1024;
const QUERY_MAX_VALUE_BYTES: usize = 256 * 1024;
const QUERY_SQLITE_LENGTH_LIMIT: i32 = 32 * 1024 * 1024;
/// Room for a few values of [`QUERY_SQLITE_LENGTH_LIMIT`] plus working memory.
const QUERY_MEMORY_LIMIT: usize = 128 * 1024 * 1024;
pub const QUERY_DEADLINE: Duration = Duration::from_secs(15);
pub const QUERY_BUSY_TIMEOUT: Duration = Duration::from_millis(3000);
const DENIED_PRAGMAS: &[&str] = &[
    "temp_store_directory",
    "data_store_directory",
    "hard_heap_limit",
    "soft_heap_limit",
];

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

#[derive(ToSchema, Serialize, Clone)]
pub struct QueryResultSet {
    pub columns: Vec<QueryColumn>,
    pub rows: Vec<Vec<QueryValue>>,
    pub rows_affected: u64,
    pub truncated: bool,
}

/// SQLite memory shared by every query a server runs at the same time.
pub struct QueryMemory {
    used: AtomicUsize,
    limit: usize,
}

impl QueryMemory {
    pub const fn new(limit: usize) -> Self {
        Self {
            used: AtomicUsize::new(0),
            limit,
        }
    }

    fn reserve(&self, size: usize) -> bool {
        self.used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(size).filter(|used| *used <= self.limit)
            })
            .is_ok()
    }

    fn release(&self, size: usize) {
        self.used.fetch_sub(size, Ordering::AcqRel);
    }

    fn settle(&self, charged: usize, actual: usize) {
        if actual > charged {
            self.used.fetch_add(actual - charged, Ordering::AcqRel);
        } else {
            self.release(charged - actual);
        }
    }
}

impl Default for QueryMemory {
    fn default() -> Self {
        Self::new(QUERY_MEMORY_LIMIT)
    }
}

#[derive(Clone, Copy)]
struct MemoryBudget {
    used: usize,
    memory: *const QueryMemory,
}

thread_local! {
    static MEMORY_BUDGET: Cell<Option<MemoryBudget>> = const { Cell::new(None) };
}

struct MemoryBudgetGuard<'a> {
    memory: &'a QueryMemory,
    _thread_bound: PhantomData<*const ()>,
}

impl<'a> MemoryBudgetGuard<'a> {
    fn new(memory: &'a QueryMemory) -> Self {
        debug_assert!(MEMORY_BUDGET.get().is_none());
        MEMORY_BUDGET.set(Some(MemoryBudget { used: 0, memory }));

        Self {
            memory,
            _thread_bound: PhantomData,
        }
    }
}

impl Drop for MemoryBudgetGuard<'_> {
    fn drop(&mut self) {
        if let Some(budget) = MEMORY_BUDGET.take() {
            self.memory.release(budget.used);
        }
    }
}

/// SQLite's own allocator, which the budgeted wrappers forward to. Every pointer
/// SQLite hands them was returned by these functions, so passing it back is sound.
struct DefaultAllocator {
    malloc: unsafe extern "C" fn(c_int) -> *mut c_void,
    free: unsafe extern "C" fn(*mut c_void),
    realloc: unsafe extern "C" fn(*mut c_void, c_int) -> *mut c_void,
    size: unsafe extern "C" fn(*mut c_void) -> c_int,
}

impl DefaultAllocator {
    unsafe fn allocation_size(&self, pointer: *mut c_void) -> usize {
        if pointer.is_null() {
            return 0;
        }

        // SAFETY: pointer came from this allocator's malloc or realloc, see DefaultAllocator
        usize::try_from(unsafe { (self.size)(pointer) }).unwrap_or(0)
    }
}

static DEFAULT_ALLOCATOR: OnceLock<Option<DefaultAllocator>> = OnceLock::new();

fn default_allocator() -> Option<&'static DefaultAllocator> {
    DEFAULT_ALLOCATOR.get().and_then(Option::as_ref)
}

/// Runs `f` against this thread's budget, or returns `None` when no query is running here.
fn with_budget<R>(f: impl FnOnce(&QueryMemory, &mut usize) -> R) -> Option<R> {
    MEMORY_BUDGET
        .try_with(|cell| {
            let mut budget = cell.get()?;
            // SAFETY: MEMORY_BUDGET only holds this pointer while the MemoryBudgetGuard that
            // borrows the QueryMemory is alive, and the guard clears it on drop.
            let result = f(unsafe { &*budget.memory }, &mut budget.used);
            cell.set(Some(budget));

            Some(result)
        })
        .ok()
        .flatten()
}

unsafe extern "C" fn budgeted_malloc(size: c_int) -> *mut c_void {
    let Some(allocator) = default_allocator() else {
        return std::ptr::null_mut();
    };

    with_budget(|memory, used| {
        let requested = usize::try_from(size).unwrap_or(0);
        if !memory.reserve(requested) {
            return std::ptr::null_mut();
        }

        // SAFETY: forwards SQLite's own allocator the size SQLite asked for; the pointer it
        // returned is the only one measured
        let pointer = unsafe { (allocator.malloc)(size) };
        let allocated = unsafe { allocator.allocation_size(pointer) };
        memory.settle(requested, allocated);
        *used = used.saturating_add(allocated);

        pointer
    })
    // SAFETY: a plain forward to SQLite's own allocator
    .unwrap_or_else(|| unsafe { (allocator.malloc)(size) })
}

unsafe extern "C" fn budgeted_free(pointer: *mut c_void) {
    let Some(allocator) = default_allocator() else {
        return;
    };

    with_budget(|memory, used| {
        // SAFETY: SQLite only frees pointers its allocator returned, see DefaultAllocator
        let freed = unsafe { allocator.allocation_size(pointer) }.min(*used);
        *used -= freed;
        memory.release(freed);
    });

    // SAFETY: a plain forward to SQLite's own allocator
    unsafe { (allocator.free)(pointer) };
}

unsafe extern "C" fn budgeted_realloc(pointer: *mut c_void, size: c_int) -> *mut c_void {
    let Some(allocator) = default_allocator() else {
        return std::ptr::null_mut();
    };

    with_budget(|memory, used| {
        // SAFETY: SQLite only reallocates pointers its allocator returned, see DefaultAllocator;
        // the resized pointer is measured before anything else sees it
        let old = unsafe { allocator.allocation_size(pointer) }.min(*used);
        let growth = usize::try_from(size).unwrap_or(0).saturating_sub(old);
        if !memory.reserve(growth) {
            return std::ptr::null_mut();
        }

        let resized = unsafe { (allocator.realloc)(pointer, size) };
        if resized.is_null() {
            memory.release(growth);
            return resized;
        }

        let allocated = unsafe { allocator.allocation_size(resized) };
        memory.settle(old + growth, allocated);
        *used = *used - old + allocated;

        resized
    })
    // SAFETY: a plain forward to SQLite's own allocator
    .unwrap_or_else(|| unsafe { (allocator.realloc)(pointer, size) })
}

/// Wraps SQLite's allocator so `run_query` can cap what a server's queries allocate on
/// their own threads. Must run before any connection is opened; every other connection
/// keeps using the default allocator unchanged.
fn install_allocator() {
    DEFAULT_ALLOCATOR.get_or_init(|| {
        let mut methods = ffi::sqlite3_mem_methods {
            xMalloc: None,
            xFree: None,
            xRealloc: None,
            xSize: None,
            xRoundup: None,
            xInit: None,
            xShutdown: None,
            pAppData: std::ptr::null_mut(),
        };

        // SAFETY: SQLITE_CONFIG_GETMALLOC writes one sqlite3_mem_methods through the pointer,
        // and is refused with SQLITE_MISUSE once SQLite is initialized.
        let got = unsafe {
            ffi::sqlite3_config(
                ffi::SQLITE_CONFIG_GETMALLOC,
                &mut methods as *mut ffi::sqlite3_mem_methods,
            )
        };
        if got != ffi::SQLITE_OK {
            return None;
        }

        let (Some(malloc), Some(free), Some(realloc), Some(size)) = (
            methods.xMalloc,
            methods.xFree,
            methods.xRealloc,
            methods.xSize,
        ) else {
            return None;
        };

        let budgeted = ffi::sqlite3_mem_methods {
            xMalloc: Some(budgeted_malloc),
            xFree: Some(budgeted_free),
            xRealloc: Some(budgeted_realloc),
            ..methods
        };
        // SAFETY: SQLITE_CONFIG_MALLOC copies the methods out of the pointer, and is refused
        // with SQLITE_MISUSE once SQLite is initialized.
        let set = unsafe {
            ffi::sqlite3_config(
                ffi::SQLITE_CONFIG_MALLOC,
                &budgeted as *const ffi::sqlite3_mem_methods,
            )
        };
        if set != ffi::SQLITE_OK {
            return None;
        }

        Some(DefaultAllocator {
            malloc,
            free,
            realloc,
            size,
        })
    });
}

/// Opens a connection with the budgeted allocator installed, which must happen before
/// the first connection in the process.
pub fn open(path: &Path, flags: OpenFlags) -> Result<Connection, rusqlite::Error> {
    install_allocator();
    Connection::open_with_flags(path, flags)
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
    connection: Connection,
    sql: &str,
    max_rows: usize,
    memory: &QueryMemory,
) -> Result<Vec<QueryResultSet>, rusqlite::Error> {
    if default_allocator().is_none() {
        return Err(rusqlite::Error::SqliteFailure(
            ffi::Error::new(ffi::SQLITE_MISUSE),
            Some("sqlite memory budget is unavailable".to_string()),
        ));
    }

    let _budget = MemoryBudgetGuard::new(memory);
    let results = execute_query(&connection, sql, max_rows).map_err(truncate_error);
    // the connection's frees must land while the budget guard is still installed
    drop(connection);

    results
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

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::ErrorCode;
    use std::path::PathBuf;

    const TINY_LIMIT: usize = 4 * 1024 * 1024;

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
        query_with_limit(connection, sql, max_rows, QUERY_MEMORY_LIMIT)
    }

    fn query_with_limit(
        connection: &Connection,
        sql: &str,
        max_rows: usize,
        limit: usize,
    ) -> Result<Vec<QueryResultSet>, rusqlite::Error> {
        let memory = QueryMemory::new(limit);
        let _budget = MemoryBudgetGuard::new(&memory);
        execute_query(connection, sql, max_rows)
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

    fn assert_out_of_memory(result: Result<Vec<QueryResultSet>, rusqlite::Error>, sql: &str) {
        match result {
            Err(rusqlite::Error::SqliteFailure(error, _)) => {
                assert_eq!(error.code, ErrorCode::OutOfMemory, "{sql}");
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
            open_db(&path, OpenFlags::SQLITE_OPEN_READ_WRITE),
            "CREATE TABLE t(x); \
             CREATE TRIGGER boom BEFORE INSERT ON t BEGIN \
             SELECT RAISE(ABORT, 'x' || replace(hex(zeroblob(500000)), '00', 'é')); END; \
             INSERT INTO t VALUES (1)",
            100,
            &QueryMemory::default(),
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
            open_db(&path, OpenFlags::SQLITE_OPEN_READ_WRITE),
            "SELECT * FROM missing",
            100,
            &QueryMemory::default(),
        );
        match result {
            Err(rusqlite::Error::SqliteFailure(_, Some(message))) => {
                assert_eq!(message, "no such table: missing");
            }
            Err(error) => panic!("{error}"),
            Ok(_) => panic!("allowed"),
        }
    }

    // budgeted_malloc

    #[test]
    fn hostile_queries_fail_with_out_of_memory_and_release_budget() {
        let dir = tempfile::tempdir().unwrap();
        let path = seeded_db(dir.path(), "main.db");
        let connection = open_db(&path, OpenFlags::SQLITE_OPEN_READ_WRITE);
        let wide_row = format!("SELECT {}", ["randomblob(1000000)"; 8].join(", "));

        for sql in [
            wide_row.as_str(),
            "ATTACH ':memory:' AS m; CREATE TABLE m.t(x); \
             WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM c WHERE i < 10000) \
             INSERT INTO m.t SELECT randomblob(1000) FROM c",
            "PRAGMA temp_store = MEMORY; CREATE TEMP TABLE big AS \
             WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM c WHERE i < 10000) \
             SELECT randomblob(1000) AS x FROM c",
            "WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM c WHERE i < 10000) \
             SELECT length(group_concat(hex(randomblob(1000)))) FROM c",
        ] {
            assert_out_of_memory(query_with_limit(&connection, sql, 100, TINY_LIMIT), sql);

            let results = query_with_limit(&connection, "SELECT 1", 100, TINY_LIMIT).unwrap();
            assert_eq!(values(results.last().unwrap()), [[Some("1")]], "{sql}");

            let unmetered = Connection::open_in_memory().unwrap();
            unmetered
                .execute_batch(
                    "CREATE TABLE t(x); \
                     WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM c WHERE i < 10000) \
                     INSERT INTO t SELECT randomblob(1000) FROM c",
                )
                .unwrap();
        }
    }

    #[test]
    fn budget_does_not_limit_other_threads() {
        let dir = tempfile::tempdir().unwrap();
        let path = seeded_db(dir.path(), "main.db");
        let (holding_tx, holding_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();

        let hostile = std::thread::spawn(move || {
            let connection = open_db(&path, OpenFlags::SQLITE_OPEN_READ_WRITE);
            let mut gate = Some((holding_tx, release_rx));
            connection
                .update_hook(Some(move |_, _: &str, table: &str, _| {
                    if table == "grow"
                        && let Some((holding, release)) = gate.take()
                    {
                        holding.send(()).unwrap();
                        let _ = release.recv_timeout(Duration::from_secs(60));
                    }
                }))
                .unwrap();

            query_with_limit(
                &connection,
                "ATTACH ':memory:' AS m; CREATE TABLE m.hold(x); CREATE TABLE m.grow(x); \
                 WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM c WHERE i < 2000) \
                 INSERT INTO m.hold SELECT randomblob(1000) FROM c; \
                 WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM c WHERE i < 10000) \
                 INSERT INTO m.grow SELECT randomblob(1000) FROM c",
                100,
                TINY_LIMIT,
            )
        });

        holding_rx.recv_timeout(Duration::from_secs(60)).unwrap();

        let mut content = vec![0; 8 * 1024 * 1024];
        rand::fill(&mut content);
        let mut storage =
            crate::server::diff::storage::Storage::open(&dir.path().join("diff.db"), 1).unwrap();
        let file_id = storage.upsert_file("world/level.dat").unwrap();
        let revision = storage.insert_snapshot(file_id, None, &content, 0).unwrap();
        assert!(storage.reconstruct(revision).unwrap() == content);

        release_tx.send(()).unwrap();
        assert_out_of_memory(hostile.join().unwrap(), "hostile grow");
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
            "PRAGMA mmap_size = 4096",
            "PRAGMA cache_size = 5000",
            "PRAGMA temp_store = MEMORY",
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

    // QueryMemory

    #[test]
    fn concurrent_queries_share_one_pool() {
        let dir = tempfile::tempdir().unwrap();
        let path = seeded_db(dir.path(), "main.db");
        let shared = QueryMemory::new(TINY_LIMIT);
        let (holding_tx, holding_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let big_value = "SELECT length(randomblob(2500000))";

        std::thread::scope(|scope| {
            let holder = scope.spawn(|| {
                let connection = open_db(&path, OpenFlags::SQLITE_OPEN_READ_WRITE);
                let mut gate = Some((holding_tx, release_rx));
                connection
                    .update_hook(Some(move |_, _: &str, table: &str, _| {
                        if table == "grow"
                            && let Some((holding, release)) = gate.take()
                        {
                            holding.send(()).unwrap();
                            let _ = release.recv_timeout(Duration::from_secs(60));
                        }
                    }))
                    .unwrap();

                run_query(
                    connection,
                    "ATTACH ':memory:' AS m; CREATE TABLE m.hold(x); CREATE TABLE m.grow(x); \
                     WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM c WHERE i < 2500) \
                     INSERT INTO m.hold SELECT randomblob(1000) FROM c; \
                     WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM c WHERE i < 10000) \
                     INSERT INTO m.grow SELECT randomblob(1000) FROM c",
                    100,
                    &shared,
                )
            });

            holding_rx.recv_timeout(Duration::from_secs(60)).unwrap();

            let contender = run_query(
                open_db(&path, OpenFlags::SQLITE_OPEN_READ_WRITE),
                big_value,
                100,
                &shared,
            );
            let separate = run_query(
                open_db(&path, OpenFlags::SQLITE_OPEN_READ_WRITE),
                big_value,
                100,
                &QueryMemory::new(TINY_LIMIT),
            );

            release_tx.send(()).unwrap();
            assert_out_of_memory(holder.join().unwrap(), "holder grow");
            assert_out_of_memory(contender, "contender");
            assert_eq!(
                values(separate.unwrap().last().unwrap()),
                [[Some("2500000")]]
            );
        });

        assert_eq!(shared.used.load(Ordering::Acquire), 0);
        let results = run_query(
            open_db(&path, OpenFlags::SQLITE_OPEN_READ_WRITE),
            big_value,
            100,
            &shared,
        )
        .unwrap();
        assert_eq!(values(results.last().unwrap()), [[Some("2500000")]]);
    }

    #[test]
    fn consumed_connection_returns_all_memory_to_pool() {
        let dir = tempfile::tempdir().unwrap();
        let path = seeded_db(dir.path(), "main.db");
        let memory = QueryMemory::new(TINY_LIMIT);

        let results = run_query(
            open_db(&path, OpenFlags::SQLITE_OPEN_READ_WRITE),
            "PRAGMA cache_size = 100000; ATTACH ':memory:' AS m; CREATE TABLE m.t(x); \
             WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM c WHERE i < 1000) \
             INSERT INTO m.t SELECT randomblob(1000) FROM c; \
             SELECT count(*) FROM m.t",
            100,
            &memory,
        )
        .unwrap();
        assert_eq!(values(results.last().unwrap()), [[Some("1000")]]);
        assert_eq!(memory.used.load(Ordering::Acquire), 0);

        let sql = "ATTACH ':memory:' AS m; CREATE TABLE m.t(x); \
                   WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM c WHERE i < 10000) \
                   INSERT INTO m.t SELECT randomblob(1000) FROM c";
        assert_out_of_memory(
            run_query(
                open_db(&path, OpenFlags::SQLITE_OPEN_READ_WRITE),
                sql,
                100,
                &memory,
            ),
            sql,
        );
        assert_eq!(memory.used.load(Ordering::Acquire), 0);
    }
}
