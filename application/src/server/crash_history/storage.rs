use anyhow::Context;
use rusqlite::{Connection, OptionalExtension, params};
use std::{collections::HashSet, path::Path};

const FORMAT_VERSION: i64 = 1;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS crashes (
    id           INTEGER PRIMARY KEY,
    server       BLOB NOT NULL,
    at           INTEGER NOT NULL,
    exit_code    INTEGER NOT NULL,
    oom_killed   INTEGER NOT NULL,
    lines        INTEGER NOT NULL,
    bytes        INTEGER NOT NULL,
    truncated    INTEGER NOT NULL,
    stored_bytes INTEGER NOT NULL,
    log          BLOB NOT NULL,
    UNIQUE (server, at)
);
"#;

const COLUMNS: &str =
    "server, at, exit_code, oom_killed, lines, bytes, truncated, stored_bytes, log";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCrash {
    pub at: i64,
    pub exit_code: i32,
    pub oom_killed: bool,
    pub lines: u64,
    pub bytes: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retention {
    pub max_records: u64,
    pub max_age: u64,
    pub disk_budget: u64,
}

impl Retention {
    fn cutoff(&self, now: i64) -> Option<i64> {
        (self.max_age != 0).then(|| now.saturating_sub((self.max_age as i64).saturating_mul(1000)))
    }
}

fn limit(value: u64) -> i64 {
    match value {
        0 => i64::MAX,
        value => value.min(i64::MAX as u64) as i64,
    }
}

pub struct Storage {
    conn: Connection,
}

impl Storage {
    pub fn open(path: &Path) -> Result<Self, anyhow::Error> {
        let conn = Connection::open(path)
            .with_context(|| format!("opening crash history db {}", path.display()))?;

        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(SCHEMA)?;
        conn.pragma_update(None, "user_version", FORMAT_VERSION)?;

        Ok(Self { conn })
    }

    fn enforce(
        conn: &Connection,
        server: uuid::Uuid,
        now: i64,
        retention: Retention,
    ) -> rusqlite::Result<()> {
        if let Some(cutoff) = retention.cutoff(now) {
            conn.execute(
                "DELETE FROM crashes WHERE server = ?1 AND at < ?2",
                params![server.as_bytes(), cutoff],
            )?;
        }

        conn.execute(
            "DELETE FROM crashes WHERE id IN (
                SELECT id FROM (
                    SELECT id, ROW_NUMBER() OVER newest AS n, SUM(stored_bytes) OVER newest AS total
                    FROM crashes WHERE server = ?1
                    WINDOW newest AS (ORDER BY at DESC)
                ) WHERE n > 1 AND (n > ?2 OR total > ?3)
            )",
            params![
                server.as_bytes(),
                limit(retention.max_records),
                limit(retention.disk_budget)
            ],
        )?;

        Ok(())
    }

    pub fn insert(
        &mut self,
        server: uuid::Uuid,
        crash: &StoredCrash,
        log: &[u8],
        retention: Retention,
    ) -> Result<i64, anyhow::Error> {
        let tx = self.conn.transaction()?;

        let mut at = crash.at;
        {
            let mut stmt = tx.prepare(&format!(
                "INSERT OR IGNORE INTO crashes ({COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"
            ))?;
            while stmt.execute(params![
                server.as_bytes(),
                at,
                crash.exit_code,
                crash.oom_killed,
                crash.lines as i64,
                crash.bytes as i64,
                crash.truncated,
                log.len() as i64,
                log,
            ])? == 0
            {
                at += 1;
            }
        }
        Self::enforce(&tx, server, at, retention)?;
        tx.commit()?;

        Ok(at)
    }

    pub fn list(&self, server: uuid::Uuid) -> Result<Vec<StoredCrash>, anyhow::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT at, exit_code, oom_killed, lines, bytes, truncated FROM crashes
            WHERE server = ?1 ORDER BY at DESC",
        )?;

        let crashes = stmt
            .query_map(params![server.as_bytes()], |r| {
                Ok(StoredCrash {
                    at: r.get(0)?,
                    exit_code: r.get(1)?,
                    oom_killed: r.get(2)?,
                    lines: r.get::<_, i64>(3)?.max(0) as u64,
                    bytes: r.get::<_, i64>(4)?.max(0) as u64,
                    truncated: r.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?;

        Ok(crashes)
    }

    pub fn log(
        &self,
        server: uuid::Uuid,
        at: i64,
    ) -> Result<Option<(Vec<u8>, u64)>, anyhow::Error> {
        Ok(self
            .conn
            .query_row(
                "SELECT log, bytes FROM crashes WHERE server = ?1 AND at = ?2",
                params![server.as_bytes(), at],
                |r| Ok((r.get(0)?, r.get::<_, i64>(1)?.max(0) as u64)),
            )
            .optional()?)
    }

    pub fn delete(&mut self, server: uuid::Uuid, at: i64) -> Result<bool, anyhow::Error> {
        let deleted = self.conn.execute(
            "DELETE FROM crashes WHERE server = ?1 AND at = ?2",
            params![server.as_bytes(), at],
        )?;

        Ok(deleted != 0)
    }

    pub fn delete_server(&mut self, server: uuid::Uuid) -> Result<(), anyhow::Error> {
        self.conn.execute(
            "DELETE FROM crashes WHERE server = ?1",
            params![server.as_bytes()],
        )?;

        Ok(())
    }

    pub fn prune(
        &mut self,
        known: Option<&HashSet<uuid::Uuid>>,
        now: i64,
        retention: Retention,
    ) -> Result<(), anyhow::Error> {
        let tx = self.conn.transaction()?;

        let servers = {
            let mut stmt = tx.prepare("SELECT DISTINCT server FROM crashes")?;
            stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        for raw in servers {
            match uuid::Uuid::from_slice(&raw) {
                Ok(server) if known.is_none_or(|known| known.contains(&server)) => {
                    Self::enforce(&tx, server, now, retention)?;
                }
                _ => {
                    tx.execute("DELETE FROM crashes WHERE server = ?1", params![raw])?;
                }
            }
        }
        tx.commit()?;

        Ok(())
    }

    pub fn export(&self, server: uuid::Uuid, path: &Path) -> Result<bool, anyhow::Error> {
        let any: bool = self.conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM crashes WHERE server = ?1)",
            params![server.as_bytes()],
            |r| r.get(0),
        )?;
        if !any {
            return Ok(false);
        }

        {
            let export = Connection::open(path)?;
            export.execute_batch(SCHEMA)?;
            export.pragma_update(None, "user_version", FORMAT_VERSION)?;
        }

        self.conn.execute(
            "ATTACH DATABASE ?1 AS export",
            params![path.to_string_lossy().into_owned()],
        )?;
        let result = self.conn.execute(
            &format!(
                "INSERT INTO export.crashes ({COLUMNS}) SELECT {COLUMNS} FROM main.crashes WHERE server = ?1"
            ),
            params![server.as_bytes()],
        );
        self.conn.execute("DETACH DATABASE export", [])?;
        result?;

        Ok(true)
    }

    pub fn import(
        &mut self,
        server: uuid::Uuid,
        path: &Path,
        now: i64,
        retention: Retention,
    ) -> Result<(), anyhow::Error> {
        self.conn.execute(
            "ATTACH DATABASE ?1 AS import",
            params![path.to_string_lossy().into_owned()],
        )?;
        let result = (|| -> Result<(), anyhow::Error> {
            let version: i64 = self
                .conn
                .query_row("PRAGMA import.user_version", [], |r| r.get(0))?;
            if version != FORMAT_VERSION {
                return Err(anyhow::anyhow!(
                    "unsupported crash history format version {version}"
                ));
            }

            let tx = self.conn.transaction()?;
            tx.execute(
                &format!(
                    "INSERT OR IGNORE INTO main.crashes ({COLUMNS})
                    SELECT {COLUMNS} FROM import.crashes WHERE server = ?1"
                ),
                params![server.as_bytes()],
            )?;
            Self::enforce(&tx, server, now, retention)?;
            tx.commit()?;

            Ok(())
        })();
        self.conn.execute("DETACH DATABASE import", [])?;

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use uuid::Uuid;

    const A: Uuid = Uuid::from_u128(1);
    const B: Uuid = Uuid::from_u128(2);
    const NONE: Retention = Retention {
        max_records: 0,
        max_age: 0,
        disk_budget: 0,
    };

    fn open() -> (tempfile::TempDir, Storage) {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(&dir.path().join("crashes.db")).unwrap();
        (dir, storage)
    }

    fn crash(at: i64, exit_code: i32) -> StoredCrash {
        StoredCrash {
            at,
            exit_code,
            oom_killed: exit_code == 137,
            lines: 3,
            bytes: 42,
            truncated: exit_code % 2 == 0,
        }
    }

    fn records(max_records: u64) -> Retention {
        Retention {
            max_records,
            ..NONE
        }
    }

    fn ats(storage: &Storage, server: Uuid) -> Vec<i64> {
        storage.list(server).unwrap().iter().map(|c| c.at).collect()
    }

    // Storage
    #[test]
    fn list_round_trips_newest_first() {
        let (_dir, mut storage) = open();
        for (at, code) in [(1000, 1), (3000, 137), (2000, 2)] {
            assert_eq!(
                storage.insert(A, &crash(at, code), b"log", NONE).unwrap(),
                at
            );
        }

        assert_eq!(
            storage.list(A).unwrap(),
            [crash(3000, 137), crash(2000, 2), crash(1000, 1)]
        );
    }

    #[test]
    fn colliding_at_moves_forward_per_server() {
        let (_dir, mut storage) = open();
        let first = storage.insert(A, &crash(1000, 1), b"one", NONE).unwrap();
        let second = storage.insert(A, &crash(1000, 2), b"two", NONE).unwrap();
        let other = storage.insert(B, &crash(1000, 3), b"three", NONE).unwrap();

        assert_eq!(first, 1000);
        assert!(second > first);
        assert_eq!(other, 1000);
        assert_eq!(ats(&storage, A), [second, first]);
        assert_eq!(storage.log(A, first).unwrap().unwrap().0, b"one");
        assert_eq!(storage.log(A, second).unwrap().unwrap().0, b"two");
    }

    #[test]
    fn log_returns_stored_bytes_scoped_to_server() {
        let (_dir, mut storage) = open();
        storage
            .insert(A, &crash(1000, 1), &[0, 1, 2, 255], NONE)
            .unwrap();

        assert_eq!(
            storage.log(A, 1000).unwrap(),
            Some((vec![0, 1, 2, 255], 42))
        );
        assert_eq!(storage.log(B, 1000).unwrap(), None);
        assert_eq!(storage.log(A, 1001).unwrap(), None);
    }

    #[test]
    fn retention_max_records_keeps_newest() {
        let (_dir, mut storage) = open();
        for at in 1..=5 {
            storage
                .insert(A, &crash(at * 1000, 1), b"log", records(3))
                .unwrap();
        }

        assert_eq!(ats(&storage, A), [5000, 4000, 3000]);
    }

    #[test]
    fn retention_max_age_drops_old_crashes() {
        let (_dir, mut storage) = open();
        let retention = Retention {
            max_age: 10,
            ..NONE
        };
        for at in [0, 12_000, 20_000] {
            storage.insert(A, &crash(at, 1), b"log", retention).unwrap();
        }

        assert_eq!(ats(&storage, A), [20_000, 12_000]);
    }

    #[test]
    fn retention_disk_budget_counts_newest_first_and_keeps_newest() {
        let (_dir, mut storage) = open();
        let retention = Retention {
            disk_budget: 10,
            ..NONE
        };
        for at in [1000, 2000, 3000] {
            storage
                .insert(A, &crash(at, 1), b"four", retention)
                .unwrap();
        }
        assert_eq!(ats(&storage, A), [3000, 2000]);

        storage
            .insert(A, &crash(4000, 1), &[7; 50], retention)
            .unwrap();
        assert_eq!(ats(&storage, A), [4000]);
    }

    #[test]
    fn zero_limits_do_not_apply() {
        let (_dir, mut storage) = open();
        for at in [1, 2, 3] {
            storage.insert(A, &crash(at, 1), &[0; 4096], NONE).unwrap();
        }
        storage.prune(None, i64::MAX / 2, NONE).unwrap();

        assert_eq!(ats(&storage, A), [3, 2, 1]);
    }

    #[test]
    fn retention_on_insert_only_touches_that_server() {
        let (_dir, mut storage) = open();
        for at in [1000, 2000, 3000] {
            storage.insert(A, &crash(at, 1), b"log", NONE).unwrap();
        }
        for at in [1000, 2000] {
            storage
                .insert(B, &crash(at, 1), b"log", records(1))
                .unwrap();
        }

        assert_eq!(ats(&storage, A), [3000, 2000, 1000]);
        assert_eq!(ats(&storage, B), [2000]);
    }

    #[test]
    fn delete_and_delete_server() {
        let (_dir, mut storage) = open();
        storage.insert(A, &crash(1000, 1), b"log", NONE).unwrap();
        storage.insert(A, &crash(2000, 1), b"log", NONE).unwrap();
        storage.insert(B, &crash(1000, 1), b"log", NONE).unwrap();

        assert!(storage.delete(A, 1000).unwrap());
        assert!(!storage.delete(A, 1000).unwrap());
        assert_eq!(storage.log(A, 1000).unwrap(), None);
        assert_eq!(ats(&storage, B), [1000]);

        storage.delete_server(A).unwrap();
        assert!(storage.list(A).unwrap().is_empty());
        assert_eq!(ats(&storage, B), [1000]);
    }

    #[test]
    fn prune_applies_retention_and_drops_unknown_servers() {
        let (_dir, mut storage) = open();
        for server in [A, B] {
            for at in [1000, 2000] {
                storage.insert(server, &crash(at, 1), b"log", NONE).unwrap();
            }
        }

        storage.prune(None, 3000, records(1)).unwrap();
        assert_eq!(ats(&storage, A), [2000]);
        assert_eq!(ats(&storage, B), [2000]);

        storage
            .prune(Some(&HashSet::from([A])), 3000, NONE)
            .unwrap();
        assert_eq!(ats(&storage, A), [2000]);
        assert!(storage.list(B).unwrap().is_empty());
    }

    #[test]
    fn export_import_round_trips_only_requested_server() {
        let (dir, mut source) = open();
        source.insert(A, &crash(1000, 1), b"first", NONE).unwrap();
        source
            .insert(A, &crash(2000, 137), b"second", NONE)
            .unwrap();
        source.insert(B, &crash(1500, 3), b"other", NONE).unwrap();
        let path = dir.path().join("export.db");

        assert!(
            !source
                .export(Uuid::from_u128(3), &dir.path().join("empty.db"))
                .unwrap()
        );
        assert!(source.export(A, &path).unwrap());

        let (_dest_dir, mut dest) = open();
        dest.import(A, &path, 3000, NONE).unwrap();
        dest.import(B, &path, 3000, NONE).unwrap();

        assert_eq!(dest.list(A).unwrap(), source.list(A).unwrap());
        assert_eq!(dest.log(A, 1000).unwrap(), source.log(A, 1000).unwrap());
        assert_eq!(dest.log(A, 2000).unwrap(), source.log(A, 2000).unwrap());
        assert!(dest.list(B).unwrap().is_empty());
    }

    #[test]
    fn import_keeps_existing_rows_on_conflict() {
        let (dir, mut source) = open();
        source.insert(A, &crash(1000, 2), b"remote", NONE).unwrap();
        source.insert(A, &crash(2000, 2), b"remote", NONE).unwrap();
        let path = dir.path().join("export.db");
        source.export(A, &path).unwrap();

        let (_dest_dir, mut dest) = open();
        dest.insert(A, &crash(1000, 1), b"local", NONE).unwrap();
        dest.import(A, &path, 3000, NONE).unwrap();

        assert_eq!(dest.list(A).unwrap(), [crash(2000, 2), crash(1000, 1)]);
        assert_eq!(dest.log(A, 1000).unwrap().unwrap().0, b"local");
    }

    #[test]
    fn import_applies_local_retention_after_merging() {
        let (dir, mut source) = open();
        source.insert(A, &crash(1000, 1), b"log", NONE).unwrap();
        source.insert(A, &crash(3000, 1), b"log", NONE).unwrap();
        let path = dir.path().join("export.db");
        source.export(A, &path).unwrap();

        let (_dest_dir, mut dest) = open();
        dest.insert(A, &crash(2000, 1), b"log", NONE).unwrap();
        dest.import(A, &path, 4000, records(2)).unwrap();

        assert_eq!(ats(&dest, A), [3000, 2000]);
    }

    #[test]
    fn import_rejects_unknown_version_without_changes() {
        let (dir, mut source) = open();
        source.insert(A, &crash(1000, 1), b"log", NONE).unwrap();
        let path = dir.path().join("export.db");
        source.export(A, &path).unwrap();
        rusqlite::Connection::open(&path)
            .unwrap()
            .pragma_update(None, "user_version", 2)
            .unwrap();

        let (_dest_dir, mut dest) = open();
        dest.insert(A, &crash(500, 1), b"log", NONE).unwrap();
        assert!(dest.import(A, &path, 2000, NONE).is_err());
        assert_eq!(ats(&dest, A), [500]);

        rusqlite::Connection::open(&path)
            .unwrap()
            .pragma_update(None, "user_version", 1)
            .unwrap();
        dest.import(A, &path, 2000, NONE).unwrap();
        assert_eq!(ats(&dest, A), [1000, 500]);
    }

    #[test]
    fn reopen_preserves_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("crashes.db");
        {
            let mut storage = Storage::open(&path).unwrap();
            storage.insert(A, &crash(1000, 137), b"log", NONE).unwrap();
        }

        let storage = Storage::open(&path).unwrap();
        assert_eq!(storage.list(A).unwrap(), [crash(1000, 137)]);
        assert_eq!(storage.log(A, 1000).unwrap(), Some((b"log".to_vec(), 42)));
    }
}
