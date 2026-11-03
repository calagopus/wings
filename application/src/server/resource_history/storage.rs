use crate::{
    config::ResourceHistoryTier,
    server::{
        resource_history::accumulator::{Bucket, Limits, Row, Span},
        state::ServerState,
    },
};
use anyhow::Context;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

const FORMAT_VERSION: i64 = 1;

pub struct Entry {
    pub uuid: uuid::Uuid,
    pub rows: Vec<Row>,
    pub limits: Option<(i64, Limits)>,
    pub spans: Vec<Span>,
}

pub type Batch = Vec<Entry>;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS servers (
    id   INTEGER PRIMARY KEY,
    uuid BLOB NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS tiers (
    step      INTEGER PRIMARY KEY,
    retention INTEGER NOT NULL,
    retired   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS limits (
    server INTEGER NOT NULL,
    at     INTEGER NOT NULL,
    memory INTEGER NOT NULL,
    cpu    INTEGER NOT NULL,
    PRIMARY KEY (server, at)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS states (
    server INTEGER NOT NULL,
    since  INTEGER NOT NULL,
    until  INTEGER NOT NULL,
    state  INTEGER NOT NULL,
    PRIMARY KEY (server, since)
) WITHOUT ROWID;
"#;

impl Span {
    fn from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            since: r.get(0)?,
            until: r.get(1)?,
            state: match r.get::<_, i64>(2)? {
                1 => ServerState::Starting,
                2 => ServerState::Stopping,
                3 => ServerState::Running,
                _ => ServerState::Offline,
            },
        })
    }

    fn db_state(&self) -> i64 {
        match self.state {
            ServerState::Offline => 0,
            ServerState::Starting => 1,
            ServerState::Stopping => 2,
            ServerState::Running => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredTier {
    pub step: u64,
    pub retention: u64,
    pub retired: bool,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PointRow {
    pub n: i64,
    pub cpu_sum: i64,
    pub cpu_max: i64,
    pub mem_sum: i64,
    pub mem_max: i64,
    pub rx: i64,
    pub tx: i64,
}

#[derive(Default)]
pub struct RawHistory {
    pub step: u64,
    /// First second the chosen tier has data for, `None` when there is none at all.
    pub covered_from: Option<i64>,
    pub rows: HashMap<usize, PointRow>,
    pub disks: HashMap<usize, i64>,
    pub disk_before: Option<i64>,
    pub limits: Vec<(i64, Limits)>,
    /// Spans overlapping the range, ordered and without overlaps.
    pub spans: Vec<Span>,
}

pub struct Storage {
    conn: Connection,
    server_ids: HashMap<uuid::Uuid, i64>,
}

impl Storage {
    fn samples_table(schema: &str, step: u64) -> String {
        format!("{schema}.samples_{step}")
    }

    fn create_samples_table(conn: &Connection, schema: &str, step: u64) -> rusqlite::Result<()> {
        conn.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS {} (
                server  INTEGER NOT NULL,
                b       INTEGER NOT NULL,
                n       INTEGER NOT NULL,
                cpu_sum INTEGER NOT NULL,
                cpu_max INTEGER NOT NULL,
                mem_sum INTEGER NOT NULL,
                mem_max INTEGER NOT NULL,
                disk    INTEGER NOT NULL,
                rx      INTEGER NOT NULL,
                tx      INTEGER NOT NULL,
                PRIMARY KEY (server, b)
            ) WITHOUT ROWID;",
            Self::samples_table(schema, step)
        ))
    }

    /// Fills `dst_step` buckets missing in `dst` from `src`, whose step must divide `dst_step`.
    /// Only buckets the source covers completely are filled, so a source pruned in the middle
    /// of a destination bucket never produces a short one.
    fn backfill(
        tx: &Transaction<'_>,
        src_schema: &str,
        src_step: u64,
        dst_step: u64,
        remap: Option<(i64, i64)>,
    ) -> rusqlite::Result<usize> {
        let k = (dst_step / src_step) as i64;
        let src = Self::samples_table(src_schema, src_step);
        let dst = Self::samples_table("main", dst_step);
        let (filter, server) = match remap {
            Some((from, to)) => (format!("WHERE server = {from}"), to.to_string()),
            None => (String::new(), "a.server".to_string()),
        };

        // the WHERE keeps sqlite from parsing ON CONFLICT as a join constraint
        tx.execute(
            &format!(
                "WITH m AS (SELECT server, MIN(b) AS mb FROM {src} {filter} GROUP BY server),
                a AS (
                    SELECT s.server AS server, s.b / {k} AS nb, SUM(s.n) AS n,
                        SUM(s.cpu_sum) AS cpu_sum, MAX(s.cpu_max) AS cpu_max,
                        SUM(s.mem_sum) AS mem_sum, MAX(s.mem_max) AS mem_max,
                        SUM(s.rx) AS rx, SUM(s.tx) AS tx, MAX(s.b) AS lb
                    FROM {src} s JOIN m ON m.server = s.server
                    WHERE (s.b / {k}) * {k} >= m.mb
                    GROUP BY s.server, nb
                )
                INSERT INTO {dst} (server, b, n, cpu_sum, cpu_max, mem_sum, mem_max, disk, rx, tx)
                SELECT {server}, a.nb, a.n, a.cpu_sum, a.cpu_max, a.mem_sum, a.mem_max, s.disk, a.rx, a.tx
                FROM a JOIN {src} s ON s.server = a.server AND s.b = a.lb
                WHERE true
                ON CONFLICT DO NOTHING"
            ),
            [],
        )
    }

    /// Picks the coarsest tier whose step fits into one slice of `width` seconds and whose data
    /// reaches back to `start`. Without such a tier the fitting one reaching back the furthest is
    /// used, and when no tier is fine enough the finest one.
    pub fn choose_tier(
        candidates: &[(u64, Option<i64>)],
        start: i64,
        width: i64,
    ) -> Option<(u64, Option<i64>)> {
        let fitting = candidates
            .iter()
            .filter(|(step, _)| *step as i64 <= width.max(1));

        fitting
            .clone()
            .filter(|(_, from)| from.is_some_and(|from| from <= start))
            .max_by_key(|(step, _)| *step)
            .or_else(|| {
                fitting
                    .filter(|(_, from)| from.is_some())
                    .min_by_key(|(step, from)| (*from, std::cmp::Reverse(*step)))
            })
            .or_else(|| candidates.iter().min_by_key(|(step, _)| *step))
            .copied()
    }

    pub fn open(path: &Path) -> Result<Self, anyhow::Error> {
        let conn = Connection::open(path)
            .with_context(|| format!("opening resource history db {}", path.display()))?;

        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        conn.execute_batch(SCHEMA)?;
        conn.pragma_update(None, "user_version", FORMAT_VERSION)?;

        Ok(Self {
            conn,
            server_ids: HashMap::new(),
        })
    }

    fn tiers_in(conn: &Connection, schema: &str) -> rusqlite::Result<Vec<StoredTier>> {
        let mut stmt = conn.prepare(&format!(
            "SELECT step, retention, retired FROM {schema}.tiers ORDER BY step"
        ))?;
        stmt.query_map([], |r| {
            Ok(StoredTier {
                step: r.get::<_, i64>(0)?.max(1) as u64,
                retention: r.get::<_, i64>(1)?.max(0) as u64,
                retired: r.get(2)?,
            })
        })?
        .collect()
    }

    pub fn tiers(&self) -> Result<Vec<StoredTier>, anyhow::Error> {
        Ok(Self::tiers_in(&self.conn, "main")?)
    }

    /// Brings the stored tiers in line with the configured ones. New tiers are backfilled from
    /// stored tiers whose step divides theirs, removed tiers are retired: no longer written,
    /// but kept and pruned under their last retention until they are empty.
    pub fn reconcile(&mut self, configured: &[ResourceHistoryTier]) -> Result<(), anyhow::Error> {
        let stored = self.tiers()?;

        for tier in configured {
            let existing = stored.iter().find(|t| t.step == tier.step);
            if existing.is_some_and(|t| !t.retired && t.retention == tier.retention) {
                continue;
            }

            let tx = self.conn.transaction()?;
            Self::create_samples_table(&tx, "main", tier.step)?;
            tx.execute(
                "INSERT INTO tiers (step, retention, retired) VALUES (?1, ?2, 0)
                ON CONFLICT (step) DO UPDATE SET retention = excluded.retention, retired = 0",
                params![tier.step as i64, tier.retention as i64],
            )?;

            if existing.is_none_or(|t| t.retired) {
                let mut sources: Vec<u64> = stored
                    .iter()
                    .map(|t| t.step)
                    .filter(|&s| s != tier.step && tier.step % s == 0)
                    .collect();
                sources.sort_unstable_by(|a, b| b.cmp(a));

                for source in sources {
                    let filled = Self::backfill(&tx, "main", source, tier.step, None)?;
                    tracing::info!(
                        step = tier.step,
                        source,
                        filled,
                        "backfilled resource history tier"
                    );
                }
            }
            tx.commit()?;
        }

        for tier in &stored {
            if !tier.retired && !configured.iter().any(|t| t.step == tier.step) {
                self.conn.execute(
                    "UPDATE tiers SET retired = 1 WHERE step = ?1",
                    params![tier.step as i64],
                )?;
                tracing::info!(step = tier.step, "retired resource history tier");
            }
        }

        Ok(())
    }

    fn server_id(&mut self, uuid: uuid::Uuid) -> rusqlite::Result<i64> {
        if let Some(&id) = self.server_ids.get(&uuid) {
            return Ok(id);
        }

        self.conn.execute(
            "INSERT INTO servers (uuid) VALUES (?1) ON CONFLICT (uuid) DO NOTHING",
            params![uuid.as_bytes()],
        )?;
        let id = self.conn.query_row(
            "SELECT id FROM servers WHERE uuid = ?1",
            params![uuid.as_bytes()],
            |r| r.get(0),
        )?;
        self.server_ids.insert(uuid, id);

        Ok(id)
    }

    fn find_server_id(&self, uuid: uuid::Uuid) -> rusqlite::Result<Option<i64>> {
        if let Some(&id) = self.server_ids.get(&uuid) {
            return Ok(Some(id));
        }

        self.conn
            .query_row(
                "SELECT id FROM servers WHERE uuid = ?1",
                params![uuid.as_bytes()],
                |r| r.get(0),
            )
            .optional()
    }

    pub fn latest_limits(&self, uuid: uuid::Uuid) -> Result<Option<Limits>, anyhow::Error> {
        let Some(id) = self.find_server_id(uuid)? else {
            return Ok(None);
        };

        Ok(self
            .conn
            .query_row(
                "SELECT memory, cpu FROM limits WHERE server = ?1 ORDER BY at DESC LIMIT 1",
                params![id],
                |r| {
                    Ok(Limits {
                        memory: r.get(0)?,
                        cpu: r.get(1)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn last_span(&self, uuid: uuid::Uuid) -> Result<Option<Span>, anyhow::Error> {
        let Some(id) = self.find_server_id(uuid)? else {
            return Ok(None);
        };

        Ok(self
            .conn
            .query_row(
                "SELECT since, until, state FROM states WHERE server = ?1 ORDER BY since DESC LIMIT 1",
                params![id],
                Span::from_row,
            )
            .optional()?)
    }

    pub fn write(&mut self, batch: Batch) -> Result<(), anyhow::Error> {
        let mut resolved = Vec::with_capacity(batch.len());
        for entry in batch {
            resolved.push((self.server_id(entry.uuid)?, entry));
        }

        let tx = self.conn.transaction()?;
        let mut statements: HashMap<u64, rusqlite::CachedStatement<'_>> = HashMap::new();

        for (
            id,
            Entry {
                rows,
                limits,
                spans,
                ..
            },
        ) in &resolved
        {
            for row in rows {
                let stmt = match statements.entry(row.step) {
                    std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                    std::collections::hash_map::Entry::Vacant(e) => e.insert(tx.prepare_cached(
                        &format!(
                            "INSERT INTO {} (server, b, n, cpu_sum, cpu_max, mem_sum, mem_max, disk, rx, tx)
                            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                            ON CONFLICT (server, b) DO UPDATE SET
                                n = n + excluded.n,
                                cpu_sum = cpu_sum + excluded.cpu_sum,
                                cpu_max = max(cpu_max, excluded.cpu_max),
                                mem_sum = mem_sum + excluded.mem_sum,
                                mem_max = max(mem_max, excluded.mem_max),
                                disk = excluded.disk,
                                rx = rx + excluded.rx,
                                tx = tx + excluded.tx",
                            Self::samples_table("main", row.step)
                        ),
                    )?),
                };

                let Bucket {
                    n,
                    cpu_sum,
                    cpu_max,
                    mem_sum,
                    mem_max,
                    disk,
                    rx,
                    tx,
                } = row.bucket;
                stmt.execute(params![
                    id, row.b, n, cpu_sum, cpu_max, mem_sum, mem_max, disk, rx, tx
                ])?;
            }

            if let Some((at, limits)) = limits {
                tx.execute(
                    "INSERT OR REPLACE INTO limits (server, at, memory, cpu) VALUES (?1, ?2, ?3, ?4)",
                    params![id, at, limits.memory, limits.cpu],
                )?;
            }

            for span in spans {
                tx.prepare_cached(
                    "INSERT INTO states (server, since, until, state) VALUES (?1, ?2, ?3, ?4)
                    ON CONFLICT (server, since) DO UPDATE SET
                        until = max(until, excluded.until),
                        state = excluded.state",
                )?
                .execute(params![id, span.since, span.until, span.db_state()])?;
            }
        }

        drop(statements);
        tx.commit()?;

        Ok(())
    }

    /// Drops buckets past their tier's retention and retired tiers that ran empty, then
    /// forgets every server that is not in `known`.
    pub fn prune(
        &mut self,
        now: i64,
        known: Option<&HashSet<uuid::Uuid>>,
    ) -> Result<(), anyhow::Error> {
        if let Some(known) = known {
            let mut stmt = self.conn.prepare("SELECT uuid FROM servers")?;
            let orphans = stmt
                .query_map([], |r| r.get::<_, Vec<u8>>(0))?
                .filter_map(|row| {
                    let uuid = uuid::Uuid::from_slice(&row.ok()?).ok()?;

                    (!known.contains(&uuid)).then_some(uuid)
                })
                .collect::<Vec<_>>();
            drop(stmt);

            for uuid in orphans {
                self.delete_server(uuid)?;
            }
        }

        let ids = {
            let mut stmt = self.conn.prepare("SELECT id FROM servers")?;
            stmt.query_map([], |r| r.get::<_, i64>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };

        let tiers = self.tiers()?;
        if let Some(retention) = tiers.iter().map(|t| t.retention).max()
            && tiers.iter().all(|t| t.retention > 0)
        {
            self.conn.execute(
                "DELETE FROM states WHERE until < ?1",
                params![now - retention as i64],
            )?;
        }

        for tier in tiers {
            let table = Self::samples_table("main", tier.step);

            if tier.retention > 0 {
                let cutoff = (now - tier.retention as i64).div_euclid(tier.step as i64);
                let tx = self.conn.transaction()?;
                {
                    let mut stmt =
                        tx.prepare(&format!("DELETE FROM {table} WHERE server = ?1 AND b < ?2"))?;
                    for id in &ids {
                        stmt.execute(params![id, cutoff])?;
                    }
                }
                tx.commit()?;
            }

            if tier.retired {
                let empty: bool = self.conn.query_row(
                    &format!("SELECT NOT EXISTS (SELECT 1 FROM {table})"),
                    [],
                    |r| r.get(0),
                )?;
                if empty {
                    let tx = self.conn.transaction()?;
                    tx.execute_batch(&format!("DROP TABLE {table};"))?;
                    tx.execute(
                        "DELETE FROM tiers WHERE step = ?1",
                        params![tier.step as i64],
                    )?;
                    tx.commit()?;
                    tracing::info!(
                        step = tier.step,
                        "dropped empty retired resource history tier"
                    );
                }
            }
        }

        self.conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;

        Ok(())
    }

    pub fn delete_server(&mut self, uuid: uuid::Uuid) -> Result<(), anyhow::Error> {
        let Some(id) = self.find_server_id(uuid)? else {
            return Ok(());
        };

        let tiers = self.tiers()?;
        let tx = self.conn.transaction()?;
        for tier in tiers {
            tx.execute(
                &format!(
                    "DELETE FROM {} WHERE server = ?1",
                    Self::samples_table("main", tier.step)
                ),
                params![id],
            )?;
        }
        tx.execute("DELETE FROM limits WHERE server = ?1", params![id])?;
        tx.execute("DELETE FROM states WHERE server = ?1", params![id])?;
        tx.execute("DELETE FROM servers WHERE id = ?1", params![id])?;
        tx.commit()?;
        self.server_ids.remove(&uuid);

        Ok(())
    }

    /// First and last second a tier has data for of one server.
    fn coverage(&self, id: i64, step: u64) -> rusqlite::Result<Option<(i64, i64)>> {
        let table = Self::samples_table("main", step);
        let step = step as i64;

        self.conn.query_row(
            &format!("SELECT MIN(b), MAX(b) FROM {table} WHERE server = ?1"),
            params![id],
            |r| {
                Ok(r.get::<_, Option<i64>>(0)?
                    .zip(r.get::<_, Option<i64>>(1)?)
                    .map(|(first, last)| (first * step, (last + 1) * step)))
            },
        )
    }

    /// Aggregates `[start, end)` into `points` equal slices, from the coarsest tier fine
    /// enough for one slice that still reaches back to `start`.
    pub fn query(
        &self,
        uuid: uuid::Uuid,
        start: i64,
        end: i64,
        points: usize,
    ) -> Result<Option<RawHistory>, anyhow::Error> {
        let Some(id) = self.find_server_id(uuid)? else {
            return Ok(None);
        };

        let mut candidates = Vec::new();
        for tier in self.tiers()? {
            let coverage = self.coverage(id, tier.step)?;

            // a retired tier stopped recording, it can only serve ranges that end before that
            if tier.retired && coverage.is_none_or(|(_, until)| until < end) {
                continue;
            }

            candidates.push((tier.step, coverage.map(|(from, _)| from)));
        }
        let width = (end - start) / points as i64;
        let Some((step, covered_from)) = Self::choose_tier(&candidates, start, width) else {
            return Ok(None);
        };

        let table = Self::samples_table("main", step);
        let step_i = step as i64;
        let b0 = start.div_euclid(step_i);
        let b1 = (end + step_i - 1).div_euclid(step_i);
        let index = format!("MIN(?5 - 1, MAX(0, (b * {step_i} - ?3) * ?5 / (?4 - ?3)))");
        let p = params![id, b0, start, end, points as i64, b1];

        let mut rows = HashMap::new();
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {index} AS i, SUM(n), SUM(cpu_sum), MAX(cpu_max), SUM(mem_sum), MAX(mem_max), SUM(rx), SUM(tx)
            FROM {table} WHERE server = ?1 AND b >= ?2 AND b < ?6 GROUP BY i"
        ))?;
        let mut q = stmt.query(p)?;
        while let Some(r) = q.next()? {
            rows.insert(
                r.get::<_, i64>(0)?.max(0) as usize,
                PointRow {
                    n: r.get(1)?,
                    cpu_sum: r.get(2)?,
                    cpu_max: r.get(3)?,
                    mem_sum: r.get(4)?,
                    mem_max: r.get(5)?,
                    rx: r.get(6)?,
                    tx: r.get(7)?,
                },
            );
        }

        // with exactly one max() aggregate sqlite takes the bare disk column from that row
        let mut disks = HashMap::new();
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {index} AS i, disk, MAX(b) FROM {table}
            WHERE server = ?1 AND b >= ?2 AND b < ?6 GROUP BY i"
        ))?;
        let mut q = stmt.query(p)?;
        while let Some(r) = q.next()? {
            disks.insert(r.get::<_, i64>(0)?.max(0) as usize, r.get(1)?);
        }

        let disk_before = self
            .conn
            .query_row(
                &format!(
                    "SELECT disk FROM {table} WHERE server = ?1 AND b < ?2 ORDER BY b DESC LIMIT 1"
                ),
                params![id, b0],
                |r| r.get(0),
            )
            .optional()?;

        let mut limits = Vec::new();
        let mut stmt = self.conn.prepare(
            "SELECT at, memory, cpu FROM (
                SELECT at, memory, cpu FROM limits WHERE server = ?1 AND at <= ?2 ORDER BY at DESC LIMIT 1
            )
            UNION ALL
            SELECT at, memory, cpu FROM limits WHERE server = ?1 AND at > ?2 AND at < ?3
            ORDER BY at",
        )?;
        let mut q = stmt.query(params![id, start, end])?;
        while let Some(r) = q.next()? {
            limits.push((
                r.get(0)?,
                Limits {
                    memory: r.get(1)?,
                    cpu: r.get(2)?,
                },
            ));
        }

        let mut spans: Vec<Span> = Vec::new();
        let mut stmt = self.conn.prepare(
            "SELECT since, until, state FROM states
            WHERE server = ?1 AND until > ?2 AND since < ?3 ORDER BY since",
        )?;
        for span in stmt.query_map(params![id, start, end], Span::from_row)? {
            let mut span = span?;

            // spans joined from two nodes may overlap when their clocks disagree
            if let Some(previous) = spans.last() {
                span.since = span.since.max(previous.until);
            }
            if span.since < span.until {
                spans.push(span);
            }
        }

        Ok(Some(RawHistory {
            step,
            covered_from,
            rows,
            disks,
            disk_before,
            limits,
            spans,
        }))
    }

    /// Copies everything stored for one server into a fresh database at `path`.
    pub fn export(&self, uuid: uuid::Uuid, path: &Path) -> Result<bool, anyhow::Error> {
        let Some(id) = self.find_server_id(uuid)? else {
            return Ok(false);
        };

        let tiers = self.tiers()?;
        {
            let export = Connection::open(path)?;
            export.execute_batch(SCHEMA)?;
            export.pragma_update(None, "user_version", FORMAT_VERSION)?;
            for tier in &tiers {
                Self::create_samples_table(&export, "main", tier.step)?;
            }
        }

        self.conn.execute(
            "ATTACH DATABASE ?1 AS export",
            params![path.to_string_lossy().into_owned()],
        )?;
        let result = (|| -> rusqlite::Result<()> {
            self.conn.execute_batch("BEGIN")?;
            self.conn.execute(
                "INSERT INTO export.servers (id, uuid) VALUES (1, ?1)",
                params![uuid.as_bytes()],
            )?;
            self.conn
                .execute("INSERT INTO export.tiers SELECT * FROM main.tiers", [])?;
            self.conn.execute(
                "INSERT INTO export.limits SELECT 1, at, memory, cpu FROM main.limits WHERE server = ?1",
                params![id],
            )?;
            self.conn.execute(
                "INSERT INTO export.states SELECT 1, since, until, state FROM main.states WHERE server = ?1",
                params![id],
            )?;
            for tier in &tiers {
                self.conn.execute(
                    &format!(
                        "INSERT INTO {} SELECT 1, b, n, cpu_sum, cpu_max, mem_sum, mem_max, disk, rx, tx
                        FROM {} WHERE server = ?1",
                        Self::samples_table("export", tier.step),
                        Self::samples_table("main", tier.step)
                    ),
                    params![id],
                )?;
            }
            self.conn.execute_batch("COMMIT")
        })();
        if result.is_err() {
            self.conn.execute_batch("ROLLBACK").ok();
        }
        self.conn.execute("DETACH DATABASE export", [])?;
        result?;

        Ok(true)
    }

    /// Merges an exported database into the configured tiers of `uuid`. Tiers of the export
    /// that no configured tier can be built from are dropped, the local retention budget wins.
    pub fn import(&mut self, uuid: uuid::Uuid, path: &Path) -> Result<(), anyhow::Error> {
        let id = self.server_id(uuid)?;
        let local = self.tiers()?;

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
                    "unsupported resource history format version {version}"
                ));
            }

            let Some(src_id) = self
                .conn
                .query_row(
                    "SELECT id FROM import.servers WHERE uuid = ?1",
                    params![uuid.as_bytes()],
                    |r| r.get::<_, i64>(0),
                )
                .optional()?
            else {
                return Ok(());
            };
            let source = Self::tiers_in(&self.conn, "import")?;

            let tx = self.conn.transaction()?;
            for tier in local.iter().filter(|t| !t.retired) {
                let mut sources: Vec<u64> = source
                    .iter()
                    .map(|t| t.step)
                    .filter(|&s| tier.step % s == 0)
                    .collect();
                sources.sort_unstable_by(|a, b| b.cmp(a));

                for src in sources {
                    Self::backfill(&tx, "import", src, tier.step, Some((src_id, id)))?;
                }
            }
            tx.execute(
                "INSERT OR IGNORE INTO main.limits SELECT ?1, at, memory, cpu FROM import.limits WHERE server = ?2",
                params![id, src_id],
            )?;
            tx.execute(
                "INSERT OR IGNORE INTO main.states SELECT ?1, since, until, state FROM import.states WHERE server = ?2",
                params![id, src_id],
            )?;
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
    use uuid::Uuid;

    const A: Uuid = Uuid::from_u128(1);
    const B: Uuid = Uuid::from_u128(2);

    fn tier(step: u64, retention: u64) -> ResourceHistoryTier {
        ResourceHistoryTier { step, retention }
    }

    fn open(tiers: &[ResourceHistoryTier]) -> (tempfile::TempDir, Storage) {
        let dir = tempfile::tempdir().unwrap();
        let mut storage = Storage::open(&dir.path().join("x.db")).unwrap();
        storage.reconcile(tiers).unwrap();
        (dir, storage)
    }

    fn entry(uuid: Uuid, rows: Vec<Row>, limits: Option<(i64, Limits)>) -> Entry {
        Entry {
            uuid,
            rows,
            limits,
            spans: Vec::new(),
        }
    }

    fn row(step: u64, b: i64, bucket: Bucket) -> Row {
        Row { step, b, bucket }
    }

    fn sample(b: i64) -> Bucket {
        Bucket {
            n: 1,
            cpu_sum: b,
            cpu_max: b,
            mem_sum: b,
            mem_max: b,
            disk: b * 10,
            rx: b,
            tx: 1,
        }
    }

    fn write_samples(
        storage: &mut Storage,
        uuid: Uuid,
        step: u64,
        bs: std::ops::RangeInclusive<i64>,
    ) {
        let rows = bs.map(|b| row(step, b, sample(b))).collect();
        storage.write(vec![entry(uuid, rows, None)]).unwrap();
    }

    fn limits(memory: i64) -> Limits {
        Limits { memory, cpu: 100 }
    }

    fn sum(bs: std::ops::RangeInclusive<i64>) -> PointRow {
        let n = bs.clone().count() as i64;
        let total: i64 = bs.clone().sum();
        PointRow {
            n,
            cpu_sum: total,
            cpu_max: *bs.end(),
            mem_sum: total,
            mem_max: *bs.end(),
            rx: total,
            tx: n,
        }
    }

    fn span(since: i64, until: i64, state: ServerState) -> Span {
        Span {
            since,
            until,
            state,
        }
    }

    fn write_spans(storage: &mut Storage, uuid: Uuid, spans: Vec<Span>) {
        storage
            .write(vec![Entry {
                spans,
                ..entry(uuid, Vec::new(), None)
            }])
            .unwrap();
    }

    // Storage
    #[test]
    fn writes_to_same_bucket_merge_additively() {
        let (_dir, mut storage) = open(&[tier(10, 0)]);
        let first = Bucket {
            n: 2,
            cpu_sum: 100,
            cpu_max: 60,
            mem_sum: 10,
            mem_max: 6,
            disk: 5,
            rx: 1,
            tx: 2,
        };
        let second = Bucket {
            n: 1,
            cpu_sum: 30,
            cpu_max: 30,
            mem_sum: 8,
            mem_max: 8,
            disk: 7,
            rx: 3,
            tx: 4,
        };
        storage
            .write(vec![entry(A, vec![row(10, 0, first)], None)])
            .unwrap();
        storage
            .write(vec![entry(A, vec![row(10, 0, second)], None)])
            .unwrap();

        let raw = storage.query(A, 0, 10, 1).unwrap().unwrap();
        assert_eq!(
            raw.rows.get(&0),
            Some(&PointRow {
                n: 3,
                cpu_sum: 130,
                cpu_max: 60,
                mem_sum: 18,
                mem_max: 8,
                rx: 4,
                tx: 6,
            })
        );
        assert_eq!(raw.disks.get(&0), Some(&7));
    }

    #[test]
    fn query_unknown_server_is_none() {
        let (_dir, mut storage) = open(&[tier(10, 0)]);
        write_samples(&mut storage, A, 10, 0..=3);
        assert!(storage.query(B, 0, 40, 4).unwrap().is_none());
    }

    #[test]
    fn query_slices_buckets_into_points() {
        let (_dir, mut storage) = open(&[tier(10, 0)]);
        write_samples(&mut storage, A, 10, -1..=5);

        let raw = storage.query(A, 5, 45, 2).unwrap().unwrap();
        assert_eq!(raw.step, 10);
        assert_eq!(raw.covered_from, Some(-10));
        assert_eq!(raw.rows.len(), 2);
        assert_eq!(raw.rows.get(&0), Some(&sum(0..=2)));
        assert_eq!(raw.rows.get(&1), Some(&sum(3..=4)));
        assert_eq!(raw.disks, HashMap::from([(0, 20), (1, 40)]));
        assert_eq!(raw.disk_before, Some(-10));
    }

    #[test]
    fn query_returns_limits_in_effect_at_start_and_changes_inside() {
        let (_dir, mut storage) = open(&[tier(10, 0)]);
        for (ts, memory) in [(0, 1), (3, 2), (12, 3), (50, 4)] {
            storage
                .write(vec![entry(A, Vec::new(), Some((ts, limits(memory))))])
                .unwrap();
        }
        write_samples(&mut storage, A, 10, 0..=5);

        let raw = storage.query(A, 5, 45, 4).unwrap().unwrap();
        assert_eq!(raw.limits, vec![(3, limits(2)), (12, limits(3))]);
        assert_eq!(storage.latest_limits(A).unwrap(), Some(limits(4)));
    }

    #[test]
    fn reconcile_backfills_only_fully_covered_buckets() {
        let (_dir, mut storage) = open(&[tier(10, 0)]);
        write_samples(&mut storage, A, 10, 3..=12);
        storage.reconcile(&[tier(10, 0), tier(60, 0)]).unwrap();

        let raw = storage.query(A, 60, 180, 2).unwrap().unwrap();
        assert_eq!(raw.step, 60);
        assert_eq!(raw.covered_from, Some(60));
        assert_eq!(raw.rows.get(&0), Some(&sum(6..=11)));
        assert_eq!(raw.rows.get(&1), Some(&sum(12..=12)));
        assert_eq!(raw.disks.get(&0), Some(&110));
    }

    #[test]
    fn removed_tier_is_retired_queryable_and_reactivated_on_readd() {
        let (_dir, mut storage) = open(&[tier(10, 0), tier(60, 0)]);
        write_samples(&mut storage, A, 10, 0..=11);
        storage.reconcile(&[tier(60, 0)]).unwrap();

        let retired = storage.tiers().unwrap();
        assert!(retired.contains(&StoredTier {
            step: 10,
            retention: 0,
            retired: true
        }));
        let raw = storage.query(A, 0, 100, 10).unwrap().unwrap();
        assert_eq!(raw.step, 10);
        assert_eq!(raw.rows.get(&3), Some(&sum(3..=3)));

        storage.reconcile(&[tier(10, 0), tier(60, 0)]).unwrap();
        assert!(storage.tiers().unwrap().iter().all(|t| !t.retired));
    }

    #[test]
    fn retired_tier_is_not_used_past_its_last_bucket() {
        let (_dir, mut storage) = open(&[tier(10, 0), tier(60, 0)]);
        write_samples(&mut storage, A, 10, 0..=11);
        write_samples(&mut storage, A, 60, 0..=3);
        storage.reconcile(&[tier(60, 0)]).unwrap();

        let raw = storage.query(A, 0, 240, 24).unwrap().unwrap();
        assert_eq!(raw.step, 60);
    }

    #[test]
    fn prune_drops_buckets_older_than_retention() {
        let (_dir, mut storage) = open(&[tier(10, 100), tier(60, 0)]);
        write_samples(&mut storage, A, 10, 0..=20);
        write_samples(&mut storage, A, 60, 0..=3);
        storage.prune(200, None).unwrap();

        let raw = storage.query(A, 100, 200, 10).unwrap().unwrap();
        assert_eq!(raw.step, 10);
        assert_eq!(raw.covered_from, Some(100));
        assert_eq!(raw.disk_before, None);
        let raw = storage.query(A, 0, 240, 4).unwrap().unwrap();
        assert_eq!(raw.step, 60);
        assert_eq!(raw.covered_from, Some(0));
    }

    #[test]
    fn prune_forgets_unknown_servers() {
        let (_dir, mut storage) = open(&[tier(10, 0)]);
        write_samples(&mut storage, A, 10, 0..=3);
        write_samples(&mut storage, B, 10, 0..=3);

        storage.prune(40, None).unwrap();
        assert!(storage.query(B, 0, 40, 4).unwrap().is_some());

        storage.prune(40, Some(&HashSet::from([A]))).unwrap();
        assert!(storage.query(A, 0, 40, 4).unwrap().is_some());
        assert!(storage.query(B, 0, 40, 4).unwrap().is_none());
    }

    #[test]
    fn retired_tier_is_pruned_under_its_retention_then_dropped() {
        let (_dir, mut storage) = open(&[tier(10, 100), tier(60, 0)]);
        write_samples(&mut storage, A, 10, 0..=20);
        storage.reconcile(&[tier(60, 0)]).unwrap();

        storage.prune(200, None).unwrap();
        assert!(
            storage
                .tiers()
                .unwrap()
                .iter()
                .any(|t| t.step == 10 && t.retired)
        );

        storage.prune(1000, None).unwrap();
        assert!(storage.tiers().unwrap().iter().all(|t| t.step != 10));
    }

    #[test]
    fn export_of_unknown_server_is_false() {
        let (dir, storage) = open(&[tier(10, 0)]);
        assert!(!storage.export(A, &dir.path().join("export.db")).unwrap());
    }

    #[test]
    fn import_rebuilds_into_local_tiers_and_drops_unbuildable_ones() {
        let (dir, mut source) = open(&[tier(10, 0), tier(7, 0)]);
        write_samples(&mut source, A, 10, 0..=11);
        write_samples(&mut source, A, 7, 0..=11);
        source
            .write(vec![entry(A, Vec::new(), Some((0, limits(5))))])
            .unwrap();
        let path = dir.path().join("export.db");
        assert!(source.export(A, &path).unwrap());

        let (_target_dir, mut target) = open(&[tier(60, 0)]);
        target.import(A, &path).unwrap();

        assert_eq!(
            target.tiers().unwrap(),
            vec![StoredTier {
                step: 60,
                retention: 0,
                retired: false
            }]
        );
        let raw = target.query(A, 0, 120, 2).unwrap().unwrap();
        assert_eq!(raw.step, 60);
        assert_eq!(raw.rows.get(&0), Some(&sum(0..=5)));
        assert_eq!(raw.rows.get(&1), Some(&sum(6..=11)));
        assert_eq!(raw.disks, HashMap::from([(0, 50), (1, 110)]));
        assert_eq!(target.latest_limits(A).unwrap(), Some(limits(5)));
    }

    #[test]
    fn choose_tier_prefers_coarsest_fitting_covered_tier() {
        let candidates = [(10, Some(0)), (600, Some(0)), (60, Some(0))];
        assert_eq!(
            Storage::choose_tier(&candidates, 100, 120),
            Some((60, Some(0)))
        );
        assert_eq!(
            Storage::choose_tier(&candidates, 100, 600),
            Some((600, Some(0)))
        );
    }

    #[test]
    fn choose_tier_skips_coarser_tier_that_does_not_reach_start() {
        let candidates = [(10, Some(0)), (60, Some(500))];
        assert_eq!(
            Storage::choose_tier(&candidates, 100, 120),
            Some((10, Some(0)))
        );
    }

    #[test]
    fn choose_tier_falls_back_to_fitting_tier_reaching_furthest_back() {
        let candidates = [(10, Some(300)), (60, Some(200)), (600, Some(0))];
        assert_eq!(
            Storage::choose_tier(&candidates, 100, 120),
            Some((60, Some(200)))
        );
        assert_eq!(
            Storage::choose_tier(&[(10, Some(300)), (60, None)], 100, 120),
            Some((10, Some(300)))
        );
    }

    #[test]
    fn choose_tier_uses_finest_tier_when_none_fit() {
        let candidates = [(600, Some(0)), (60, Some(0))];
        assert_eq!(
            Storage::choose_tier(&candidates, 100, 5),
            Some((60, Some(0)))
        );
        assert_eq!(
            Storage::choose_tier(&[(10, Some(0)), (1, Some(0))], 100, 0),
            Some((1, Some(0)))
        );
        assert_eq!(Storage::choose_tier(&[], 100, 60), None);
    }

    #[test]
    fn span_rewritten_with_same_since_stays_one_span() {
        let (_dir, mut storage) = open(&[tier(10, 0)]);
        assert_eq!(storage.last_span(A).unwrap(), None);

        write_spans(&mut storage, A, vec![span(0, 5, ServerState::Running)]);
        write_spans(&mut storage, A, vec![span(0, 9, ServerState::Running)]);
        write_spans(&mut storage, A, vec![span(0, 7, ServerState::Stopping)]);

        assert_eq!(
            storage.last_span(A).unwrap(),
            Some(span(0, 9, ServerState::Stopping))
        );
        let raw = storage.query(A, 0, 20, 2).unwrap().unwrap();
        assert_eq!(raw.spans, vec![span(0, 9, ServerState::Stopping)]);
    }

    #[test]
    fn last_span_is_greatest_since() {
        let (_dir, mut storage) = open(&[tier(10, 0)]);
        write_spans(
            &mut storage,
            A,
            vec![
                span(8, 10, ServerState::Offline),
                span(0, 5, ServerState::Starting),
                span(5, 8, ServerState::Running),
            ],
        );

        assert_eq!(
            storage.last_span(A).unwrap(),
            Some(span(8, 10, ServerState::Offline))
        );
        assert_eq!(storage.last_span(B).unwrap(), None);
    }

    #[test]
    fn query_returns_overlapping_spans_unclipped_and_non_overlapping() {
        let (_dir, mut storage) = open(&[tier(10, 0)]);
        write_spans(
            &mut storage,
            A,
            vec![
                span(-20, 9, ServerState::Offline),
                span(0, 10, ServerState::Running),
                span(5, 15, ServerState::Offline),
                span(8, 12, ServerState::Starting),
                span(20, 30, ServerState::Running),
                span(25, 40, ServerState::Stopping),
            ],
        );

        let raw = storage.query(A, 9, 25, 2).unwrap().unwrap();
        assert_eq!(
            raw.spans,
            vec![
                span(0, 10, ServerState::Running),
                span(10, 15, ServerState::Offline),
                span(20, 30, ServerState::Running),
            ]
        );
    }

    #[test]
    fn states_are_pruned_by_max_retention_unless_a_tier_is_forever() {
        let spans = vec![
            span(0, 10, ServerState::Running),
            span(690, 700, ServerState::Offline),
            span(800, 900, ServerState::Running),
        ];

        let (_dir, mut storage) = open(&[tier(10, 100), tier(60, 0)]);
        write_spans(&mut storage, A, spans.clone());
        storage.prune(1000, None).unwrap();
        let raw = storage.query(A, 0, 1000, 10).unwrap().unwrap();
        assert_eq!(raw.spans, spans);

        let (_dir, mut storage) = open(&[tier(10, 100), tier(60, 300)]);
        write_spans(&mut storage, A, spans.clone());
        storage.prune(1000, None).unwrap();
        let raw = storage.query(A, 0, 1000, 10).unwrap().unwrap();
        assert_eq!(raw.spans, spans[1..].to_vec());
    }

    #[test]
    fn delete_server_removes_states() {
        let (_dir, mut storage) = open(&[tier(10, 0)]);
        write_spans(&mut storage, A, vec![span(0, 10, ServerState::Running)]);
        storage.delete_server(A).unwrap();

        assert_eq!(storage.last_span(A).unwrap(), None);
        assert!(storage.query(A, 0, 20, 2).unwrap().is_none());
    }

    #[test]
    fn export_import_carries_spans_and_local_span_with_same_since_wins() {
        let (dir, mut source) = open(&[tier(10, 0)]);
        write_spans(
            &mut source,
            A,
            vec![
                span(0, 10, ServerState::Running),
                span(10, 20, ServerState::Offline),
            ],
        );
        let path = dir.path().join("export.db");
        assert!(source.export(A, &path).unwrap());

        let (_target_dir, mut target) = open(&[tier(10, 0)]);
        write_spans(&mut target, A, vec![span(10, 15, ServerState::Starting)]);
        target.import(A, &path).unwrap();

        let raw = target.query(A, 0, 20, 2).unwrap().unwrap();
        assert_eq!(
            raw.spans,
            vec![
                span(0, 10, ServerState::Running),
                span(10, 15, ServerState::Starting),
            ]
        );
    }
}
