use anyhow::Context;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use std::{
    io::{Read, Write},
    path::Path,
};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS files (
    id   INTEGER PRIMARY KEY,
    path TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS revisions (
    id           INTEGER PRIMARY KEY,
    file_id      INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    chain_id     INTEGER NOT NULL,
    size         INTEGER NOT NULL,
    user_id      BLOB,
    base_id      INTEGER,
    payload      BLOB NOT NULL,
    content_hash BLOB NOT NULL,
    created      INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_revisions_file_created ON revisions(file_id, created DESC);
CREATE INDEX IF NOT EXISTS idx_revisions_file_chain   ON revisions(file_id, chain_id);
CREATE INDEX IF NOT EXISTS idx_revisions_created      ON revisions(created);
"#;

#[derive(Debug, Clone)]
pub struct RevisionRow {
    pub id: i64,
    pub chain_id: i64,
    pub size: u64,
    pub user: Option<uuid::Uuid>,
    pub base_id: Option<i64>,
    pub stored_size: u64,
    pub content_hash: [u8; 32],
    pub created_ms: i64,
}

impl RevisionRow {
    fn from_row(r: &rusqlite::Row<'_>) -> Result<Self, rusqlite::Error> {
        let user_blob: Option<Vec<u8>> = r.get(5)?;
        let user = user_blob.and_then(|b| {
            if b.len() == 16 {
                let mut bytes = [0; 16];
                bytes.copy_from_slice(&b);
                Some(uuid::Uuid::from_bytes(bytes))
            } else {
                None
            }
        });
        let hash_blob: Vec<u8> = r.get(8)?;
        let mut hash = [0; 32];
        if hash_blob.len() == 32 {
            hash.copy_from_slice(&hash_blob);
        }

        Ok(RevisionRow {
            id: r.get(0)?,
            chain_id: r.get(2)?,
            created_ms: r.get(3)?,
            size: r.get::<_, i64>(4)?.max(0) as u64,
            user,
            base_id: r.get(6)?,
            stored_size: r.get::<_, i64>(7)?.max(0) as u64,
            content_hash: hash,
        })
    }
}

pub struct Storage {
    conn: Connection,
    zstd_level: i32,
}

impl Storage {
    pub fn open(path: &Path, zstd_level: i32) -> Result<Self, anyhow::Error> {
        let conn = crate::server::filesystem::sqlite::open(path, OpenFlags::default())
            .with_context(|| format!("opening diff db {}", path.display()))?;

        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        conn.execute_batch(SCHEMA)?;

        Ok(Self { conn, zstd_level })
    }

    pub fn zstd_level(&self) -> i32 {
        self.zstd_level
    }

    pub fn total_payload_bytes(&self) -> Result<u64, anyhow::Error> {
        let n: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(LENGTH(payload)), 0) FROM revisions",
            [],
            |r| r.get(0),
        )?;

        Ok(n.max(0) as u64)
    }

    pub fn file_payload_bytes(&self, file_id: i64) -> Result<u64, anyhow::Error> {
        let n: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(LENGTH(payload)), 0) FROM revisions WHERE file_id = ?",
            params![file_id],
            |r| r.get(0),
        )?;

        Ok(n.max(0) as u64)
    }

    pub fn upsert_file(&mut self, path: &str) -> Result<i64, anyhow::Error> {
        let tx = self.conn.transaction()?;
        let id: Option<i64> = tx
            .query_row("SELECT id FROM files WHERE path = ?", params![path], |r| {
                r.get(0)
            })
            .optional()?;
        let id = match id {
            Some(id) => id,
            None => {
                tx.execute("INSERT INTO files(path) VALUES (?)", params![path])?;
                tx.last_insert_rowid()
            }
        };
        tx.commit()?;

        Ok(id)
    }

    pub fn find_file(&self, path: &str) -> Result<Option<i64>, anyhow::Error> {
        Ok(self
            .conn
            .query_row("SELECT id FROM files WHERE path = ?", params![path], |r| {
                r.get::<_, i64>(0)
            })
            .optional()?)
    }

    pub fn revision_path(&self, revision_id: i64) -> Result<Option<String>, anyhow::Error> {
        Ok(self
            .conn
            .query_row(
                "SELECT f.path FROM revisions r
                JOIN files f ON f.id = r.file_id
                WHERE r.id = ?",
                params![revision_id],
                |r| r.get::<_, String>(0),
            )
            .optional()?)
    }

    pub fn latest_revision(&self, file_id: i64) -> Result<Option<RevisionRow>, anyhow::Error> {
        let row = self
            .conn
            .query_row(
                "SELECT id, file_id, chain_id, created, size, user_id, base_id, LENGTH(payload), content_hash
                FROM revisions WHERE file_id = ?
                ORDER BY id DESC LIMIT 1",
                params![file_id],
                RevisionRow::from_row,
            )
            .optional()?;

        Ok(row)
    }

    pub fn list_for_file(&self, file_id: i64) -> Result<Vec<RevisionRow>, anyhow::Error> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT id, file_id, chain_id, created, size, user_id, base_id, LENGTH(payload), content_hash
            FROM revisions WHERE file_id = ?
            ORDER BY id DESC",
        )?;
        let rows = stmt
            .query_map(params![file_id], RevisionRow::from_row)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(rows)
    }

    pub fn chain_count(&self, file_id: i64) -> Result<u64, anyhow::Error> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(DISTINCT chain_id) FROM revisions WHERE file_id = ?",
            params![file_id],
            |r| r.get(0),
        )?;

        Ok(n.max(0) as u64)
    }

    pub fn latest_chain_id(&self, file_id: i64) -> Result<Option<i64>, anyhow::Error> {
        let row: Option<i64> = self
            .conn
            .query_row(
                "SELECT chain_id FROM revisions WHERE file_id = ?
                ORDER BY id DESC LIMIT 1",
                params![file_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(row)
    }

    pub fn current_chain_length(&self, file_id: i64) -> Result<u64, anyhow::Error> {
        let Some(chain_id) = self.latest_chain_id(file_id)? else {
            return Ok(0);
        };

        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM revisions WHERE file_id = ? AND chain_id = ?",
            params![file_id, chain_id],
            |r| r.get(0),
        )?;

        Ok(n.max(0) as u64)
    }

    pub fn insert_snapshot(
        &mut self,
        file_id: i64,
        user: Option<uuid::Uuid>,
        content: &[u8],
        created_ms: i64,
    ) -> Result<i64, anyhow::Error> {
        let payload = zstd::encode_all(content, self.zstd_level).context("zstd encode snapshot")?;
        let hash = blake3::hash(content);
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO revisions(file_id, chain_id, created, size, user_id, base_id, payload, content_hash)
            VALUES (?, 0, ?, ?, ?, NULL, ?, ?)",
            params![
                file_id,
                created_ms,
                content.len() as i64,
                user.map(|u| u.as_bytes().to_vec()),
                payload,
                hash.as_bytes().to_vec(),
            ],
        )?;
        let id = tx.last_insert_rowid();

        tx.execute(
            "UPDATE revisions SET chain_id = ? WHERE id = ?",
            params![id, id],
        )?;
        tx.commit()?;

        Ok(id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_delta(
        &mut self,
        file_id: i64,
        base_id: i64,
        base_chain_id: i64,
        base_content: &[u8],
        user: Option<uuid::Uuid>,
        content: &[u8],
        created_ms: i64,
    ) -> Result<i64, anyhow::Error> {
        let payload = encode_with_dictionary(content, base_content, self.zstd_level)?;
        let hash = blake3::hash(content);
        self.conn.execute(
            "INSERT INTO revisions(file_id, chain_id, created, size, user_id, base_id, payload, content_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                file_id,
                base_chain_id,
                created_ms,
                content.len() as i64,
                user.map(|u| u.as_bytes().to_vec()),
                base_id,
                payload,
                hash.as_bytes().to_vec(),
            ],
        )?;

        Ok(self.conn.last_insert_rowid())
    }

    pub fn try_encode_delta(
        &self,
        base_content: &[u8],
        new: &[u8],
    ) -> Result<Vec<u8>, anyhow::Error> {
        encode_with_dictionary(new, base_content, self.zstd_level)
    }

    pub fn reconstruct(&self, id: i64) -> Result<Vec<u8>, anyhow::Error> {
        let mut chain = Vec::new();
        let mut cur = Some(id);

        while let Some(rid) = cur
            && chain.len() < 1000
        {
            let row = self
                .conn
                .query_row(
                    "SELECT id, base_id, payload, content_hash FROM revisions WHERE id = ?",
                    params![rid],
                    |r| {
                        let hb: Vec<u8> = r.get(3)?;
                        let mut hash = [0; 32];
                        if hb.len() == 32 {
                            hash.copy_from_slice(&hb);
                        }

                        Ok((
                            r.get::<_, i64>(0)?,
                            r.get::<_, Option<i64>>(1)?,
                            r.get::<_, Vec<u8>>(2)?,
                            hash,
                        ))
                    },
                )
                .optional()?
                .ok_or_else(|| {
                    anyhow::anyhow!("revision {rid} not found while reconstructing {id}")
                })?;

            let is_snapshot = row.1.is_none();
            cur = row.1;
            chain.push(row);
            if is_snapshot {
                break;
            }
        }

        chain.reverse();

        let (Some(chain_first), Some(chain_slice)) = (chain.first(), chain.get(1..)) else {
            return Err(anyhow::anyhow!("revision {id} not found"));
        };

        let mut content =
            zstd::decode_all(&chain_first.2[..]).context("decode snapshot at chain head")?;
        let h = blake3::hash(&content);
        if h.as_bytes() != &chain_first.3 {
            return Err(anyhow::anyhow!(
                "content hash mismatch at chain head (revision {})",
                chain_first.0
            ));
        }

        for step in chain_slice {
            let next = decode_with_dictionary(&step.2, &content)?;
            let h = blake3::hash(&next);
            if h.as_bytes() != &step.3 {
                return Err(anyhow::anyhow!(
                    "content hash mismatch reconstructing revision {} (chain step from {})",
                    id,
                    step.0
                ));
            }
            content = next;
        }
        Ok(content)
    }

    pub fn prune_old_chains(
        &mut self,
        file_id: i64,
        keep_chains: u64,
    ) -> Result<u64, anyhow::Error> {
        if keep_chains == 0 {
            return Ok(0);
        }

        let mut stmt = self.conn.prepare_cached(
            "SELECT DISTINCT chain_id FROM revisions WHERE file_id = ?
            ORDER BY chain_id DESC LIMIT ?",
        )?;
        let chains: Vec<i64> = stmt
            .query_map(params![file_id, keep_chains as i64], |r| r.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);

        if (chains.len() as u64) < keep_chains {
            return Ok(0);
        }
        let Some(&min_keep) = chains.last() else {
            return Ok(0);
        };

        let n = self.conn.execute(
            "DELETE FROM revisions WHERE file_id = ? AND chain_id < ?",
            params![file_id, min_keep],
        )?;

        Ok(n as u64)
    }

    pub fn drop_oldest_chain(
        &mut self,
        file_id: i64,
        protect_chain_id: Option<i64>,
        min_chains_to_keep: u64,
    ) -> Result<u64, anyhow::Error> {
        let chain_count = self.chain_count(file_id)?;
        if chain_count <= min_chains_to_keep.max(1) {
            return Ok(0);
        }

        let oldest: Option<i64> = match protect_chain_id {
            Some(protect) => self
                .conn
                .query_row(
                    "SELECT MIN(chain_id) FROM revisions
                    WHERE file_id = ? AND chain_id <> ?",
                    params![file_id, protect],
                    |r| r.get(0),
                )
                .optional()?
                .flatten(),
            None => self
                .conn
                .query_row(
                    "SELECT MIN(chain_id) FROM revisions WHERE file_id = ?",
                    params![file_id],
                    |r| r.get(0),
                )
                .optional()?
                .flatten(),
        };
        let Some(oldest) = oldest else {
            return Ok(0);
        };

        let freed: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(LENGTH(payload)), 0) FROM revisions
            WHERE file_id = ? AND chain_id = ?",
            params![file_id, oldest],
            |r| r.get(0),
        )?;
        self.conn.execute(
            "DELETE FROM revisions WHERE file_id = ? AND chain_id = ?",
            params![file_id, oldest],
        )?;

        Ok(freed.max(0) as u64)
    }

    pub fn drop_globally_oldest_chain(
        &mut self,
        protect: Option<(i64, i64)>,
    ) -> Result<u64, anyhow::Error> {
        let row: Option<(i64, i64)> = {
            let (pf, pc) = protect.unwrap_or((-1, -1));
            self.conn
                .query_row(
                    "SELECT r.file_id, r.chain_id
                    FROM revisions r
                    WHERE NOT (r.file_id = ? AND r.chain_id = ?)
                    AND (SELECT COUNT(DISTINCT chain_id) FROM revisions
                            WHERE file_id = r.file_id) > 1
                    GROUP BY r.file_id, r.chain_id
                    ORDER BY MIN(r.created) ASC, r.chain_id ASC
                    LIMIT 1",
                    params![pf, pc],
                    |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
                )
                .optional()?
        };
        let Some((file_id, chain_id)) = row else {
            return Ok(0);
        };

        let freed: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(LENGTH(payload)), 0) FROM revisions
            WHERE file_id = ? AND chain_id = ?",
            params![file_id, chain_id],
            |r| r.get(0),
        )?;
        self.conn.execute(
            "DELETE FROM revisions WHERE file_id = ? AND chain_id = ?",
            params![file_id, chain_id],
        )?;

        Ok(freed.max(0) as u64)
    }

    pub fn delete_file(&mut self, path: &str) -> Result<(), anyhow::Error> {
        self.conn
            .execute("DELETE FROM files WHERE path = ?", params![path])?;
        Ok(())
    }

    pub fn rename_file(&mut self, old: &str, new: &str) -> Result<(), anyhow::Error> {
        self.conn.execute(
            "UPDATE files SET path = ? WHERE path = ?",
            params![new, old],
        )?;
        Ok(())
    }

    pub fn clear(&mut self) -> Result<(), anyhow::Error> {
        self.conn.execute("DELETE FROM revisions", [])?;
        self.conn.execute("DELETE FROM files", [])?;

        Ok(())
    }

    pub fn vacuum_into(&self, path: &Path) -> Result<(), anyhow::Error> {
        self.conn.execute(
            "VACUUM INTO ?",
            params![path.to_string_lossy().into_owned()],
        )?;
        Ok(())
    }

    pub fn vacuum(&mut self) -> Result<(), anyhow::Error> {
        self.conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    }
}

fn encode_with_dictionary(
    content: &[u8],
    dict: &[u8],
    level: i32,
) -> Result<Vec<u8>, anyhow::Error> {
    let mut out = Vec::with_capacity(content.len() / 2 + 64);
    let mut enc = zstd::stream::Encoder::with_dictionary(&mut out, level, dict)?;
    enc.write_all(content)?;
    enc.finish()?;

    Ok(out)
}

fn decode_with_dictionary(payload: &[u8], dict: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    let mut dec = zstd::stream::Decoder::with_dictionary(payload, dict)?;
    let mut out = Vec::new();
    dec.read_to_end(&mut out)?;

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn storage() -> (TempDir, Storage) {
        let dir = TempDir::new().unwrap();
        let s = Storage::open(&dir.path().join("t.db"), 3).unwrap();
        (dir, s)
    }

    // Storage

    #[test]
    fn snapshot_reconstruct_round_trip() {
        let (_d, mut s) = storage();
        let f = s.upsert_file("a").unwrap();
        let content = b"hello world".to_vec();
        let id = s.insert_snapshot(f, None, &content, 1).unwrap();
        assert_eq!(s.reconstruct(id).unwrap(), content);
    }

    #[test]
    fn delta_chain_reconstruct_round_trip() {
        let (_d, mut s) = storage();
        let f = s.upsert_file("a").unwrap();
        let a = b"the quick brown fox".to_vec();
        let b = b"the quick brown fox jumps".to_vec();
        let c = b"the quick brown fox jumps over the lazy dog".to_vec();
        let id1 = s.insert_snapshot(f, None, &a, 1).unwrap();
        let id2 = s.insert_delta(f, id1, id1, &a, None, &b, 2).unwrap();
        let id3 = s.insert_delta(f, id2, id1, &b, None, &c, 3).unwrap();
        assert_eq!(s.reconstruct(id1).unwrap(), a);
        assert_eq!(s.reconstruct(id2).unwrap(), b);
        assert_eq!(s.reconstruct(id3).unwrap(), c);
    }

    #[test]
    fn upsert_file_is_idempotent() {
        let (_d, mut s) = storage();
        let a = s.upsert_file("p").unwrap();
        assert_eq!(s.upsert_file("p").unwrap(), a);
        assert_ne!(s.upsert_file("q").unwrap(), a);
        assert_eq!(s.find_file("p").unwrap(), Some(a));
        assert_eq!(s.find_file("missing").unwrap(), None);
    }

    #[test]
    fn revision_path_resolves_owning_file() {
        let (_d, mut s) = storage();
        let f = s.upsert_file("config/server.properties").unwrap();
        let id = s.insert_snapshot(f, None, b"x", 1).unwrap();
        assert_eq!(
            s.revision_path(id).unwrap().as_deref(),
            Some("config/server.properties")
        );
        assert_eq!(s.revision_path(id + 1000).unwrap(), None);
    }

    #[test]
    fn revision_path_follows_rename() {
        let (_d, mut s) = storage();
        let f = s.upsert_file("old.txt").unwrap();
        let id = s.insert_snapshot(f, None, b"x", 1).unwrap();
        s.rename_file("old.txt", "new.txt").unwrap();
        assert_eq!(s.revision_path(id).unwrap().as_deref(), Some("new.txt"));
    }

    #[test]
    fn delete_file_cascades_revisions() {
        let (_d, mut s) = storage();
        let f = s.upsert_file("d").unwrap();
        s.insert_snapshot(f, None, b"x", 1).unwrap();
        assert!(s.file_payload_bytes(f).unwrap() > 0);
        s.delete_file("d").unwrap();
        assert_eq!(s.find_file("d").unwrap(), None);
        assert_eq!(s.file_payload_bytes(f).unwrap(), 0);
    }

    #[test]
    fn prune_old_chains_keeps_newest() {
        let (_d, mut s) = storage();
        let f = s.upsert_file("a").unwrap();
        let id1 = s.insert_snapshot(f, None, b"1", 1).unwrap();
        let _id2 = s.insert_snapshot(f, None, b"2", 2).unwrap();
        let id3 = s.insert_snapshot(f, None, b"3", 3).unwrap();
        assert_eq!(s.chain_count(f).unwrap(), 3);
        s.prune_old_chains(f, 2).unwrap();
        assert_eq!(s.chain_count(f).unwrap(), 2);
        assert!(s.reconstruct(id1).is_err());
        assert_eq!(s.reconstruct(id3).unwrap(), b"3");
    }

    #[test]
    fn prune_old_chains_noop_when_under_limit() {
        let (_d, mut s) = storage();
        let f = s.upsert_file("a").unwrap();
        s.insert_snapshot(f, None, b"1", 1).unwrap();
        s.insert_snapshot(f, None, b"2", 2).unwrap();
        assert_eq!(s.prune_old_chains(f, 5).unwrap(), 0);
        assert_eq!(s.chain_count(f).unwrap(), 2);
    }

    #[test]
    fn drop_oldest_chain_respects_protection_and_min_keep() {
        let (_d, mut s) = storage();
        let f = s.upsert_file("a").unwrap();
        let id1 = s.insert_snapshot(f, None, b"1", 1).unwrap();
        let _id2 = s.insert_snapshot(f, None, b"2", 2).unwrap();
        let id3 = s.insert_snapshot(f, None, b"3", 3).unwrap();
        let freed = s.drop_oldest_chain(f, Some(id3), 1).unwrap();
        assert!(freed > 0);
        assert_eq!(s.chain_count(f).unwrap(), 2);
        assert!(s.reconstruct(id1).is_err());
        assert_eq!(s.reconstruct(id3).unwrap(), b"3");
        assert_eq!(s.drop_oldest_chain(f, Some(id3), 5).unwrap(), 0);
    }

    #[test]
    fn drop_globally_oldest_chain_never_empties_single_chain_file() {
        let (_d, mut s) = storage();
        let f1 = s.upsert_file("f1").unwrap();
        let f2 = s.upsert_file("f2").unwrap();
        let a1 = s.insert_snapshot(f1, None, b"a", 1).unwrap();
        let _a2 = s.insert_snapshot(f1, None, b"b", 2).unwrap();
        let b1 = s.insert_snapshot(f2, None, b"c", 0).unwrap();

        let freed = s.drop_globally_oldest_chain(None).unwrap();
        assert!(freed > 0);
        // f2 is single-chain and older, but must stay intact
        assert_eq!(s.chain_count(f2).unwrap(), 1);
        assert_eq!(s.reconstruct(b1).unwrap(), b"c");
        assert_eq!(s.chain_count(f1).unwrap(), 1);
        assert!(s.reconstruct(a1).is_err());
        assert_eq!(s.drop_globally_oldest_chain(None).unwrap(), 0);
    }

    #[test]
    fn reconstruct_missing_revision_errors() {
        let (_d, s) = storage();
        assert!(s.reconstruct(999_999).is_err());
    }

    #[test]
    fn rename_file_moves_history() {
        let (_d, mut s) = storage();
        let f = s.upsert_file("old").unwrap();
        s.insert_snapshot(f, None, b"x", 1).unwrap();
        s.rename_file("old", "new").unwrap();
        assert_eq!(s.find_file("old").unwrap(), None);
        assert_eq!(s.find_file("new").unwrap(), Some(f));
    }

    // encode_with_dictionary

    #[test]
    fn dictionary_round_trip() {
        let dict = b"shared prefix between consecutive revisions";
        let content = b"shared prefix between consecutive revisions plus a trailing change";
        let enc = encode_with_dictionary(content, dict, 3).unwrap();
        assert_eq!(decode_with_dictionary(&enc, dict).unwrap(), content);
        let enc_empty = encode_with_dictionary(content, &[], 3).unwrap();
        assert_eq!(decode_with_dictionary(&enc_empty, &[]).unwrap(), content);
    }
}
