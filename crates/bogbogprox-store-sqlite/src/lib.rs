//! SQLite (WAL) implementation of the [`FlowStore`] port.
//!
//! Phase-0 simplification: a single `Mutex<Connection>` guards writes. The
//! design doc's writer-actor + blob store (§7) is a Phase-1 upgrade; the trait
//! boundary means callers won't change when we swap it in.

use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use bogbogprox_core::model::{Flow, FlowSummary, Header, HttpRequest, HttpResponse, Source};
use bogbogprox_core::store::{FlowQuery, FlowStore};

const SCHEMA_VERSION: i64 = 2;

#[derive(Clone)]
pub struct SqliteStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteStore {
    /// Open (creating if needed) a store at `path`. Use `":memory:"` for tests.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        secure_create(path)?;
        let conn = Connection::open(path).context("open sqlite db")?;
        let store = Self::init(conn)?;
        secure_sidecars(path);
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS flows (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                ts            INTEGER NOT NULL,
                source        TEXT    NOT NULL,
                scheme        TEXT    NOT NULL,
                method        TEXT    NOT NULL,
                host          TEXT    NOT NULL,
                port          INTEGER NOT NULL,
                path          TEXT    NOT NULL,
                query         TEXT,
                http_version  TEXT    NOT NULL,
                req_headers   TEXT    NOT NULL,
                req_body      BLOB    NOT NULL,
                req_body_truncated INTEGER NOT NULL DEFAULT 0,
                status        INTEGER,
                resp_version  TEXT,
                resp_headers  TEXT,
                resp_body     BLOB,
                resp_body_truncated INTEGER NOT NULL DEFAULT 0,
                mime          TEXT,
                resp_size     INTEGER,
                duration_ms   INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_flows_ts   ON flows(ts);
            CREATE INDEX IF NOT EXISTS idx_flows_host ON flows(host);
            "#,
        )?;

        let current: Option<i64> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .and_then(|s| s.parse().ok());

        match current {
            None => {
                conn.execute(
                    "INSERT INTO meta(key, value) VALUES ('schema_version', ?1)",
                    params![SCHEMA_VERSION.to_string()],
                )?;
            }
            Some(1) => {
                conn.execute_batch(
                    "ALTER TABLE flows ADD COLUMN req_body_truncated INTEGER NOT NULL DEFAULT 0;
                     ALTER TABLE flows ADD COLUMN resp_body_truncated INTEGER NOT NULL DEFAULT 0;",
                )?;
                conn.execute(
                    "UPDATE meta SET value = ?1 WHERE key = 'schema_version'",
                    params![SCHEMA_VERSION.to_string()],
                )?;
            }
            Some(v) if v > SCHEMA_VERSION => {
                anyhow::bail!("database schema {v} is newer than supported {SCHEMA_VERSION}");
            }
            Some(_) => {}
        }
        // (forward-only migrations dispatch on `current` here in later phases)

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }
}

#[cfg(unix)]
fn secure_create(path: &Path) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    if std::fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        anyhow::bail!("refusing symlinked sqlite database {}", path.display());
    }
    std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create secure sqlite db {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn secure_create(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn secure_sidecars(path: &Path) {
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::PermissionsExt;

    for suffix in [b"-wal".as_slice(), b"-shm".as_slice()] {
        let mut name = path.as_os_str().to_owned().into_vec();
        name.extend_from_slice(suffix);
        let sidecar = std::path::PathBuf::from(std::ffi::OsString::from_vec(name));
        if sidecar.exists() {
            let _ = std::fs::set_permissions(sidecar, std::fs::Permissions::from_mode(0o600));
        }
    }
}

#[cfg(not(unix))]
fn secure_sidecars(_path: &Path) {}

fn headers_to_json(headers: &[Header]) -> String {
    serde_json::to_string(headers).unwrap_or_else(|_| "[]".into())
}

fn headers_from_json(s: &str) -> Vec<Header> {
    serde_json::from_str(s).unwrap_or_default()
}

impl FlowStore for SqliteStore {
    fn insert_request(&self, ts: i64, source: Source, req: &HttpRequest) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"INSERT INTO flows
                (ts, source, scheme, method, host, port, path, query,
                 http_version, req_headers, req_body, req_body_truncated)
               VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)"#,
            params![
                ts,
                source.as_str(),
                req.scheme,
                req.method,
                req.host,
                req.port,
                req.path,
                req.query,
                req.http_version,
                headers_to_json(&req.headers),
                req.body,
                req.body_truncated,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    fn attach_response(&self, id: i64, resp: &HttpResponse, duration_ms: u64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"UPDATE flows SET
                status = ?2, resp_version = ?3, resp_headers = ?4,
                resp_body = ?5, resp_body_truncated = ?6,
                mime = ?7, resp_size = ?8, duration_ms = ?9
               WHERE id = ?1"#,
            params![
                id,
                resp.status,
                resp.http_version,
                headers_to_json(&resp.headers),
                resp.body,
                resp.body_truncated,
                resp.mime(),
                resp.body.len() as i64,
                duration_ms as i64,
            ],
        )?;
        Ok(())
    }

    fn list_flows(&self, q: &FlowQuery) -> Result<Vec<FlowSummary>> {
        let conn = self.conn.lock().unwrap();
        let mut sql = String::from(
            "SELECT id, ts, source, method, scheme, host, port, path, status, mime, resp_size, duration_ms FROM flows",
        );
        let mut clauses: Vec<String> = Vec::new();
        let mut args: Vec<String> = Vec::new();
        if let Some(h) = &q.host {
            clauses.push(format!("host LIKE ?{}", args.len() + 1));
            args.push(format!("%{}%", h));
        }
        if let Some(s) = &q.search {
            let n = args.len();
            clauses.push(format!(
                "(method LIKE ?{0} OR host LIKE ?{0} OR path LIKE ?{0})",
                n + 1
            ));
            args.push(format!("%{}%", s));
        }
        if !clauses.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&clauses.join(" AND "));
        }
        sql.push_str(" ORDER BY id DESC LIMIT ?");
        sql.push_str(&(args.len() + 1).to_string());
        sql.push_str(" OFFSET ?");
        sql.push_str(&(args.len() + 2).to_string());

        let mut stmt = conn.prepare(&sql)?;
        let mut bind: Vec<&dyn rusqlite::ToSql> =
            args.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        let limit = q.limit.clamp(1, 1_000);
        let offset = q.offset.max(0);
        bind.push(&limit);
        bind.push(&offset);

        let rows = stmt.query_map(bind.as_slice(), |r| {
            Ok(FlowSummary {
                id: r.get(0)?,
                ts: r.get(1)?,
                source: source_from_str(&r.get::<_, String>(2)?),
                method: r.get(3)?,
                scheme: r.get(4)?,
                host: r.get(5)?,
                port: r.get(6)?,
                path: r.get(7)?,
                status: r.get(8)?,
                mime: r.get(9)?,
                resp_size: r.get::<_, Option<i64>>(10)?.map(|v| v as u64),
                duration_ms: r.get::<_, Option<i64>>(11)?.map(|v| v as u64),
                connect_ms: None,
                initiator: None,
                wait_ms: None,
                download_ms: None,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    fn get_flow(&self, id: i64) -> Result<Option<Flow>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            r#"SELECT id, ts, source, scheme, method, host, port, path, query,
                      http_version, req_headers, req_body, req_body_truncated,
                      status, resp_version, resp_headers, resp_body,
                      resp_body_truncated, duration_ms
               FROM flows WHERE id = ?1"#,
            params![id],
            |r| {
                let request = HttpRequest {
                    scheme: r.get(3)?,
                    method: r.get(4)?,
                    host: r.get(5)?,
                    port: r.get(6)?,
                    path: r.get(7)?,
                    query: r.get(8)?,
                    http_version: r.get(9)?,
                    headers: headers_from_json(&r.get::<_, String>(10)?),
                    body: r.get(11)?,
                    body_truncated: r.get(12)?,
                };
                let status: Option<u16> = r.get(13)?;
                let response = match status {
                    Some(status) => Some(HttpResponse {
                        status,
                        http_version: r.get::<_, Option<String>>(14)?.unwrap_or_default(),
                        headers: headers_from_json(
                            &r.get::<_, Option<String>>(15)?.unwrap_or_default(),
                        ),
                        body: r.get::<_, Option<Vec<u8>>>(16)?.unwrap_or_default(),
                        body_truncated: r.get(17)?,
                    }),
                    None => None,
                };
                Ok(Flow {
                    id: r.get(0)?,
                    ts: r.get(1)?,
                    source: source_from_str(&r.get::<_, String>(2)?),
                    request,
                    response,
                    duration_ms: r.get::<_, Option<i64>>(18)?.map(|v| v as u64),
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }

    fn count(&self) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.query_row("SELECT COUNT(*) FROM flows", [], |r| r.get(0))?)
    }

    fn clear(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM flows", [])?;
        Ok(())
    }
}

fn source_from_str(s: &str) -> Source {
    match s {
        "repeater" => Source::Repeater,
        "intruder" => Source::Intruder,
        "scanner" => Source::Scanner,
        _ => Source::Proxy,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_req() -> HttpRequest {
        HttpRequest {
            method: "GET".into(),
            scheme: "https".into(),
            host: "example.com".into(),
            port: 443,
            path: "/api/orders".into(),
            query: Some("id=1".into()),
            http_version: "HTTP/1.1".into(),
            headers: vec![("Host".into(), "example.com".into())],
            body: Vec::new(),
            body_truncated: false,
        }
    }

    #[test]
    fn insert_and_read_back() {
        let store = SqliteStore::open_in_memory().unwrap();
        let id = store
            .insert_request(123, Source::Proxy, &sample_req())
            .unwrap();
        assert_eq!(store.count().unwrap(), 1);

        let resp = HttpResponse {
            status: 200,
            http_version: "HTTP/1.1".into(),
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: b"{\"ok\":true}".to_vec(),
            body_truncated: false,
        };
        store.attach_response(id, &resp, 42).unwrap();

        let flow = store.get_flow(id).unwrap().unwrap();
        assert_eq!(flow.request.url(), "https://example.com/api/orders?id=1");
        assert_eq!(flow.response.as_ref().unwrap().status, 200);
        assert_eq!(flow.duration_ms, Some(42));
        assert!(!flow.request.body_truncated);
        assert!(!flow.response.as_ref().unwrap().body_truncated);

        let list = store.list_flows(&FlowQuery::new()).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].status, Some(200));
        assert_eq!(list[0].mime.as_deref(), Some("application/json"));
    }

    #[test]
    fn search_filters() {
        let store = SqliteStore::open_in_memory().unwrap();
        store
            .insert_request(1, Source::Proxy, &sample_req())
            .unwrap();
        let mut other = sample_req();
        other.host = "other.test".into();
        store.insert_request(2, Source::Proxy, &other).unwrap();

        let mut q = FlowQuery::new();
        q.search = Some("orders".into());
        assert_eq!(store.list_flows(&q).unwrap().len(), 2);

        q.search = None;
        q.host = Some("other".into());
        assert_eq!(store.list_flows(&q).unwrap().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn database_file_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "bogbogprox-sqlite-perms-{}-{}.sqlite",
            std::process::id(),
            bogbogprox_core::now_millis()
        ));
        let store = SqliteStore::open(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(store);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn migrates_v1_truncation_columns() {
        let path = std::env::temp_dir().join(format!(
            "bogbogprox-sqlite-v1-{}-{}.sqlite",
            std::process::id(),
            bogbogprox_core::now_millis()
        ));
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             INSERT INTO meta(key,value) VALUES('schema_version','1');
             CREATE TABLE flows (id INTEGER PRIMARY KEY, ts INTEGER, host TEXT);",
        )
        .unwrap();
        drop(conn);

        let store = SqliteStore::open(&path).unwrap();
        let columns: Vec<String> = {
            let conn = store.conn.lock().unwrap();
            let mut stmt = conn.prepare("PRAGMA table_info(flows)").unwrap();
            stmt.query_map([], |row| row.get(1))
                .unwrap()
                .collect::<std::result::Result<_, _>>()
                .unwrap()
        };
        assert!(columns.contains(&"req_body_truncated".to_string()));
        assert!(columns.contains(&"resp_body_truncated".to_string()));
        drop(store);
        let _ = std::fs::remove_file(path);
    }
}
