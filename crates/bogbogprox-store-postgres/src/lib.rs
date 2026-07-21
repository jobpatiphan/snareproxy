//! Postgres implementation of the [`FlowStore`] port — the scale-out / team-mode
//! backend (design: docs/design/team-mode.md, phase T1).
//!
//! The synchronous `postgres` client drives its own async runtime internally, so
//! it must NOT be used from within our tokio worker threads. We therefore run all
//! database work on a dedicated **DB-actor thread** (plain `std::thread`, no
//! tokio): the sync `FlowStore` methods send a closure to it and block on the
//! reply — the same "block a worker while the store does IO" behaviour the SQLite
//! backend already has via its `Mutex<Connection>`.

use std::sync::mpsc;

use anyhow::{anyhow, Result};
use postgres::types::ToSql;
use postgres::NoTls;
use bogbogprox_core::model::{Flow, FlowSummary, Header, HttpRequest, HttpResponse, Source};
use bogbogprox_core::store::{FlowQuery, FlowStore};

/// Advisory-lock key that serializes schema init across daemons.
const INIT_LOCK: i64 = 91370001;

const SCHEMA: &str = r#"
    CREATE TABLE IF NOT EXISTS flows (
        id            BIGSERIAL PRIMARY KEY,
        ts            BIGINT  NOT NULL,
        source        TEXT    NOT NULL,
        scheme        TEXT    NOT NULL,
        method        TEXT    NOT NULL,
        host          TEXT    NOT NULL,
        port          INTEGER NOT NULL,
        path          TEXT    NOT NULL,
        query         TEXT,
        http_version  TEXT    NOT NULL,
        req_headers   TEXT    NOT NULL,
        req_body      BYTEA   NOT NULL,
        req_body_truncated BOOLEAN NOT NULL DEFAULT FALSE,
        status        INTEGER,
        resp_version  TEXT,
        resp_headers  TEXT,
        resp_body     BYTEA,
        resp_body_truncated BOOLEAN NOT NULL DEFAULT FALSE,
        mime          TEXT,
        resp_size     BIGINT,
        duration_ms   BIGINT
    );
    CREATE INDEX IF NOT EXISTS idx_flows_ts   ON flows(ts);
    CREATE INDEX IF NOT EXISTS idx_flows_host ON flows(host);
    ALTER TABLE flows ADD COLUMN IF NOT EXISTS req_body_truncated BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE flows ADD COLUMN IF NOT EXISTS resp_body_truncated BOOLEAN NOT NULL DEFAULT FALSE;
    CREATE TABLE IF NOT EXISTS bogbogprox_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at BIGINT NOT NULL
    );
"#;

/// Run the schema DDL guarded by an advisory lock so concurrent daemons don't
/// race on `CREATE TABLE IF NOT EXISTS`. The lock and DDL must be *separate*
/// autocommit statements: in one multi-statement query they share a transaction,
/// and the CREATE wouldn't see the lock-holder's committed catalog.
fn init_schema(client: &mut postgres::Client) -> Result<(), postgres::Error> {
    client.execute("SELECT pg_advisory_lock($1)", &[&INIT_LOCK])?;
    let res = client.batch_execute(SCHEMA);
    let _ = client.execute("SELECT pg_advisory_unlock($1)", &[&INIT_LOCK]);
    res
}

type Job = Box<dyn FnOnce(&mut postgres::Client) + Send>;

#[derive(Clone)]
pub struct PostgresStore {
    tx: mpsc::Sender<Job>,
}

impl PostgresStore {
    /// Connect (e.g. `postgres://user:pass@host:5432/db`), ensure the schema, and
    /// start the DB-actor thread.
    pub fn connect(url: &str) -> Result<Self> {
        let url = url.to_string();
        let (job_tx, job_rx) = mpsc::channel::<Job>();
        let (ready_tx, ready_rx) = mpsc::channel::<Result<()>>();

        std::thread::Builder::new()
            .name("bogbogprox-pg".into())
            .spawn(move || {
                let mut client = match postgres::Client::connect(&url, NoTls) {
                    Ok(c) => c,
                    Err(e) => {
                        let _ = ready_tx.send(Err(anyhow!("connect: {e}")));
                        return;
                    }
                };
                if let Err(e) = init_schema(&mut client) {
                    let _ = ready_tx.send(Err(anyhow!("schema: {e}")));
                    return;
                }
                let _ = ready_tx.send(Ok(()));
                while let Ok(job) = job_rx.recv() {
                    job(&mut client);
                }
            })
            .map_err(|e| anyhow!("spawn pg actor: {e}"))?;

        ready_rx
            .recv()
            .map_err(|_| anyhow!("pg actor died on startup"))??;
        Ok(Self { tx: job_tx })
    }

    /// Run `f` on the DB-actor thread and block for its result.
    fn exec<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut postgres::Client) -> Result<T> + Send + 'static,
    {
        let (tx, rx) = mpsc::channel();
        self.tx
            .send(Box::new(move |c| {
                let _ = tx.send(f(c));
            }))
            .map_err(|_| anyhow!("pg actor gone"))?;
        rx.recv().map_err(|_| anyhow!("pg actor dropped the job"))?
    }

    pub fn load_setting(&self, key: &str) -> Result<Option<String>> {
        let key = key.to_string();
        self.exec(move |c| {
            Ok(
                c.query_opt("SELECT value FROM bogbogprox_settings WHERE key=$1", &[&key])?
                    .map(|row| row.get(0)),
            )
        })
    }

    pub fn save_setting(&self, key: &str, value: &str) -> Result<()> {
        let key = key.to_string();
        let value = value.to_string();
        let updated_at = bogbogprox_core::now_millis();
        self.exec(move |c| {
            c.execute(
                "INSERT INTO bogbogprox_settings(key,value,updated_at) VALUES($1,$2,$3) \
                 ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value, updated_at=EXCLUDED.updated_at",
                &[&key, &value, &updated_at],
            )?;
            Ok(())
        })
    }

    /// Update one top-level field of a JSON setting under a row lock. This
    /// prevents unrelated config changes from separate daemons overwriting one
    /// another with stale snapshots.
    pub fn save_setting_field(&self, key: &str, field: &str, value: &str) -> Result<()> {
        let key = key.to_string();
        let field = field.to_string();
        let value: serde_json::Value = serde_json::from_str(value)?;
        let updated_at = bogbogprox_core::now_millis();
        self.exec(move |c| {
            let mut tx = c.transaction()?;
            tx.execute(
                "INSERT INTO bogbogprox_settings(key,value,updated_at) VALUES($1,'{}',$2) \
                 ON CONFLICT(key) DO NOTHING",
                &[&key, &updated_at],
            )?;
            let current = tx
                .query_opt(
                    "SELECT value FROM bogbogprox_settings WHERE key=$1 FOR UPDATE",
                    &[&key],
                )?
                .map(|row| row.get::<_, String>(0));
            let mut document: serde_json::Value = current
                .as_deref()
                .and_then(|raw| serde_json::from_str(raw).ok())
                .unwrap_or_else(|| serde_json::json!({}));
            let object = document
                .as_object_mut()
                .ok_or_else(|| anyhow!("shared config is not a JSON object"))?;
            object.insert(field, value);
            let serialized = serde_json::to_string(&document)?;
            tx.execute(
                "INSERT INTO bogbogprox_settings(key,value,updated_at) VALUES($1,$2,$3) \
                 ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value, updated_at=EXCLUDED.updated_at",
                &[&key, &serialized, &updated_at],
            )?;
            tx.commit()?;
            Ok(())
        })
    }
}

fn headers_to_json(headers: &[Header]) -> String {
    serde_json::to_string(headers).unwrap_or_else(|_| "[]".into())
}

fn headers_from_json(s: &str) -> Vec<Header> {
    serde_json::from_str(s).unwrap_or_default()
}

fn source_from_str(s: &str) -> Source {
    match s {
        "repeater" => Source::Repeater,
        "intruder" => Source::Intruder,
        "scanner" => Source::Scanner,
        _ => Source::Proxy,
    }
}

impl FlowStore for PostgresStore {
    fn insert_request(&self, ts: i64, source: Source, req: &HttpRequest) -> Result<i64> {
        let req = req.clone();
        let src = source.as_str().to_string();
        self.exec(move |c| {
            let headers = headers_to_json(&req.headers);
            let port = req.port as i32;
            let row = c.query_one(
                r#"INSERT INTO flows
                    (ts, source, scheme, method, host, port, path, query,
                     http_version, req_headers, req_body, req_body_truncated)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
                   RETURNING id"#,
                &[
                    &ts,
                    &src,
                    &req.scheme,
                    &req.method,
                    &req.host,
                    &port,
                    &req.path,
                    &req.query,
                    &req.http_version,
                    &headers,
                    &req.body,
                    &req.body_truncated,
                ],
            )?;
            Ok(row.get::<_, i64>(0))
        })
    }

    fn attach_response(&self, id: i64, resp: &HttpResponse, duration_ms: u64) -> Result<()> {
        let resp = resp.clone();
        self.exec(move |c| {
            let headers = headers_to_json(&resp.headers);
            let status = resp.status as i32;
            let size = resp.body.len() as i64;
            let dur = duration_ms as i64;
            let mime = resp.mime();
            c.execute(
                r#"UPDATE flows SET
                    status=$2, resp_version=$3, resp_headers=$4, resp_body=$5,
                    resp_body_truncated=$6, mime=$7, resp_size=$8, duration_ms=$9
                   WHERE id=$1"#,
                &[
                    &id,
                    &status,
                    &resp.http_version,
                    &headers,
                    &resp.body,
                    &resp.body_truncated,
                    &mime,
                    &size,
                    &dur,
                ],
            )?;
            Ok(())
        })
    }

    fn list_flows(&self, q: &FlowQuery) -> Result<Vec<FlowSummary>> {
        let q = q.clone();
        self.exec(move |c| {
            let mut where_parts: Vec<String> = Vec::new();
            let mut svals: Vec<String> = Vec::new();
            if let Some(h) = &q.host {
                svals.push(format!("%{}%", h));
                where_parts.push(format!("host ILIKE ${}", svals.len()));
            }
            if let Some(s) = &q.search {
                svals.push(format!("%{}%", s));
                let n = svals.len();
                where_parts.push(format!(
                    "(method ILIKE ${0} OR host ILIKE ${0} OR path ILIKE ${0})",
                    n
                ));
            }
            let mut sql = String::from(
                "SELECT id, ts, source, method, scheme, host, port, path, status, mime, resp_size, duration_ms FROM flows",
            );
            if !where_parts.is_empty() {
                sql.push_str(" WHERE ");
                sql.push_str(&where_parts.join(" AND "));
            }
            let limit = q.limit.clamp(1, 1_000);
            let offset = q.offset.max(0);
            sql.push_str(&format!(
                " ORDER BY id DESC LIMIT ${} OFFSET ${}",
                svals.len() + 1,
                svals.len() + 2
            ));

            let mut params: Vec<&(dyn ToSql + Sync)> = Vec::new();
            for s in &svals {
                params.push(s);
            }
            params.push(&limit);
            params.push(&offset);

            let rows = c.query(&sql, &params)?;
            Ok(rows
                .iter()
                .map(|r| FlowSummary {
                    id: r.get(0),
                    ts: r.get(1),
                    source: source_from_str(r.get::<_, &str>(2)),
                    method: r.get(3),
                    scheme: r.get(4),
                    host: r.get(5),
                    port: r.get::<_, i32>(6) as u16,
                    path: r.get(7),
                    status: r.get::<_, Option<i32>>(8).map(|v| v as u16),
                    mime: r.get(9),
                    resp_size: r.get::<_, Option<i64>>(10).map(|v| v as u64),
                    duration_ms: r.get::<_, Option<i64>>(11).map(|v| v as u64),
                    connect_ms: None,
                    initiator: None,
                    wait_ms: None,
                    download_ms: None,
                })
                .collect())
        })
    }

    fn get_flow(&self, id: i64) -> Result<Option<Flow>> {
        self.exec(move |c| {
            let Some(r) = c.query_opt(
                r#"SELECT id, ts, source, scheme, method, host, port, path, query,
                          http_version, req_headers, req_body, req_body_truncated,
                          status, resp_version, resp_headers, resp_body,
                          resp_body_truncated, duration_ms
                   FROM flows WHERE id=$1"#,
                &[&id],
            )?
            else {
                return Ok(None);
            };
            let request = HttpRequest {
                scheme: r.get(3),
                method: r.get(4),
                host: r.get(5),
                port: r.get::<_, i32>(6) as u16,
                path: r.get(7),
                query: r.get(8),
                http_version: r.get(9),
                headers: headers_from_json(r.get::<_, &str>(10)),
                body: r.get(11),
                body_truncated: r.get(12),
            };
            let status: Option<i32> = r.get(13);
            let response = status.map(|status| HttpResponse {
                status: status as u16,
                http_version: r.get::<_, Option<String>>(14).unwrap_or_default(),
                headers: headers_from_json(&r.get::<_, Option<String>>(15).unwrap_or_default()),
                body: r.get::<_, Option<Vec<u8>>>(16).unwrap_or_default(),
                body_truncated: r.get(17),
            });
            Ok(Some(Flow {
                id: r.get(0),
                ts: r.get(1),
                source: source_from_str(r.get::<_, &str>(2)),
                request,
                response,
                duration_ms: r.get::<_, Option<i64>>(18).map(|v| v as u64),
            }))
        })
    }

    fn count(&self) -> Result<i64> {
        self.exec(|c| Ok(c.query_one("SELECT COUNT(*) FROM flows", &[])?.get(0)))
    }

    fn clear(&self) -> Result<()> {
        self.exec(|c| {
            c.execute("DELETE FROM flows", &[])?;
            Ok(())
        })
    }
}
