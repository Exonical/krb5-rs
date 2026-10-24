//! Versioned, embedded, idempotent migrations (`krb5-rs-kdb database migrate`).

use std::collections::HashMap;

use krb5_rs::kdc::StoreError;

use crate::db::{is_retryable, Db, TxError};

/// Newest schema version this build understands.
pub const SCHEMA_VERSION: i64 = 1;

/// Forward-only migrations: (version, name, SQL).
const MIGRATIONS: &[(i64, &str, &str)] = &[(1, "initial", include_str!("sql/v1.sql"))];

const ROLES_SQL: &str = include_str!("sql/roles.sql");

/// Options of [`migrate`].
#[derive(Debug, Clone, Default)]
pub struct MigrateOptions {
    /// Create `kdc_admin` / `kdc_replica` and grant them their privileges
    /// (needs a user that may `GRANT`, for example root).
    pub create_roles: bool,
    /// The opt-in multi-region step.
    pub multi_region: Option<MultiRegion>,
}

/// Multi-region settings: the database regions and GLOBAL locality.
#[derive(Debug, Clone)]
pub struct MultiRegion {
    /// `PRIMARY REGION`.
    pub primary_region: String,
    /// Further regions.
    pub regions: Vec<String>,
}

/// What a migration run did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrateReport {
    /// Schema version before the run.
    pub from: i64,
    /// Schema version after the run.
    pub to: i64,
    /// Whether the multi-region step ran.
    pub multi_region: bool,
    /// Whether roles were created.
    pub roles: bool,
}

/// Quote an SQL identifier.
pub(crate) fn ident(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

pub(crate) async fn current_version(db: &Db) -> Result<i64, StoreError> {
    let rows = db
        .rows(
            "SELECT count(*)::INT8 FROM [SHOW TABLES] WHERE table_name = 'schema_migrations'",
            &[],
        )
        .await?;
    let present: i64 = rows.first().map_or(0, |r| r.get(0));
    if present == 0 {
        return Ok(0);
    }
    let rows = db
        .rows(
            "SELECT coalesce(max(version), 0)::INT8 FROM schema_migrations",
            &[],
        )
        .await?;
    Ok(rows.first().map_or(0, |r| r.get(0)))
}

/// The database the connection is using.
pub(crate) async fn database_name(db: &Db) -> Result<String, StoreError> {
    let rows = db.rows("SELECT current_database()", &[]).await?;
    Ok(rows
        .first()
        .map(|r| r.get::<_, String>(0))
        .unwrap_or_default())
}

/// Apply every migration newer than the database, then the optional role and
/// multi-region steps. Idempotent; refuses a database newer than this build.
pub(crate) async fn migrate(db: &Db, opts: &MigrateOptions) -> Result<MigrateReport, StoreError> {
    db.simple(
        "CREATE TABLE IF NOT EXISTS schema_migrations (\
         version INT8 NOT NULL PRIMARY KEY, name STRING NOT NULL, \
         applied_at TIMESTAMPTZ NOT NULL DEFAULT now())",
    )
    .await?;
    let from = current_version(db).await?;
    if from > SCHEMA_VERSION {
        return Err(StoreError::backend(format!(
            "database schema version {from} is newer than the supported {SCHEMA_VERSION}"
        )));
    }
    for (version, name, sql) in MIGRATIONS.iter().filter(|(v, _, _)| *v > from) {
        apply(db, *version, name, sql).await?;
    }
    let dbname = database_name(db).await?;
    if opts.create_roles {
        db.simple(&ROLES_SQL.replace("{db}", &ident(&dbname)))
            .await?;
    }
    if let Some(mr) = &opts.multi_region {
        db.simple(&multi_region_sql(&dbname, mr)).await?;
    }
    Ok(MigrateReport {
        from,
        to: current_version(db).await?,
        multi_region: opts.multi_region.is_some(),
        roles: opts.create_roles,
    })
}

/// Apply one migration. CockroachDB commits each DDL statement on its own
/// (`autocommit_before_ddl`, even inside BEGIN), so a script retried after a
/// serialization failure, or racing another migrate, finds tables an earlier
/// attempt already created: every statement is idempotent (`IF NOT EXISTS`,
/// `ON CONFLICT DO NOTHING`). After a failure the version is read again, as a
/// concurrent migrate or an ambiguous commit may have applied it. Because
/// `IF NOT EXISTS` would also accept an unrelated table of the same name, the
/// resulting tables and indexes are checked before the version is recorded.
async fn apply(db: &Db, version: i64, name: &str, sql: &str) -> Result<(), StoreError> {
    let mut attempt = 0;
    loop {
        let Err(error) = db.simple_once(sql).await else {
            break;
        };
        if current_version(db).await? >= version {
            return Ok(());
        }
        match error {
            TxError::Pg(e) if is_retryable(&e) => {
                db.again(&mut attempt).await.map_err(TxError::into_store)?;
            }
            e => return Err(e.into_store()),
        }
    }
    check_schema(db, version, sql).await?;
    db.simple(&format!(
        "INSERT INTO schema_migrations (version, name) VALUES ({version}, '{name}') \
         ON CONFLICT DO NOTHING"
    ))
    .await
}

/// A table a migration creates: its columns (name, type, nullable) and
/// primary key, as written in the migration SQL.
#[derive(Debug, Default, PartialEq, Eq)]
struct ExpectedTable {
    name: String,
    columns: Vec<(String, String, bool)>,
    primary_key: Vec<String>,
}

/// The tables and secondary indexes (table, index, key columns) a migration
/// creates.
#[derive(Debug, Default, PartialEq, Eq)]
struct ExpectedSchema {
    tables: Vec<ExpectedTable>,
    indexes: Vec<(String, String, Vec<String>)>,
}

fn unquote(s: &str) -> String {
    s.trim().trim_matches('"').to_string()
}

fn column_list(s: &str) -> Vec<String> {
    s.trim_end_matches(';')
        .trim_end_matches(')')
        .split(',')
        .map(unquote)
        .collect()
}

/// Parse the `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS`
/// statements of a migration script (one column definition per line).
fn expected_schema(sql: &str) -> ExpectedSchema {
    let mut out = ExpectedSchema::default();
    let mut table: Option<ExpectedTable> = None;
    for line in sql.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("CREATE TABLE IF NOT EXISTS ") {
            table = Some(ExpectedTable {
                name: unquote(rest.trim_end_matches('(')),
                ..ExpectedTable::default()
            });
        } else if let Some(rest) = line.strip_prefix("CREATE INDEX IF NOT EXISTS ") {
            let Some((index, rest)) = rest.split_once(" ON ") else {
                continue;
            };
            let Some((on, columns)) = rest.split_once(" (") else {
                continue;
            };
            out.indexes
                .push((unquote(on), unquote(index), column_list(columns)));
        } else if line == ");" {
            out.tables.extend(table.take());
        } else if let Some(t) = table.as_mut() {
            let def = line.trim_end_matches(',');
            if let Some(columns) = def.strip_prefix("PRIMARY KEY (") {
                t.primary_key = column_list(columns);
                continue;
            }
            let mut words = def.split_whitespace();
            let (Some(column), Some(ty)) = (words.next(), words.next()) else {
                continue;
            };
            let column = unquote(column);
            if def.contains("PRIMARY KEY") {
                t.primary_key = vec![column.clone()];
            }
            t.columns
                .push((column, ty.to_string(), !def.contains("NOT NULL")));
        }
    }
    out
}

/// Key columns of `index` on `table`, in order (without stored or implicit
/// columns).
async fn index_columns(db: &Db, table: &str, index: &str) -> Result<Vec<String>, StoreError> {
    let rows = db
        .rows(
            &format!(
                "SELECT column_name FROM [SHOW INDEXES FROM {}] \
                 WHERE index_name = $1 AND NOT storing AND NOT implicit ORDER BY seq_in_index",
                ident(table)
            ),
            &[&index],
        )
        .await?;
    Ok(rows.iter().map(|r| r.get::<_, String>(0)).collect())
}

/// Refuse to record `version` when a table or index the migration creates
/// already existed with another definition.
async fn check_schema(db: &Db, version: i64, sql: &str) -> Result<(), StoreError> {
    let mismatch = |what: String| {
        StoreError::backend(format!(
            "existing {what} does not match schema version {version}"
        ))
    };
    let expected = expected_schema(sql);
    for table in &expected.tables {
        let rows = db
            .rows(
                "SELECT column_name, crdb_sql_type, is_nullable FROM information_schema.columns \
                 WHERE table_schema = 'public' AND table_name = $1",
                &[&table.name],
            )
            .await?;
        let actual: HashMap<String, (String, bool)> = rows
            .iter()
            .map(|r| {
                (
                    r.get::<_, String>(0),
                    (r.get::<_, String>(1), r.get::<_, String>(2) == "YES"),
                )
            })
            .collect();
        for (column, ty, nullable) in &table.columns {
            match actual.get(column) {
                Some((t, n)) if t.eq_ignore_ascii_case(ty) && n == nullable => {}
                Some((t, n)) => {
                    let null = if *n { "NULL" } else { "NOT NULL" };
                    return Err(mismatch(format!(
                        "column {}.{column} ({t} {null})",
                        table.name
                    )));
                }
                None => {
                    return Err(mismatch(format!(
                        "table {} (no column {column})",
                        table.name
                    )))
                }
            }
        }
        let pkey = format!("{}_pkey", table.name);
        if index_columns(db, &table.name, &pkey).await? != table.primary_key {
            return Err(mismatch(format!("primary key of {}", table.name)));
        }
    }
    for (table, index, columns) in &expected.indexes {
        if &index_columns(db, table, index).await? != columns {
            return Err(mismatch(format!("index {index} on {table}")));
        }
    }
    Ok(())
}

/// SQL of the multi-region step: the database regions, GLOBAL locality for
/// the replicated tables (consistent local reads in every region, writes pay
/// commit-wait) and REGIONAL BY ROW for `replica_status` (each KDC's
/// heartbeat row lives in its own region).
pub(crate) fn multi_region_sql(db: &str, mr: &MultiRegion) -> String {
    let d = ident(db);
    let mut sql = format!(
        "ALTER DATABASE {d} SET PRIMARY REGION {};\n",
        ident(&mr.primary_region)
    );
    for r in &mr.regions {
        if r != &mr.primary_region {
            sql += &format!(
                "ALTER DATABASE {d} ADD REGION IF NOT EXISTS {};\n",
                ident(r)
            );
        }
    }
    for t in [
        "principals",
        "principal_keys",
        "policies",
        "lockouts",
        "replication_log",
        "replication_meta",
    ] {
        sql += &format!("ALTER TABLE {t} SET LOCALITY GLOBAL;\n");
    }
    sql += "ALTER TABLE replica_status SET LOCALITY REGIONAL BY ROW;\n";
    sql
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_v1_schema_is_parsed_from_its_sql() {
        let v1 = expected_schema(MIGRATIONS[0].2);
        let names: Vec<&str> = v1.tables.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "realms",
                "principals",
                "principal_keys",
                "policies",
                "lockouts",
                "replication_meta",
                "replica_status",
                "transaction_markers",
                "replication_log",
            ]
        );
        let principals = &v1.tables[1];
        assert_eq!(principals.primary_key, ["realm", "name"]);
        assert!(principals
            .columns
            .contains(&("delegate_to".into(), "STRING[]".into(), false)));
        assert!(principals
            .columns
            .contains(&("policy".into(), "STRING".into(), true)));
        assert_eq!(v1.tables[0].primary_key, ["name"]);
        let log = &v1.tables[8];
        assert!(log
            .columns
            .contains(&("key".into(), "STRING".into(), false)));
        assert_eq!(
            v1.indexes,
            [
                (
                    "transaction_markers".into(),
                    "transaction_markers_logical_id".into(),
                    vec!["logical_id".to_string()]
                ),
                (
                    "replication_log".into(),
                    "replication_log_txn_id".into(),
                    vec!["txn_id".to_string()]
                ),
                (
                    "replication_log".into(),
                    "replication_log_entity_key".into(),
                    ["entity", "realm", "key", "bucket", "id"]
                        .map(String::from)
                        .to_vec()
                ),
            ]
        );
        assert!(v1.tables.iter().all(|t| !t.primary_key.is_empty()));
    }

    #[test]
    fn identifiers_are_quoted() {
        assert_eq!(ident("krb5"), "\"krb5\"");
        assert_eq!(ident("a\"b"), "\"a\"\"b\"");
    }

    #[test]
    fn the_multi_region_step_sets_regions_global_and_regional_by_row() {
        let sql = multi_region_sql(
            "krb5",
            &MultiRegion {
                primary_region: "california".into(),
                regions: vec!["california".into(), "ohio".into(), "washington-dc".into()],
            },
        );
        assert!(sql.contains("SET PRIMARY REGION \"california\""));
        assert!(sql.contains("ADD REGION IF NOT EXISTS \"ohio\""));
        assert!(sql.contains("ADD REGION IF NOT EXISTS \"washington-dc\""));
        assert!(!sql.contains("ADD REGION IF NOT EXISTS \"california\""));
        assert!(sql.contains("ALTER TABLE principals SET LOCALITY GLOBAL"));
        assert!(sql.contains("ALTER TABLE replication_log SET LOCALITY GLOBAL"));
        assert!(sql.contains("ALTER TABLE replica_status SET LOCALITY REGIONAL BY ROW"));
    }
}
