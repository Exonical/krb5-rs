//! Versioned, embedded, idempotent migrations (`krb5-rs-kdb database migrate`).

use krb5_rs::kdc::StoreError;

use crate::db::Db;

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
        let script = format!(
            "{sql}\nINSERT INTO schema_migrations (version, name) VALUES ({version}, '{name}');"
        );
        db.simple(&script).await?;
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
