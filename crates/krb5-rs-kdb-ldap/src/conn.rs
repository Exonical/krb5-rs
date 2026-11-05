//! LDAP connections (`krb5_ldap_db_init`, kdb_ldap_conn.c:40-260) and the
//! handle pool (ldap_handle.c).

use std::sync::Arc;
use std::time::Duration;

use krb5_rs::kdc::{StoreError, StoreErrorKind};
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings};
use tokio::sync::{Mutex, Semaphore};

use crate::config::{read_password, LdapConfig};

fn invalid(msg: impl Into<String>) -> StoreError {
    StoreError::new(StoreErrorKind::Rejected, msg.into())
}

fn access(msg: impl Into<String>) -> StoreError {
    StoreError::backend(msg.into())
}

/// How connections authenticate, after `validate_context`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bind {
    /// Simple bind with a DN and password.
    Simple {
        /// The bind DN.
        dn: String,
        /// The password.
        password: String,
    },
    /// SASL bind with a mechanism.
    Sasl {
        /// The mechanism name.
        mech: String,
    },
}

/// `validate_context` (kdb_ldap_conn.c:43-88).
pub fn validate(cfg: &LdapConfig) -> Result<Bind, StoreError> {
    if let Some(mech) = &cfg.sasl_mech {
        return Ok(Bind::Sasl { mech: mech.clone() });
    }
    let dn = cfg
        .bind_dn
        .clone()
        .ok_or_else(|| invalid("LDAP bind dn value missing"))?;
    let password = match (&cfg.bind_pwd, &cfg.service_password_file) {
        (Some(p), _) => p.clone(),
        (None, None) => return Err(invalid("LDAP bind password value missing")),
        (None, Some(file)) => read_password(file, &dn).map_err(|e| {
            StoreError::new(e.kind(), format!("Error reading password from stash: {e}"))
        })?,
    };
    if password.is_empty() {
        return Err(invalid("Service password length is zero"));
    }
    Ok(Bind::Simple { dn, password })
}

async fn authenticate(ldap: &mut Ldap, server: &str, bind: &Bind) -> Result<(), StoreError> {
    match bind {
        Bind::Simple { dn, password } => {
            let r = ldap
                .simple_bind(dn, password)
                .await
                .and_then(|r| r.success());
            r.map(|_| ()).map_err(|e| {
                access(format!(
                    "Cannot bind to LDAP server '{server}' as '{dn}': {e}"
                ))
            })
        }
        Bind::Sasl { mech } => {
            let r = if mech.eq_ignore_ascii_case("EXTERNAL") {
                ldap.sasl_external_bind()
                    .await
                    .and_then(|r| r.success())
                    .map(|_| ())
            } else {
                Err(ldap3::LdapError::InvalidScopeString(format!(
                    "SASL mechanism {mech} is not supported"
                )))
            };
            r.map_err(|e| {
                access(format!(
                    "Cannot bind to LDAP server '{server}' with SASL mechanism '{mech}': {e}"
                ))
            })
        }
    }
}

/// One server's connection, opened and bound (`initialize_server`).
pub async fn connect(server: &str, bind: &Bind) -> Result<Ldap, StoreError> {
    let settings = LdapConnSettings::new().set_conn_timeout(Duration::from_secs(10));
    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, server)
        .await
        .map_err(|e| access(format!("Cannot create LDAP handle for '{server}': {e}")))?;
    ldap3::drive!(conn);
    authenticate(&mut ldap, server, bind).await?;
    Ok(ldap)
}

/// The handle pool: up to `max_server_conns` bound connections, opened on
/// the first server in `ldap_servers` that accepts them.
pub struct Pool {
    servers: Vec<String>,
    bind: Bind,
    idle: Mutex<Vec<Ldap>>,
    slots: Arc<Semaphore>,
}

/// A pooled connection, returned on drop unless it failed.
pub struct Handle<'a> {
    pool: &'a Pool,
    ldap: Option<Ldap>,
    _permit: tokio::sync::SemaphorePermit<'a>,
}

impl std::ops::Deref for Handle<'_> {
    type Target = Ldap;
    fn deref(&self) -> &Ldap {
        self.ldap.as_ref().expect("live handle")
    }
}

impl std::ops::DerefMut for Handle<'_> {
    fn deref_mut(&mut self) -> &mut Ldap {
        self.ldap.as_mut().expect("live handle")
    }
}

impl Handle<'_> {
    /// Drop the connection instead of returning it (after a server error).
    pub fn discard(mut self) {
        self.ldap = None;
    }
}

impl Drop for Handle<'_> {
    fn drop(&mut self) {
        if let Some(ldap) = self.ldap.take() {
            if let Ok(mut idle) = self.pool.idle.try_lock() {
                idle.push(ldap);
            }
        }
    }
}

impl Pool {
    /// Validate the bind parameters and open the first connection.
    pub async fn open(cfg: &LdapConfig) -> Result<Self, StoreError> {
        let bind = validate(cfg)?;
        let pool = Pool {
            servers: cfg.servers.clone(),
            bind,
            idle: Mutex::new(Vec::new()),
            slots: Arc::new(Semaphore::new(cfg.max_server_conns as usize)),
        };
        let first = pool.dial().await?;
        pool.idle.lock().await.push(first);
        Ok(pool)
    }

    async fn dial(&self) -> Result<Ldap, StoreError> {
        let mut last = access("no LDAP servers configured");
        for server in &self.servers {
            match connect(server, &self.bind).await {
                Ok(ldap) => return Ok(ldap),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// `krb5_ldap_request_handle_from_pool`.
    pub async fn get(&self) -> Result<Handle<'_>, StoreError> {
        let permit = self
            .slots
            .acquire()
            .await
            .map_err(|e| access(e.to_string()))?;
        let idle = self.idle.lock().await.pop();
        let ldap = match idle {
            Some(mut l) if !l.is_closed() => l,
            _ => self.dial().await?,
        };
        Ok(Handle {
            pool: self,
            ldap: Some(ldap),
            _permit: permit,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> LdapConfig {
        LdapConfig {
            servers: vec!["ldapi://".into()],
            container_dn: None,
            bind_dn: None,
            bind_pwd: None,
            service_password_file: None,
            sasl_mech: None,
            sasl_authcid: None,
            sasl_authzid: None,
            sasl_realm: None,
            max_server_conns: 5,
            disable_last_success: false,
            disable_lockout: false,
        }
    }

    #[test]
    fn validate_messages() {
        let mut c = cfg();
        assert!(validate(&c)
            .unwrap_err()
            .to_string()
            .contains("LDAP bind dn value missing"));
        c.bind_dn = Some("cn=kdc".into());
        assert!(validate(&c)
            .unwrap_err()
            .to_string()
            .contains("LDAP bind password value missing"));
        c.bind_pwd = Some(String::new());
        assert!(validate(&c)
            .unwrap_err()
            .to_string()
            .contains("Service password length is zero"));
        c.bind_pwd = Some("pw".into());
        assert_eq!(
            validate(&c).unwrap(),
            Bind::Simple {
                dn: "cn=kdc".into(),
                password: "pw".into()
            }
        );
        c.sasl_mech = Some("EXTERNAL".into());
        assert_eq!(
            validate(&c).unwrap(),
            Bind::Sasl {
                mech: "EXTERNAL".into()
            }
        );
    }
}
