//! `kdb5_ldap_util`'s directory operations: realm listing, modification and
//! deletion (ldap_realm.c), ticket policies (ldap_tkt_policy.c) and the
//! service password file (kdb5_ldap_services.c).

use std::collections::HashSet;
use std::io::{BufRead, Write};
use std::path::Path;

use krb5_rs::kdc::StoreError;
use ldap3::{Mod, Scope, SearchEntry};

use crate::attr::filter_correct;
use crate::config::{stash_line, LdapConfig};
use crate::conn::Pool;
use crate::entry::Attrs;
use crate::realm::{RealmParams, SCOPE_ONE, SCOPE_SUB};
use crate::store::{attrs_of, ldap_err};
use crate::write::ATTRIBUTES_SET;

/// `subtreeclass` (ldap_realm.c:62): classes a subtree or container
/// reference may have.
pub const SUBTREE_CLASSES: [&str; 7] = [
    "Organization",
    "OrganizationalUnit",
    "Domain",
    "krbContainer",
    "krbRealmContainer",
    "Country",
    "Locality",
];

const NO_SUCH_OBJECT: u32 = 32;

/// Realm attributes to change (`krb5_ldap_modify_realm`); `None` leaves one
/// alone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RealmChanges {
    /// `krbSubTrees`.
    pub subtrees: Option<Vec<String>>,
    /// `krbPrincContainerRef`.
    pub containerref: Option<String>,
    /// `krbSearchScope`.
    pub search_scope: Option<i32>,
    /// `krbMaxTicketLife`.
    pub max_life: Option<i32>,
    /// `krbMaxRenewableAge`.
    pub max_renewable_life: Option<i32>,
    /// `krbTicketFlags`.
    pub tkt_flags: Option<i32>,
}

/// A ticket policy object (`krb5_ldap_policy_params`); `None` fields are
/// absent from the directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TicketPolicy {
    /// The policy name (`cn`).
    pub name: String,
    /// `krbMaxTicketLife`.
    pub max_life: Option<i32>,
    /// `krbMaxRenewableAge`.
    pub max_renewable_life: Option<i32>,
    /// `krbTicketFlags`.
    pub tkt_flags: Option<i32>,
}

fn b(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

fn one(s: impl Into<String>) -> HashSet<Vec<u8>> {
    HashSet::from([s.into().into_bytes()])
}

fn not_found(e: &ldap3::LdapError) -> bool {
    matches!(e, ldap3::LdapError::LdapResult { result } if result.rc == NO_SUCH_OBJECT)
}

/// A realm object and which of its optional attributes are present.
#[derive(Debug, Clone)]
pub struct RealmInfo {
    /// The parameters, with MIT's defaults for missing attributes.
    pub params: RealmParams,
    /// `krbSearchScope`, if present.
    pub search_scope: Option<i32>,
    /// `krbMaxTicketLife`, if present.
    pub max_life: Option<i32>,
    /// `krbMaxRenewableAge`, if present.
    pub max_renewable_life: Option<i32>,
    /// `krbTicketFlags`, if present.
    pub tkt_flags: Option<i32>,
}

/// A bound connection pool and the container, for `kdb5_ldap_util`.
pub struct LdapUtil {
    pool: Pool,
    container: Option<String>,
}

impl LdapUtil {
    /// Bind as `cfg` says.
    pub async fn open(cfg: &LdapConfig) -> Result<Self, StoreError> {
        Ok(LdapUtil {
            pool: Pool::open(cfg).await?,
            container: cfg.container_dn.clone(),
        })
    }

    /// `krb5_ldap_read_krbcontainer_dn`.
    pub fn container(&self) -> Result<&str, StoreError> {
        self.container
            .as_deref()
            .ok_or_else(|| StoreError::rejected("Kerberos Container information is missing"))
    }

    /// The DN of `realm`'s object.
    pub fn realm_dn(&self, realm: &str) -> Result<String, StoreError> {
        Ok(format!("cn={realm},{}", self.container()?))
    }

    /// `krb5_ldap_list_realm`: the `cn` of each realm container.
    pub async fn list_realms(&self) -> Result<Vec<String>, StoreError> {
        let container = self.container()?.to_string();
        let mut h = self.pool.get().await?;
        let (rs, _) = h
            .search(
                &container,
                Scope::OneLevel,
                "(objectclass=krbRealmContainer)",
                vec!["cn"],
            )
            .await
            .and_then(|r| r.success())
            .map_err(|e| ldap_err("Error reading container object", e))?;
        Ok(rs
            .into_iter()
            .filter_map(|e| {
                attrs_of(SearchEntry::construct(e))
                    .first("cn")
                    .map(str::to_string)
            })
            .collect())
    }

    /// `krb5_ldap_read_realm_params`.
    pub async fn read_realm(&self, realm: &str) -> Result<RealmInfo, StoreError> {
        let dn = self.realm_dn(realm)?;
        let mut h = self.pool.get().await?;
        let r = h
            .search(
                &dn,
                Scope::Base,
                "(objectclass=krbRealmContainer)",
                vec![
                    "krbSubTrees",
                    "krbPrincContainerRef",
                    "krbSearchScope",
                    "krbMaxTicketLife",
                    "krbMaxRenewableAge",
                    "krbTicketFlags",
                ],
            )
            .await
            .and_then(|r| r.success());
        let a = match r {
            Ok((rs, _)) => rs
                .into_iter()
                .next()
                .map(|e| attrs_of(SearchEntry::construct(e))),
            Err(e) if not_found(&e) => None,
            Err(e) => return Err(ldap_err("Error reading realm object", e)),
        };
        let a =
            a.ok_or_else(|| StoreError::not_found(format!("Kerberos realm {realm} not found")))?;
        let int = |n: &str| a.first(n).and_then(|v| v.trim().parse::<i32>().ok());
        Ok(RealmInfo {
            search_scope: int("krbsearchscope"),
            max_life: int("krbmaxticketlife"),
            max_renewable_life: int("krbmaxrenewableage"),
            tkt_flags: int("krbticketflags"),
            params: RealmParams::from_attrs(dn, &a),
        })
    }

    /// `checkattributevalue` + `CHECK_CLASS_VALIDITY`: `dn` must exist and
    /// have one of [`SUBTREE_CLASSES`].
    pub async fn check_subtree_class(&self, dn: &str, what: &str) -> Result<(), StoreError> {
        if dn.is_empty() {
            return Err(StoreError::not_found(format!("{what}No such object")));
        }
        let mut h = self.pool.get().await?;
        let (rs, _) = h
            .search(dn, Scope::Base, "(objectclass=*)", vec!["objectclass"])
            .await
            .and_then(|r| r.success())
            .map_err(|e| ldap_err(what.trim_end_matches([':', ' ']), e))?;
        let ok = rs.into_iter().next().is_some_and(|e| {
            let a = attrs_of(SearchEntry::construct(e));
            a.text.get("objectclass").is_some_and(|v| {
                v.iter()
                    .any(|c| SUBTREE_CLASSES.iter().any(|s| s.eq_ignore_ascii_case(c)))
            })
        });
        if ok {
            Ok(())
        } else {
            Err(StoreError::rejected(format!(
                "{what}Object class violation"
            )))
        }
    }

    /// `krb5_ldap_modify_realm`.
    pub async fn modify_realm(&self, realm: &str, c: &RealmChanges) -> Result<(), StoreError> {
        let dn = self.realm_dn(realm)?;
        let mut mods: Vec<Mod<Vec<u8>>> = Vec::new();
        if let Some(subtrees) = &c.subtrees {
            for s in subtrees.iter().filter(|s| !s.is_empty()) {
                self.check_subtree_class(s, "subtree value: ").await?;
            }
            mods.push(Mod::Replace(
                b("krbsubtrees"),
                subtrees.iter().map(|s| b(s)).collect(),
            ));
        }
        if let Some(r) = &c.containerref {
            if !r.is_empty() {
                self.check_subtree_class(r, "container reference value: ")
                    .await?;
            }
            mods.push(Mod::Replace(b("krbPrincContainerRef"), one(r.clone())));
        }
        if let Some(s) = c.search_scope {
            let s = if s == SCOPE_ONE || s == SCOPE_SUB {
                s
            } else {
                SCOPE_SUB
            };
            mods.push(Mod::Replace(b("krbsearchscope"), one(s.to_string())));
        }
        for (n, v) in [
            ("krbMaxRenewableAge", c.max_renewable_life),
            ("krbMaxTicketLife", c.max_life),
            ("krbTicketFlags", c.tkt_flags),
        ] {
            if let Some(v) = v {
                mods.push(Mod::Replace(b(n), one(v.to_string())));
            }
        }
        if mods.is_empty() {
            return Ok(());
        }
        let mut h = self.pool.get().await?;
        h.modify(&dn, mods)
            .await
            .and_then(|r| r.success())
            .map_err(|e| ldap_err("Realm modify failed", e))?;
        Ok(())
    }

    /// `krb5_ldap_delete_realm`: the realm's principals, its password and
    /// ticket policies, then the realm object.
    pub async fn delete_realm(&self, realm: &str) -> Result<(), StoreError> {
        let params = self.read_realm(realm).await?.params;
        let scope = if params.search_scope == SCOPE_ONE {
            Scope::OneLevel
        } else {
            Scope::Subtree
        };
        let filter = format!("(krbprincipalname=*@{})", filter_correct(realm));
        let suffix = format!("@{realm}");
        let mut h = self.pool.get().await?;
        for base in params.search_bases() {
            let rs = match h
                .search(
                    &base,
                    scope,
                    &filter,
                    vec!["krbprincipalname", "objectclass"],
                )
                .await
                .and_then(|r| r.success())
            {
                Ok((rs, _)) => rs,
                Err(e) if not_found(&e) => continue,
                Err(e) => return Err(ldap_err("Error reading principals", e)),
            };
            for e in rs {
                let se = SearchEntry::construct(e);
                let dn = se.dn.clone();
                let a = attrs_of(se);
                delete_names(&mut h, &dn, &a, &suffix).await?;
            }
        }
        for class in ["krbpwdpolicy", "krbTicketPolicy"] {
            let rs = match h
                .search(
                    &params.realm_dn,
                    if class == "krbpwdpolicy" {
                        Scope::OneLevel
                    } else {
                        Scope::Subtree
                    },
                    &format!("(objectclass={class})"),
                    vec!["1.1"],
                )
                .await
                .and_then(|r| r.success())
            {
                Ok((rs, _)) => rs,
                Err(e) => return Err(ldap_err("Error reading ticket policy", e)),
            };
            // Children before parents, so nested policies don't block deletion.
            let mut dns: Vec<String> = rs
                .into_iter()
                .map(|e| SearchEntry::construct(e).dn)
                .collect();
            dns.sort_by_key(|dn| std::cmp::Reverse(dn.split(',').count()));
            for dn in dns {
                let _ = h.delete(&dn).await;
            }
        }
        h.delete(&params.realm_dn)
            .await
            .and_then(|r| r.success())
            .map_err(|e| ldap_err("Realm Delete FAILED", e))?;
        Ok(())
    }

    /// `krb5_ldap_name_to_policydn`.
    pub fn policy_dn(realm_dn: &str, name: &str) -> String {
        format!("cn={},{realm_dn}", filter_correct(name))
    }

    /// `krb5_ldap_create_policy`.
    pub async fn create_tkt_policy(
        &self,
        realm_dn: &str,
        p: &TicketPolicy,
    ) -> Result<(), StoreError> {
        if p.name.is_empty() {
            return Err(StoreError::rejected("Ticket Policy Name missing"));
        }
        let mut attrs = vec![
            (b("cn"), one(p.name.clone())),
            (
                b("objectclass"),
                HashSet::from([b("krbTicketPolicy"), b("krbTicketPolicyaux")]),
            ),
        ];
        for (n, v) in tkt_values(p) {
            if let Some(v) = v {
                attrs.push((b(n), one(v.to_string())));
            }
        }
        let mut h = self.pool.get().await?;
        h.add(&Self::policy_dn(realm_dn, &p.name), attrs)
            .await
            .and_then(|r| r.success())
            .map_err(|e| ldap_err("Ticket policy create FAILED", e))?;
        Ok(())
    }

    /// `krb5_ldap_read_policy`.
    pub async fn read_tkt_policy(
        &self,
        realm_dn: &str,
        name: &str,
    ) -> Result<TicketPolicy, StoreError> {
        if name.is_empty() {
            return Err(StoreError::rejected(
                "Ticket Policy Object information missing",
            ));
        }
        let mut h = self.pool.get().await?;
        let r = h
            .search(
                &Self::policy_dn(realm_dn, name),
                Scope::Base,
                "(objectclass=krbTicketPolicy)",
                vec!["krbMaxTicketLife", "krbMaxRenewableAge", "krbTicketFlags"],
            )
            .await
            .and_then(|r| r.success());
        let a: Option<Attrs> = match r {
            Ok((rs, _)) => rs
                .into_iter()
                .next()
                .map(|e| attrs_of(SearchEntry::construct(e))),
            Err(e) if not_found(&e) => None,
            Err(e) => return Err(ldap_err("Error reading ticket policy", e)),
        };
        let a = a.ok_or_else(|| {
            StoreError::not_found("Ticket policy object: No such object".to_string())
        })?;
        let int = |n: &str| a.first(n).and_then(|v| v.trim().parse::<i32>().ok());
        Ok(TicketPolicy {
            name: name.to_string(),
            max_life: int("krbmaxticketlife"),
            max_renewable_life: int("krbmaxrenewableage"),
            tkt_flags: int("krbticketflags"),
        })
    }

    /// `krb5_ldap_modify_policy`: replace the set fields.
    pub async fn modify_tkt_policy(
        &self,
        realm_dn: &str,
        p: &TicketPolicy,
    ) -> Result<(), StoreError> {
        if p.name.is_empty() {
            return Err(StoreError::rejected("Ticket Policy Name missing"));
        }
        let mods: Vec<Mod<Vec<u8>>> = tkt_values(p)
            .into_iter()
            .filter_map(|(n, v)| v.map(|v| Mod::Replace(b(n), one(v.to_string()))))
            .collect();
        if mods.is_empty() {
            return Ok(());
        }
        let mut h = self.pool.get().await?;
        h.modify(&Self::policy_dn(realm_dn, &p.name), mods)
            .await
            .and_then(|r| r.success())
            .map_err(|e| ldap_err("Ticket policy modify FAILED", e))?;
        Ok(())
    }

    /// `krb5_ldap_delete_policy`: refused while a principal references it.
    pub async fn delete_tkt_policy(
        &self,
        params: &RealmParams,
        name: &str,
    ) -> Result<(), StoreError> {
        let dn = Self::policy_dn(&params.realm_dn, name);
        let scope = if params.search_scope == SCOPE_ONE {
            Scope::OneLevel
        } else {
            Scope::Subtree
        };
        let filter = format!("(krbticketpolicyreference={})", filter_correct(&dn));
        let mut h = self.pool.get().await?;
        for base in params.search_bases() {
            match h
                .search(&base, scope, &filter, vec!["1.1"])
                .await
                .and_then(|r| r.success())
            {
                Ok((rs, _)) if !rs.is_empty() => {
                    return Err(StoreError::rejected(
                        "Delete Failed: One or more Principals associated with the Ticket Policy",
                    ));
                }
                Ok(_) => {}
                Err(e) if not_found(&e) => {}
                Err(e) => return Err(ldap_err("Error reading principals", e)),
            }
        }
        h.delete(&dn)
            .await
            .and_then(|r| r.success())
            .map_err(|e| ldap_err("Ticket policy delete FAILED", e))?;
        Ok(())
    }

    /// `krb5_ldap_list_policy`: the names of the ticket policies under the
    /// realm, from DNs of the form `cn=<name>,<realm DN>`.
    pub async fn list_tkt_policies(&self, realm_dn: &str) -> Result<Vec<String>, StoreError> {
        let mut h = self.pool.get().await?;
        let (rs, _) = h
            .search(
                realm_dn,
                Scope::Subtree,
                "(objectclass=krbTicketPolicy)",
                vec!["cn"],
            )
            .await
            .and_then(|r| r.success())
            .map_err(|e| ldap_err("Error reading container object", e))?;
        Ok(rs
            .into_iter()
            .filter_map(|e| {
                let se = SearchEntry::construct(e);
                let rdn = se.dn.strip_suffix(realm_dn)?.strip_suffix(',')?;
                let (attr, value) = rdn.split_once('=')?;
                (attr.eq_ignore_ascii_case("cn") && !rdn_has_separator(value))
                    .then(|| unescape_rdn(value))
            })
            .collect())
    }
}

fn tkt_values(p: &TicketPolicy) -> [(&'static str, Option<i32>); 3] {
    [
        ("krbMaxTicketLife", p.max_life),
        ("krbMaxRenewableAge", p.max_renewable_life),
        ("krbTicketFlags", p.tkt_flags),
    ]
}

/// True if an RDN value holds an unescaped `,` or `+` (more than one RDN or
/// AVA).
fn rdn_has_separator(v: &str) -> bool {
    let mut esc = false;
    for c in v.chars() {
        match c {
            _ if esc => esc = false,
            '\\' => esc = true,
            ',' | '+' => return true,
            _ => {}
        }
    }
    false
}

/// An RDN value with `\c` and `\xx` escapes removed.
fn unescape_rdn(v: &str) -> String {
    let bytes = v.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            let hex = bytes
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok());
            match hex {
                Some(x) => {
                    out.push(x);
                    i += 3;
                }
                None => {
                    out.push(bytes[i + 1]);
                    i += 2;
                }
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `krb5_ldap_delete_principal` for each of the entry's names in the realm.
async fn delete_names(
    h: &mut ldap3::Ldap,
    dn: &str,
    a: &Attrs,
    suffix: &str,
) -> Result<(), StoreError> {
    let names = a.text.get("krbprincipalname").cloned().unwrap_or_default();
    let (ours, rest): (Vec<String>, Vec<String>) = names.into_iter().partition(|n| {
        n.len() > suffix.len()
            && n.to_ascii_lowercase()
                .ends_with(&suffix.to_ascii_lowercase())
    });
    if ours.is_empty() {
        return Ok(());
    }
    let classes = a.text.get("objectclass").cloned().unwrap_or_default();
    let has = |c: &str| classes.iter().any(|x| x.eq_ignore_ascii_case(c));
    if rest.is_empty() && has("krbprincipal") {
        return match h.delete(dn).await.and_then(|r| r.success()) {
            Ok(_) => Ok(()),
            Err(e) if not_found(&e) => Ok(()),
            Err(e) => Err(ldap_err("Principal delete failed", e)),
        };
    }
    let mut mods = vec![Mod::Delete(
        b("krbprincipalname"),
        ours.iter().map(|n| b(n)).collect(),
    )];
    if rest.is_empty() {
        mods.extend(
            ATTRIBUTES_SET
                .iter()
                .map(|n| Mod::Replace(b(n), HashSet::new())),
        );
        let gone: HashSet<Vec<u8>> = ["krbticketpolicyaux", "krbprincipalaux"]
            .into_iter()
            .filter(|c| has(c))
            .map(b)
            .collect();
        if !gone.is_empty() {
            mods.push(Mod::Delete(b("objectclass"), gone));
        }
    }
    h.modify(dn, mods)
        .await
        .and_then(|r| r.success())
        .map_err(|e| ldap_err("User modification failed", e))?;
    Ok(())
}

/// `kdb5_ldap_stash_service_password`: add `dn#{HEX}<password>` to `file`,
/// or replace the line for `dn` through `<file>.tmp`.
pub fn stash_service_password(file: &Path, dn: &str, password: &str) -> std::io::Result<()> {
    let line = stash_line(dn, password);
    let existing = match std::fs::File::open(file) {
        Ok(f) => Some(
            std::io::BufReader::new(f)
                .lines()
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    let matches = |l: &str| l.starts_with(dn) && l.as_bytes().get(dn.len()) == Some(&b'#');
    match existing {
        Some(lines) if lines.iter().any(|l| matches(l)) => {
            let mut tmp = file.as_os_str().to_owned();
            tmp.push(".tmp");
            let tmp = std::path::PathBuf::from(tmp);
            let mut out = private_file(&tmp, true)?;
            for l in &lines {
                if matches(l) {
                    out.write_all(line.as_bytes())?;
                } else {
                    writeln!(out, "{l}")?;
                }
            }
            out.sync_all()?;
            std::fs::rename(&tmp, file)
        }
        _ => {
            let mut out = private_file(file, false)?;
            out.write_all(line.as_bytes())
        }
    }
}

fn private_file(path: &Path, truncate: bool) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    if truncate {
        o.write(true).create(true).truncate(true);
    } else {
        o.append(true).create(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}
