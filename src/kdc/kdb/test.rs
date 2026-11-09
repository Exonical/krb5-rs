//! MIT's read-only test KDB module (`plugins/kdb/test/kdb_test.c`), selected
//! with `db_library = test`. Principals, aliases and delegation tables come
//! from the module's `[dbmodules]` subsection:
//!
//! ```text
//! [dbmodules]
//!     test = {
//!         alias = { aliasname = canonname  aliasname = @FOREIGN }
//!         princs = {
//!             krbtgt/KRBTEST.COM = {
//!                 flags = +preauth
//!                 maxlife = 1d
//!                 expiration = 14d        # relative to now
//!                 keys = 3 aes256-cts aes128-cts:normal
//!                 strings = require_auth:strong
//!             }
//!         }
//!         delegation = { intermediate_service = target_service }
//!         rbcd = { target_service = intermediate_service }
//!     }
//! ```
//!
//! Keys are derived from a SHA-1 hash of the kvno, enctype, salt type,
//! principal name and lookup realm, so MIT and krb5-rs derive the same keys.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha1::{Digest, Sha1};

use crate::crypto::find_etype;
use crate::crypto::{enctype_from_name, parse_keysalt_list, SaltType};
use crate::kdc::kdb::admin::AttrChange;
use crate::kdc::policy::kerberos_time;
use crate::kdc::{
    IssuePac, KeyEntry, PrincipalAttributes, PrincipalEntry, PrincipalStore, StoreError,
    StoreErrorKind,
};
use crate::pac::{
    PAC_CLIENT_INFO, PAC_DELEGATION_INFO, PAC_LOGON_INFO, PAC_PRIVSVR_CHECKSUM,
    PAC_SERVER_CHECKSUM, PAC_TICKET_CHECKSUM,
};
use crate::profile::string_to_deltat;
use crate::profile::Profile;
use crate::types::{EncryptionKey, PrincipalName};

/// The test module over one `[dbmodules]` subsection.
#[derive(Debug, Clone)]
pub struct TestStore {
    profile: Profile,
    section: String,
    realm: String,
}

fn bad(e: impl std::fmt::Display) -> StoreError {
    StoreError::new(StoreErrorKind::Corrupt, e.to_string())
}

/// `krb5_unparse_name_flags(KRB5_PRINCIPAL_UNPARSE_NO_REALM)`.
fn unparse_no_realm(name: &PrincipalName) -> String {
    let mut out = String::new();
    for (i, c) in name.name_string.iter().enumerate() {
        if i > 0 {
            out.push('/');
        }
        for ch in String::from_utf8_lossy(c.as_bytes()).chars() {
            match ch {
                '/' | '@' | '\\' => {
                    out.push('\\');
                    out.push(ch);
                }
                '\n' => out.push_str("\\n"),
                '\t' => out.push_str("\\t"),
                '\x08' => out.push_str("\\b"),
                '\0' => out.push_str("\\0"),
                _ => out.push(ch),
            }
        }
    }
    out
}

fn components(name: &PrincipalName) -> Vec<u8> {
    name.name_string
        .iter()
        .flat_map(|c| c.as_bytes().to_vec())
        .collect()
}

/// `KRB5_PAC_CREDENTIALS_INFO`.
const PAC_CREDENTIALS_INFO: u32 = 2;

/// `change_auth_indicators`: an indicator `dbincrX` replaces the whole list
/// with `dbincr{X+1}`.
fn change_auth_indicators(inds: &mut Vec<String>) {
    let found = inds.iter().find_map(|i| {
        let b = i.as_bytes();
        (b.len() == 7 && b.starts_with(b"dbincr")).then(|| b[6])
    });
    if let Some(x) = found {
        let mut ind = b"dbincr".to_vec();
        ind.push(x.wrapping_add(1));
        *inds = vec![String::from_utf8_lossy(&ind).into_owned()];
    }
}

/// `arcfour-hmac`, which MIT's module still makes keys for.
const ARCFOUR_HMAC: i32 = 23;

/// `krb5_string_to_keysalts`, keeping `arcfour-hmac` tuples that
/// [`parse_keysalt_list`] drops because krb5-rs has no RC4.
fn keysalts(s: &str) -> Result<Vec<(i32, SaltType)>, StoreError> {
    let mut out: Vec<(i32, SaltType)> = Vec::new();
    for tuple in s.split([',', ' ', '\t']).filter(|t| !t.is_empty()) {
        let mut parsed = parse_keysalt_list(tuple).map_err(bad)?;
        if parsed.is_empty()
            && enctype_from_name(tuple.split(':').next().unwrap_or("")) == Some(ARCFOUR_HMAC)
        {
            let mut salted = parse_keysalt_list(&tuple.replacen(
                tuple.split(':').next().unwrap_or(""),
                "aes128-cts",
                1,
            ))
            .map_err(bad)?;
            parsed = salted
                .drain(..)
                .map(|(_, salt)| (ARCFOUR_HMAC, salt))
                .collect();
        }
        for ks in parsed {
            if !out.contains(&ks) {
                out.push(ks);
            }
        }
    }
    Ok(out)
}

fn salt_number(s: SaltType) -> i32 {
    match s {
        SaltType::Normal => 0,
        SaltType::NoRealm => 2,
        SaltType::OnlyRealm => 3,
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// `make_keyblock`: a key from `SHA-1("kvno etype salttype name realm")`.
fn make_key(
    kvno: u32,
    etype: i32,
    salttype: i32,
    princ: &str,
    realm: &str,
) -> Result<EncryptionKey, StoreError> {
    let hash = Sha1::digest(format!("{kvno} {etype} {salttype} {princ} {realm}").as_bytes());
    let random = |n| hash.iter().copied().cycle().take(n).collect::<Vec<u8>>();
    if etype == ARCFOUR_HMAC {
        // krb5-rs has no RC4; its random-to-key is the identity.
        return Ok(EncryptionKey::new(etype, random(16)));
    }
    let profile = find_etype(etype).map_err(bad)?;
    let key = profile
        .random_to_key(&random(profile.key_bytes()))
        .map_err(bad)?;
    Ok(EncryptionKey::new(etype, key.to_vec()))
}

impl TestStore {
    /// The module for `[dbmodules] section` in `profile`, serving `realm`
    /// (the KDC's default realm).
    pub fn new(profile: Profile, section: &str, realm: &str) -> Self {
        Self {
            profile,
            section: section.to_string(),
            realm: realm.to_string(),
        }
    }

    fn values(&self, path: &[&str]) -> Vec<String> {
        let mut names = vec!["dbmodules", self.section.as_str()];
        names.extend_from_slice(path);
        self.profile.get_values(&names)
    }

    fn string(&self, path: &[&str]) -> Option<String> {
        self.values(path).into_iter().next()
    }

    fn duration(&self, path: &[&str]) -> Result<i32, StoreError> {
        match self.string(path) {
            Some(s) => string_to_deltat(&s).map_err(bad),
            None => Ok(0),
        }
    }

    /// `get_time`: a delta from now; absent is 0 (never).
    fn time(&self, path: &[&str]) -> Result<Option<crate::types::KerberosTime>, StoreError> {
        Ok(match self.string(path) {
            Some(s) => Some(kerberos_time(
                now() + i64::from(string_to_deltat(&s).map_err(bad)?),
            )),
            None => None,
        })
    }

    fn parse(&self, s: &str) -> Result<(PrincipalName, String), StoreError> {
        crate::kdc::kdb::admin::parse_principal(s, &self.realm)
    }

    /// `request_for_us`: the default realm, or an incoming cross-realm TGS
    /// name.
    fn for_us(&self, name: &PrincipalName, realm: &str) -> bool {
        realm == self.realm
            || (name.name_string.len() == 2
                && name.name_string[0].as_bytes() == b"krbtgt"
                && name.name_string[1].as_bytes() == self.realm.as_bytes())
    }

    /// `test_get_principal`. An alias to another realm returns an entry with
    /// only the principal set, in that realm: the KDC makes a client referral
    /// of it, or (for a service) looks up the TGT for that realm, as MIT's
    /// module does under `KRB5_KDB_FLAG_REFERRAL_OK`.
    fn get(
        &self,
        search: &PrincipalName,
        realm: &str,
    ) -> Result<Option<PrincipalEntry>, StoreError> {
        if !self.for_us(search, realm) {
            return Ok(None);
        }
        let search_name = unparse_no_realm(search);
        let (name, ename) = match self.string(&["alias", &search_name]) {
            Some(canon) => {
                let (cname, crealm) = self.parse(&canon)?;
                if crealm != realm {
                    return Ok(Some(stub(cname, crealm)));
                }
                (cname, canon_no_realm(&canon))
            }
            None => (search.clone(), search_name),
        };
        if !self
            .profile
            .subsection_names(&["dbmodules", &self.section, "princs"])
            .contains(&ename)
        {
            return Ok(None);
        }
        let p = |k: &'static str| ["princs", ename.as_str(), k];
        let mut attrs = AttrChange::default();
        if let Some(flags) = self.string(&p("flags")) {
            attrs.add_spec(&flags)?;
        }
        let mut entry = stub(name, realm.to_string());
        entry.attributes = PrincipalAttributes::from_bits_retain(attrs.set & !attrs.clear);
        entry.max_life = Some(Duration::from_secs(
            self.duration(&p("maxlife"))?.max(0) as u64
        ));
        entry.max_renewable_life = Some(Duration::from_secs(
            self.duration(&p("maxrenewlife"))?.max(0) as u64,
        ));
        entry.expiration = self.time(&p("expiration"))?;
        entry.pw_expiration = self.time(&p("pwexpiration"))?;
        for spec in self.values(&p("keys")) {
            let digits = spec.bytes().take_while(u8::is_ascii_digit).count();
            let (kvno, rest) = match digits {
                0 => (1, spec.as_str()),
                n => (spec[..n].parse().map_err(bad)?, spec[n..].trim_start()),
            };
            for (etype, salt) in keysalts(rest)? {
                let key = make_key(kvno, etype, salt_number(salt), &ename, realm)?;
                let salt = match salt {
                    SaltType::Normal => None,
                    SaltType::NoRealm => Some(components(&entry.name)),
                    SaltType::OnlyRealm => Some(realm.as_bytes().to_vec()),
                };
                entry.keys.push(KeyEntry {
                    kvno,
                    key,
                    salt,
                    s2kparams: None,
                });
            }
        }
        for s in self.values(&p("strings")) {
            let (k, v) = s.split_once(':').ok_or_else(|| bad("string without ':'"))?;
            match k {
                "require_auth" => entry.require_auth = Some(v.to_string()),
                "otp" => entry.otp = Some(v.to_string()),
                "pkinit_cert_match" => entry.pkinit_cert_match = Some(v.to_string()),
                _ => {}
            }
        }
        entry.allowed_to_delegate_to = self.values(&["delegation", &ename]);
        let full = format!("{ename}@{realm}");
        entry.allowed_to_delegate_from = self.values(&["rbcd", &full]);
        Ok(Some(entry))
    }
}

fn canon_no_realm(canon: &str) -> String {
    let mut esc = false;
    for (i, c) in canon.char_indices() {
        match c {
            _ if esc => esc = false,
            '\\' => esc = true,
            '@' => return canon[..i].to_string(),
            _ => {}
        }
    }
    canon.to_string()
}

fn stub(name: PrincipalName, realm: String) -> PrincipalEntry {
    PrincipalEntry {
        name,
        realm,
        attributes: PrincipalAttributes::empty(),
        max_life: None,
        max_renewable_life: None,
        expiration: None,
        pw_expiration: None,
        keys: Vec::new(),
        allowed_to_delegate_to: Vec::new(),
        allowed_to_delegate_from: Vec::new(),
        require_auth: None,
        otp: None,
        pkinit_cert_match: None,
        policy: None,
        security_epoch: 0,
        last_admin_unlock: None,
    }
}

impl PrincipalStore for TestStore {
    async fn lookup(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<Option<PrincipalEntry>, StoreError> {
        self.get(name, realm)
    }

    /// `test_issue_pac`: a fake logon info buffer in an initial PAC, copied
    /// (and checked) on later requests.
    fn issue_pac(&self, req: IssuePac<'_>) -> Result<(), StoreError> {
        change_auth_indicators(req.auth_indicators);
        let old = match req.old_pac {
            Some(old) if !(req.client.is_some() && req.protocol_transition) => old,
            _ => {
                if req.client.is_none() {
                    return Err(bad("initial PAC without a client"));
                }
                req.new_pac
                    .add_buffer(PAC_LOGON_INFO, b"fake")
                    .map_err(bad)?;
                if req.replaced_reply_key {
                    req.new_pac
                        .add_buffer(PAC_CREDENTIALS_INFO, b"fake credinfo")
                        .map_err(bad)?;
                }
                return Ok(());
            }
        };
        let mut found_logon_info = false;
        for ty in old.types() {
            if matches!(
                ty,
                PAC_SERVER_CHECKSUM
                    | PAC_PRIVSVR_CHECKSUM
                    | PAC_TICKET_CHECKSUM
                    | PAC_CLIENT_INFO
                    | PAC_DELEGATION_INFO
            ) {
                continue;
            }
            let data = old.get_buffer(ty).map_err(bad)?;
            if ty == PAC_LOGON_INFO {
                if data != b"fake" {
                    return Err(bad("logon info is not the fake one"));
                }
                found_logon_info = true;
            }
            req.new_pac.add_buffer(ty, data).map_err(bad)?;
        }
        if !found_logon_info {
            return Err(bad("subject PAC has no logon info"));
        }
        Ok(())
    }

    /// `test_get_s4u_x509_principal`: the "certificate" is a principal name,
    /// parsed as an enterprise name.
    async fn lookup_s4u_x509(
        &self,
        cert: &[u8],
        name: &PrincipalName,
        realm: &str,
        referral_ok: bool,
    ) -> Result<Option<PrincipalEntry>, StoreError> {
        let text = String::from_utf8_lossy(cert);
        let (n, r) = text.rsplit_once('@').unwrap_or((&text, &self.realm));
        let ent = PrincipalName {
            name_type: 10,
            name_string: vec![rasn::types::GeneralString::from_bytes(n.as_bytes()).map_err(bad)?],
        };
        let Some(entry) = self.get(&ent, r)? else {
            return Ok(None);
        };
        if referral_ok
            || name.name_string.is_empty()
            || (entry.name.name_string == name.name_string && entry.realm == realm)
        {
            return Ok(Some(entry));
        }
        let matched = match self.string(&["alias", &unparse_no_realm(name)]) {
            Some(canon) => {
                let (cn, cr) = self.parse(&canon)?;
                cn.name_string == entry.name.name_string && cr == entry.realm
            }
            None => false,
        };
        if matched {
            Ok(Some(entry))
        } else {
            Err(StoreError::new(
                StoreErrorKind::NameMismatch,
                "client name mismatch",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONF: &str = "[dbmodules]\n test = {\n  alias = {\n   alias1 = user\n   fuser = @FOREIGN\n  }\n  \
        princs = {\n   krbtgt/KRBTEST.COM = {\n    keys = aes128-cts\n   }\n   user = {\n    \
        flags = +preauth\n    maxlife = 1d\n    maxrenewlife = 7d\n    expiration = 14d\n    \
        keys = 3 aes256-cts aes128-cts:normal\n    keys = 2 rc4-hmac aes128-cts:norealm\n    \
        strings = require_auth:strong\n    strings = other:x\n   }\n   svc1 = {\n    keys = aes128-cts\n   }\n  }\n  \
        delegation = {\n   svc1 = svc2\n  }\n  rbcd = {\n   svc1@KRBTEST.COM = svc3@KRBTEST.COM\n  }\n }\n";

    fn store() -> TestStore {
        TestStore::new(
            Profile::parse(CONF).expect("profile"),
            "test",
            "KRBTEST.COM",
        )
    }

    fn name(s: &str) -> PrincipalName {
        crate::kdc::kdb::admin::parse_principal(s, "KRBTEST.COM")
            .expect("name")
            .0
    }

    fn get(s: &str, realm: &str) -> Option<PrincipalEntry> {
        store().get(&name(s), realm).expect("lookup")
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Keys from MIT 1.22.2's test.so (`kadmin.local ktadd -norandkey`).
    #[test]
    fn keys_match_mit_kdb_test() {
        let e = get("user", "KRBTEST.COM").expect("user");
        let keys: Vec<(u32, i32, String, bool)> = e
            .keys
            .iter()
            .map(|k| {
                (
                    k.kvno,
                    k.key.keytype,
                    hex(k.key.key_bytes()),
                    k.salt.is_some(),
                )
            })
            .collect();
        assert_eq!(
            keys,
            vec![
                (
                    3,
                    18,
                    "497d78460e7246cdfffd3994791b478ff03c08fe497d78460e7246cdfffd3994".into(),
                    false
                ),
                (3, 17, "b448996367c8a1a5c1814daee8049f1f".into(), false),
                (2, 23, "b4f6704a55f41b5f8ead622d76b38f54".into(), false),
                (2, 17, "e28d2541bddc24a802789b9f2d1a4f31".into(), true),
            ]
        );
        assert_eq!(e.keys[3].salt.as_deref(), Some(&b"user"[..]));
    }

    #[test]
    fn entry_fields_follow_the_profile() {
        let e = get("user", "KRBTEST.COM").expect("user");
        assert!(e
            .attributes
            .contains(PrincipalAttributes::REQUIRES_PRE_AUTH));
        assert_eq!(e.max_life, Some(Duration::from_secs(86400)));
        assert_eq!(e.max_renewable_life, Some(Duration::from_secs(7 * 86400)));
        assert!(e.expiration.is_some() && e.pw_expiration.is_none());
        assert_eq!(e.require_auth.as_deref(), Some("strong"));
        let t = get("krbtgt/KRBTEST.COM", "KRBTEST.COM").expect("tgt");
        assert_eq!(t.max_renewable_life, Some(Duration::ZERO));
        assert_eq!(t.keys[0].kvno, 1);
        let s = get("svc1", "KRBTEST.COM").expect("svc1");
        assert_eq!(s.allowed_to_delegate_to, vec!["svc2".to_string()]);
        assert_eq!(
            s.allowed_to_delegate_from,
            vec!["svc3@KRBTEST.COM".to_string()]
        );
    }

    #[test]
    fn aliases_and_realms() {
        let e = get("alias1", "KRBTEST.COM").expect("alias");
        assert_eq!(e.name, name("user"));
        assert_eq!(e.keys.len(), 4);
        let f = get("fuser", "KRBTEST.COM").expect("foreign alias");
        // Only the principal is set: `krb5_parse_name("@FOREIGN")`, as MIT.
        let (canon, _) =
            crate::kdc::kdb::admin::parse_principal("@FOREIGN", "KRBTEST.COM").expect("canon");
        assert_eq!((f.name, f.realm.as_str()), (canon, "FOREIGN"));
        assert!(f.keys.is_empty());
        assert!(get("nobody", "KRBTEST.COM").is_none());
        assert!(get("user", "OTHER").is_none());
        // request_for_us: the local TGS name in any realm.
        assert!(get("krbtgt/KRBTEST.COM", "OTHER").is_some());
    }

    #[test]
    fn several_flag_specs_are_refused_like_mit() {
        let conf = "[dbmodules]\n t = {\n  princs = {\n   u = {\n    flags = +preauth +allow_tix\n   }\n  }\n }\n";
        let st = TestStore::new(Profile::parse(conf).expect("profile"), "t", "R");
        assert!(st.get(&name("u"), "R").is_err());
    }

    #[tokio::test]
    async fn s4u_x509_certificate_is_a_principal_name() {
        let st = store();
        let e = st
            .lookup_s4u_x509(b"alias1@KRBTEST.COM", &name("user"), "KRBTEST.COM", false)
            .await
            .expect("lookup")
            .expect("entry");
        assert_eq!(e.name, name("user"));
        let empty = PrincipalName {
            name_type: 1,
            name_string: Vec::new(),
        };
        assert!(st
            .lookup_s4u_x509(b"user", &empty, "KRBTEST.COM", false)
            .await
            .expect("ok")
            .is_some());
        let err = st
            .lookup_s4u_x509(b"user", &name("svc1"), "KRBTEST.COM", false)
            .await
            .expect_err("mismatch");
        assert_eq!(err.kind(), StoreErrorKind::NameMismatch);
    }

    fn issue(
        st: &TestStore,
        client: bool,
        protocol_transition: bool,
        replaced_reply_key: bool,
        old: Option<&crate::pac::Pac>,
        inds: &mut Vec<String>,
    ) -> Result<crate::pac::Pac, StoreError> {
        let entry = st
            .get(&name("user"), "KRBTEST.COM")
            .expect("get")
            .expect("user");
        let mut new = crate::pac::Pac::new();
        st.issue_pac(IssuePac {
            client: client.then_some(&entry),
            protocol_transition,
            replaced_reply_key,
            old_pac: old,
            new_pac: &mut new,
            auth_indicators: inds,
        })?;
        Ok(new)
    }

    #[test]
    fn dbincr_indicator_replaces_the_list() {
        let mut inds = vec!["a".to_string(), "dbincr1".to_string(), "b".to_string()];
        change_auth_indicators(&mut inds);
        assert_eq!(inds, ["dbincr2"]);
        let mut inds = vec!["dbincr".to_string(), "dbincr12".to_string()];
        change_auth_indicators(&mut inds);
        assert_eq!(inds, ["dbincr", "dbincr12"]);
    }

    #[test]
    fn issue_pac_like_mit() {
        let st = store();
        let mut inds = vec!["dbincr1".to_string()];
        let initial = issue(&st, true, false, false, None, &mut inds).expect("initial");
        assert_eq!(inds, ["dbincr2"]);
        assert_eq!(initial.types(), [PAC_LOGON_INFO]);
        assert_eq!(initial.get_buffer(PAC_LOGON_INFO).expect("logon"), b"fake");
        let replaced = issue(&st, true, false, true, None, &mut Vec::new()).expect("replaced");
        assert_eq!(
            replaced.get_buffer(PAC_CREDENTIALS_INFO).expect("credinfo"),
            b"fake credinfo"
        );
        assert!(issue(&st, false, false, false, None, &mut Vec::new()).is_err());

        let mut old = replaced.clone();
        old.add_buffer(PAC_CLIENT_INFO, b"skipped")
            .expect("client info");
        old.add_buffer(PAC_DELEGATION_INFO, b"skipped")
            .expect("delegation");
        let copied = issue(&st, false, false, false, Some(&old), &mut Vec::new()).expect("copy");
        assert_eq!(copied.types(), [PAC_LOGON_INFO, PAC_CREDENTIALS_INFO]);
        // S4U2Self with a local client makes a new PAC.
        let s4u = issue(&st, true, true, false, Some(&old), &mut Vec::new()).expect("s4u");
        assert_eq!(s4u.types(), [PAC_LOGON_INFO]);

        let mut wrong = crate::pac::Pac::new();
        wrong.add_buffer(PAC_LOGON_INFO, b"real").expect("logon");
        assert!(issue(&st, false, false, false, Some(&wrong), &mut Vec::new()).is_err());
        assert!(issue(
            &st,
            false,
            false,
            false,
            Some(&crate::pac::Pac::new()),
            &mut Vec::new()
        )
        .is_err());
    }
}
