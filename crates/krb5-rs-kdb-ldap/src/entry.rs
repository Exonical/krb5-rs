//! Directory entry <-> MIT `krb5_db_entry` (`populate_krb5_db_entry`,
//! ldap_misc.c:1411-1702).

use std::collections::HashMap;

use krb5_rs::kdc::kdb::mit::{
    MitEntry, TlData, CONSTRAINED_DELEGATION_ACL, LAST_ADMIN_UNLOCK, LAST_PWD_CHANGE, MKVNO,
};
use krb5_rs::kdc::store::StoreError;
use krb5_rs::types::PrincipalName;

use crate::attr::{epoch_time, tl_from_value};
use crate::keyseq;

/// Attribute values of one search entry, names lowercased.
#[derive(Debug, Clone, Default)]
pub struct Attrs {
    /// Text values.
    pub text: HashMap<String, Vec<String>>,
    /// Binary values (`krbPrincipalKey`, `krbPwdHistory`, `krbExtraData`).
    pub bin: HashMap<String, Vec<Vec<u8>>>,
}

impl Attrs {
    /// First text value of `name`.
    pub fn first(&self, name: &str) -> Option<&str> {
        self.text
            .get(&name.to_ascii_lowercase())
            .and_then(|v| v.first())
            .map(String::as_str)
    }

    /// All binary values of `name` (text values as bytes too).
    pub fn bytes(&self, name: &str) -> Vec<Vec<u8>> {
        let n = name.to_ascii_lowercase();
        let mut out = self.bin.get(&n).cloned().unwrap_or_default();
        out.extend(
            self.text
                .get(&n)
                .into_iter()
                .flatten()
                .map(|s| s.as_bytes().to_vec()),
        );
        out
    }

    fn int(&self, name: &str) -> Option<u32> {
        // atoi: leading digits, 0 otherwise.
        self.first(name).map(|v| {
            let v = v.trim_start();
            let (neg, d) = v.strip_prefix('-').map_or((false, v), |d| (true, d));
            let n: i64 = d
                .chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
                .parse()
                .unwrap_or(0);
            (if neg { -n } else { n }) as i32 as u32
        })
    }

    fn time(&self, name: &str) -> Result<Option<u32>, StoreError> {
        self.first(name).map(epoch_time).transpose()
    }
}

/// `populate_krb5_db_entry` minus the kldap user-info tl-data, which the
/// store keeps itself.
pub fn mit_entry(a: &Attrs, name: PrincipalName, realm: String) -> Result<MitEntry, StoreError> {
    let mut e = MitEntry {
        principal: name,
        realm,
        attributes: a.int("krbticketflags").unwrap_or(0),
        max_life: a.int("krbmaxticketlife").unwrap_or(0),
        max_renewable_life: a.int("krbmaxrenewableage").unwrap_or(0),
        expiration: a.time("krbprincipalexpiration")?.unwrap_or(0),
        pw_expiration: a.time("krbpasswordexpiration")?.unwrap_or(0),
        last_success: a.time("krbLastSuccessfulAuth")?.unwrap_or(0),
        last_failed: a.time("krbLastFailedAuth")?.unwrap_or(0),
        fail_auth_count: a.int("krbLoginFailedCount").unwrap_or(0),
        tl_data: Vec::new(),
        key_data: Vec::new(),
    };
    let mut mkvno = 0;
    for v in a.bytes("krbprincipalkey") {
        let set = keyseq::decode(&v)?;
        mkvno = set.mkvno;
        e.key_data.extend(set.key_data);
    }
    // krb5_decode_krbsecretkey: newest kvno first.
    e.key_data.sort_by(|x, y| y.kvno.cmp(&x.kvno));
    if mkvno != 0 {
        e.tl_data.push(TlData {
            kind: MKVNO,
            data: (mkvno as u32).to_le_bytes().to_vec(),
        });
    }
    if let Some(t) = a.time("krbLastPwdChange")? {
        e.tl_data.push(TlData {
            kind: LAST_PWD_CHANGE,
            data: t.to_le_bytes().to_vec(),
        });
    }
    if let Some(t) = a.time("krbLastAdminUnlock")? {
        e.tl_data.push(TlData {
            kind: LAST_ADMIN_UNLOCK,
            data: t.to_le_bytes().to_vec(),
        });
    }
    for v in a.text.get("krballowedtodelegateto").into_iter().flatten() {
        let mut d = v.as_bytes().to_vec();
        d.push(0);
        e.tl_data.push(TlData {
            kind: CONSTRAINED_DELEGATION_ACL,
            data: d,
        });
    }
    for v in a.bytes("krbExtraData") {
        let tl = tl_from_value(&v)?;
        e.tl_data.retain(|t| t.kind != tl.kind);
        e.tl_data.push(tl);
    }
    if a.first("nsAccountLock")
        .is_some_and(|v| v.eq_ignore_ascii_case("TRUE"))
    {
        e.attributes |= 0x40; // KRB5_KDB_DISALLOW_ALL_TIX
    }
    Ok(e)
}
