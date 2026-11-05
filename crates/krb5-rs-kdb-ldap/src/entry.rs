//! Directory entry <-> MIT `krb5_db_entry` (`populate_krb5_db_entry`,
//! ldap_misc.c:1411-1702).

use std::collections::HashMap;

use krb5_rs::kdc::kdb::mit::{
    set_string_attr, MitEntry, OsaPrincipalData, TlData, CONSTRAINED_DELEGATION_ACL, KADM_DATA,
    LAST_ADMIN_UNLOCK, LAST_PWD_CHANGE, MKVNO,
};
use krb5_rs::kdc::store::StoreError;
use krb5_rs::types::PrincipalName;

use crate::attr::{epoch_time, string_time, tl_from_value, tl_to_value};
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

    pub(crate) fn int(&self, name: &str) -> Option<u32> {
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

/// `KADM5_POLICY` (kadm5/admin.h:99).
pub const KADM5_POLICY: i32 = 0x0800;
/// `KADM5_KEY_HIST` (kadm5/admin.h:113).
pub const KADM5_KEY_HIST: i32 = 0x0040_0000;

/// What MIT keeps in its `KDB_TL_USER_INFO` tl-data: facts about the
/// directory entry rather than the principal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EntryMeta {
    /// The entry's DN.
    pub dn: String,
    /// `krbTicketPolicyReference`.
    pub tkt_policy_dn: Option<String>,
    /// `krbObjectReferences`.
    pub link_dns: Vec<String>,
    /// Whether `krbMaxTicketLife`, `krbMaxRenewableAge` and
    /// `krbTicketFlags` are present.
    pub has_max_life: bool,
    /// See [`EntryMeta::has_max_life`].
    pub has_max_rlife: bool,
    /// See [`EntryMeta::has_max_life`].
    pub has_flags: bool,
    /// The `krbPrincipalName` values.
    pub names: Vec<String>,
    /// Whether the entry is a standalone `krbPrincipal`.
    pub standalone: bool,
    /// The attribute names the entry has (lowercase).
    pub present: Vec<String>,
    /// The `objectClass` values.
    pub classes: Vec<String>,
}

/// `krb5_ldap_policydn_to_name` (ldap_misc.c:1281-1327): the first RDN's
/// value, unescaped.
pub fn policydn_to_name(dn: &str) -> Result<String, StoreError> {
    let bad = || StoreError::corrupt(format!("invalid policy DN {dn:?}"));
    let (_, rest) = dn.split_once('=').ok_or_else(bad)?;
    let mut out = Vec::new();
    let b = rest.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b',' | b'+' => break,
            b'\\' => {
                let hex = b
                    .get(i + 1..i + 3)
                    .and_then(|h| std::str::from_utf8(h).ok());
                if let Some(v) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    out.push(v);
                    i += 3;
                } else {
                    out.push(*b.get(i + 1).ok_or_else(bad)?);
                    i += 2;
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| bad())
}

/// The directory facts of an entry.
pub fn entry_meta(dn: &str, a: &Attrs) -> EntryMeta {
    let has = |n: &str| a.first(n).is_some();
    EntryMeta {
        dn: dn.to_string(),
        tkt_policy_dn: a.first("krbticketpolicyreference").map(str::to_string),
        link_dns: a
            .text
            .get("krbobjectreferences")
            .cloned()
            .unwrap_or_default(),
        has_max_life: has("krbmaxticketlife"),
        has_max_rlife: has("krbmaxrenewableage"),
        has_flags: has("krbticketflags"),
        names: a.text.get("krbprincipalname").cloned().unwrap_or_default(),
        standalone: a
            .text
            .get("objectclass")
            .into_iter()
            .flatten()
            .any(|c| c.eq_ignore_ascii_case("krbprincipal")),
        present: a.text.keys().chain(a.bin.keys()).cloned().collect(),
        classes: a.text.get("objectclass").cloned().unwrap_or_default(),
    }
}

/// `populate_krb5_db_entry` minus the kldap user-info tl-data (see
/// [`EntryMeta`]) and the ticket policy, which the store applies.
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
    let mut osa = OsaPrincipalData::default();
    if let Some(dn) = a.first("krbpwdpolicyreference") {
        osa.policy = Some(policydn_to_name(dn)?.into_bytes());
        osa.aux_attributes |= KADM5_POLICY;
    }
    let hist = a.bytes("krbpwdhistory");
    if !hist.is_empty() {
        let mut sets = hist
            .iter()
            .map(|v| keyseq::decode(v))
            .collect::<Result<Vec<_>, _>>()?;
        osa.admin_history_kvno = sets[0].mkvno as u32;
        sets.sort_by_key(|s| s.key_data.first().map_or(0, |k| k.kvno));
        osa.old_keys = sets.into_iter().map(|s| s.key_data).collect();
        osa.old_key_next = osa.old_keys.len() as u32;
        osa.aux_attributes |= KADM5_KEY_HIST;
    }
    if osa.aux_attributes != 0 {
        e.tl_data.push(TlData {
            kind: KADM_DATA,
            data: osa.encode()?,
        });
    }
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
            data: (mkvno as u16).to_le_bytes().to_vec(),
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
    if let Some(inds) = a.text.get("krbprincipalauthind").filter(|v| !v.is_empty()) {
        set_string_attr(&mut e, b"require_auth", Some(inds.join(" ").as_bytes()))?;
    }
    if a.first("nsAccountLock")
        .is_some_and(|v| v.eq_ignore_ascii_case("TRUE"))
    {
        e.attributes |= 0x40; // KRB5_KDB_DISALLOW_ALL_TIX
    }
    Ok(e)
}

/// Integer policy attributes in `add_policy_mods` order
/// (ldap_pwd_policy.c:52-133).
pub const POLICY_INT_ATTRS: [&str; 11] = [
    "krbmaxpwdlife",
    "krbminpwdlife",
    "krbpwdmindiffchars",
    "krbpwdminlength",
    "krbpwdhistorylength",
    "krbpwdmaxfailure",
    "krbpwdfailurecountinterval",
    "krbpwdlockoutduration",
    "krbpwdattributes",
    "krbpwdmaxlife",
    "krbpwdmaxrenewablelife",
];

/// `populate_policy` (ldap_pwd_policy.c:244-284).
pub fn mit_policy(a: &Attrs, name: &str) -> krb5_rs::kdc::kdb::mit::MitPolicy {
    let v = |n: &str| a.int(n).unwrap_or(0);
    krb5_rs::kdc::kdb::mit::MitPolicy {
        name: name.to_string(),
        pw_max_life: v("krbmaxpwdlife"),
        pw_min_life: v("krbminpwdlife"),
        pw_min_classes: v("krbpwdmindiffchars"),
        pw_min_length: v("krbpwdminlength"),
        pw_history_num: v("krbpwdhistorylength"),
        pw_max_fail: v("krbpwdmaxfailure"),
        pw_failcnt_interval: v("krbpwdfailurecountinterval"),
        pw_lockout_duration: v("krbpwdlockoutduration"),
        attributes: v("krbpwdattributes"),
        max_life: v("krbpwdmaxlife"),
        max_renewable_life: v("krbpwdmaxrenewablelife"),
        allowed_keysalts: a.first("krbpwdallowedkeysalts").map(str::to_string),
        tl_data: Vec::new(),
    }
}

/// `add_policy_mods` values, as `(attribute, value)` pairs.
pub fn policy_values(p: &krb5_rs::kdc::kdb::mit::MitPolicy) -> Vec<(&'static str, String)> {
    let ints = [
        p.pw_max_life,
        p.pw_min_life,
        p.pw_min_classes,
        p.pw_min_length,
        p.pw_history_num,
        p.pw_max_fail,
        p.pw_failcnt_interval,
        p.pw_lockout_duration,
        p.attributes,
        p.max_life,
        p.max_renewable_life,
    ];
    let mut out: Vec<(&'static str, String)> = POLICY_INT_ATTRS
        .iter()
        .zip(ints)
        .map(|(n, v)| (*n, (v as i32).to_string()))
        .collect();
    if let Some(k) = &p.allowed_keysalts {
        out.push(("krbpwdallowedkeysalts", k.clone()));
    }
    out
}

/// Attribute values a principal write sets, as `krb5_ldap_put_principal`
/// builds them (ldap_principal2.c:1095-1430). `None` deletes the attribute.
pub type Values = Vec<(&'static str, Option<Vec<Vec<u8>>>)>;

fn tl_u32(e: &MitEntry, kind: u16) -> Option<u32> {
    e.tl_data
        .iter()
        .find(|t| t.kind == kind)
        .and_then(|t| t.data.get(..4))
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn text(v: impl Into<String>) -> Option<Vec<Vec<u8>>> {
    Some(vec![v.into().into_bytes()])
}

fn time_or_delete(t: u32) -> Option<Vec<Vec<u8>>> {
    (t != 0).then(|| vec![string_time(t).into_bytes()])
}

/// Tl-data types kept in their own attributes, not `krbExtraData`.
const DEDICATED_TL: [u16; 5] = [
    LAST_PWD_CHANGE,
    KADM_DATA,
    KDB_TL_USER_INFO,
    CONSTRAINED_DELEGATION_ACL,
    LAST_ADMIN_UNLOCK,
];

/// `KDB_TL_USER_INFO` (kdb_ldap.h).
pub const KDB_TL_USER_INFO: u16 = 0x00ff;

/// The values a full write of `e` stores. `policy_dn` maps a password
/// policy name to its DN.
pub fn put_values(e: &MitEntry, policy_dn: impl Fn(&str) -> String) -> Result<Values, StoreError> {
    let mut v: Values = vec![
        ("krbmaxticketlife", text((e.max_life as i32).to_string())),
        (
            "krbmaxrenewableage",
            text((e.max_renewable_life as i32).to_string()),
        ),
        ("krbticketflags", text((e.attributes as i32).to_string())),
        ("krbprincipalexpiration", time_or_delete(e.expiration)),
        ("krbpasswordexpiration", time_or_delete(e.pw_expiration)),
        ("krbLastSuccessfulAuth", time_or_delete(e.last_success)),
        ("krbLastFailedAuth", time_or_delete(e.last_failed)),
        ("krbLoginFailedCount", text(e.fail_auth_count.to_string())),
    ];
    let osa = match e.tl_data.iter().find(|t| t.kind == KADM_DATA) {
        Some(t) => OsaPrincipalData::decode(&t.data)?,
        None => OsaPrincipalData::default(),
    };
    let policy = match (&osa.policy, osa.aux_attributes & KADM5_POLICY != 0) {
        (Some(p), true) => {
            let name = String::from_utf8(p.clone())
                .map_err(|_| StoreError::corrupt("policy name is not UTF-8"))?;
            text(policy_dn(&name))
        }
        _ => None,
    };
    v.push(("krbpwdpolicyreference", policy));
    let hist = osa
        .old_keys
        .iter()
        .filter(|k| !k.is_empty())
        .map(|k| keyseq::encode(k, osa.admin_history_kvno as i32))
        .collect::<Result<Vec<_>, _>>()?;
    v.push(("krbpwdhistory", (!hist.is_empty()).then_some(hist)));
    let mkvno = e
        .tl_data
        .iter()
        .find(|t| t.kind == MKVNO)
        .and_then(|t| t.data.get(..2))
        .map_or(0, |b| i32::from(u16::from_le_bytes([b[0], b[1]])));
    let mut keys = Vec::new();
    let mut start = 0;
    for i in 0..e.key_data.len() {
        if i + 1 == e.key_data.len() || e.key_data[i + 1].kvno != e.key_data[start].kvno {
            keys.push(keyseq::encode(&e.key_data[start..=i], mkvno)?);
            start = i + 1;
        }
    }
    v.push(("krbprincipalkey", (!keys.is_empty()).then_some(keys)));
    v.push((
        "krbLastPwdChange",
        tl_u32(e, LAST_PWD_CHANGE).and_then(time_or_delete),
    ));
    let extra: Vec<Vec<u8>> = e
        .tl_data
        .iter()
        .filter(|t| !DEDICATED_TL.contains(&t.kind))
        .map(tl_to_value)
        .collect();
    v.push(("krbExtraData", (!extra.is_empty()).then_some(extra)));
    let inds = krb5_rs::kdc::kdb::mit::string_attributes(e)?
        .into_iter()
        .find(|a| a.0 == b"require_auth")
        .map(|a| {
            String::from_utf8_lossy(&a.1)
                .split(' ')
                .filter(|s| !s.is_empty())
                .take(10)
                .map(|s| s.as_bytes().to_vec())
                .collect::<Vec<_>>()
        })
        .filter(|v| !v.is_empty());
    v.push(("krbPrincipalAuthInd", inds));
    v.push((
        "krbLastAdminUnlock",
        tl_u32(e, LAST_ADMIN_UNLOCK).and_then(time_or_delete),
    ));
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb5_rs::kdc::kdb::mit::KeyData;

    #[test]
    fn put_then_read_round_trips() {
        let mut e = MitEntry {
            principal: PrincipalName::new_principal("alice"),
            realm: "EXAMPLE.COM".into(),
            attributes: 0x80,
            max_life: 36000,
            max_renewable_life: 0,
            expiration: 1_700_000_000,
            pw_expiration: 0,
            last_success: 0,
            last_failed: 1_700_000_100,
            fail_auth_count: 2,
            tl_data: vec![
                TlData {
                    kind: MKVNO,
                    data: 1u16.to_le_bytes().to_vec(),
                },
                TlData {
                    kind: LAST_PWD_CHANGE,
                    data: 1_600_000_000u32.to_le_bytes().to_vec(),
                },
                TlData {
                    kind: 0x0002,
                    data: b"mod".to_vec(),
                },
            ],
            key_data: vec![
                KeyData {
                    ver: 2,
                    kvno: 2,
                    fields: vec![(18, vec![1; 32]), (0, Vec::new())],
                },
                KeyData {
                    ver: 2,
                    kvno: 1,
                    fields: vec![(18, vec![2; 32]), (0, Vec::new())],
                },
            ],
        };
        set_string_attr(&mut e, b"require_auth", Some(b"otp pkinit")).unwrap();
        let osa = OsaPrincipalData {
            policy: Some(b"p1".to_vec()),
            aux_attributes: KADM5_POLICY,
            ..Default::default()
        };
        e.tl_data.push(TlData {
            kind: KADM_DATA,
            data: osa.encode().unwrap(),
        });
        let vals = put_values(&e, |n| format!("cn={n},cn=EXAMPLE.COM,cn=krb")).unwrap();
        let mut a = Attrs::default();
        for (name, val) in vals.into_iter() {
            if let Some(val) = val {
                let n = name.to_ascii_lowercase();
                match std::str::from_utf8(&val[0]) {
                    Ok(_)
                        if !matches!(
                            n.as_str(),
                            "krbprincipalkey" | "krbextradata" | "krbpwdhistory"
                        ) =>
                    {
                        a.text.insert(
                            n,
                            val.into_iter()
                                .map(|v| String::from_utf8(v).unwrap())
                                .collect(),
                        );
                    }
                    _ => {
                        a.bin.insert(n, val);
                    }
                }
            }
        }
        assert_eq!(a.text["krbprincipalauthind"], ["otp", "pkinit"]);
        assert_eq!(
            a.first("krbpwdpolicyreference"),
            Some("cn=p1,cn=EXAMPLE.COM,cn=krb")
        );
        assert_eq!(a.bin["krbprincipalkey"].len(), 2);
        let back = mit_entry(&a, e.principal.clone(), e.realm.clone()).unwrap();
        assert_eq!(back.max_life, 36000);
        assert_eq!(back.expiration, 1_700_000_000);
        assert_eq!(back.fail_auth_count, 2);
        assert_eq!(back.key_data, e.key_data);
        assert_eq!(tl_u32(&back, LAST_PWD_CHANGE), Some(1_600_000_000));
        let osa = OsaPrincipalData::decode(
            &back
                .tl_data
                .iter()
                .find(|t| t.kind == KADM_DATA)
                .unwrap()
                .data,
        )
        .unwrap();
        assert_eq!(osa.policy.as_deref(), Some(&b"p1"[..]));
        assert!(back
            .tl_data
            .iter()
            .any(|t| t.kind == 0x0002 && t.data == b"mod"));
    }
}
