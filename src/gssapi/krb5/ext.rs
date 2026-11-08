//! Context extensions: gss_pseudo_random (prf.c), gss_inquire_context
//! (inq_context.c) and gss_inquire_sec_context_by_oid (gssapi_krb5.c,
//! inq_context.c).

use super::*;

/// libdefaults `clockskew` default, the grace period inq_context.c:116
/// gives an acceptor's context lifetime.
const CLOCKSKEW_SECS: i64 = 300;

/// GSS_KRB5_GET_TKT_FLAGS_OID (1.2.840.113554.1.2.2.5.1).
pub const GET_TKT_FLAGS_OID: &[u8] = b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x01";
/// GSS_KRB5_INQ_SSPI_SESSION_KEY_OID (1.2.840.113554.1.2.2.5.5).
pub const INQ_SSPI_SESSION_KEY_OID: &[u8] = b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x05";
/// GSS_KRB5_EXPORT_LUCID_SEC_CONTEXT_OID (1.2.840.113554.1.2.2.5.6).
pub const EXPORT_LUCID_SEC_CONTEXT_OID: &[u8] = b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x06";
/// GSS_KRB5_EXTRACT_AUTHZ_DATA_FROM_SEC_CONTEXT_OID (…5.10); the ad-type
/// is appended as one more arc.
pub const EXTRACT_AUTHZ_DATA_OID: &[u8] = b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x0a";
/// GSS_KRB5_EXTRACT_AUTHTIME_FROM_SEC_CONTEXT_OID (…5.12).
pub const EXTRACT_AUTHTIME_OID: &[u8] = b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x0c";
/// GET_SEC_CONTEXT_SASL_SSF_OID (…5.15).
pub const SASL_SSF_OID: &[u8] = b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x0f";
/// GSS_KRB5_INQ_ODBC_SESSION_KEY_OID (…5.19).
pub const INQ_ODBC_SESSION_KEY_OID: &[u8] = b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x13";
/// GSS_KRB5_SESSION_KEY_ENCTYPE_OID (1.2.840.113554.1.2.2.4); the enctype
/// is appended as one more arc.
pub const SESSION_KEY_ENCTYPE_OID: &[u8] = b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x04";

/// `prf_key` for [`Krb5Context::pseudo_random`] (RFC 4401).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrfKey {
    /// GSS_C_PRF_KEY_PARTIAL: the initiator subkey (or session key).
    Partial,
    /// GSS_C_PRF_KEY_FULL: the acceptor subkey when there is one.
    Full,
}

/// Result of [`Krb5Context::inquire`] (gss_inquire_context).
#[derive(Debug, Clone)]
pub struct ContextInfo {
    /// Initiator principal and its realm.
    pub initiator: (PrincipalName, String),
    /// Acceptor principal.
    pub acceptor: PrincipalName,
    /// Remaining lifetime; zero means GSS_S_CONTEXT_EXPIRED.
    pub lifetime: Duration,
    /// Mechanism OID (krb5 or IAKERB).
    pub mech: &'static [u8],
    /// Context flags.
    pub flags: GssFlags,
    /// Whether this side initiated the context.
    pub locally_initiated: bool,
    /// Always true: a [`Krb5Context`] is established.
    pub open: bool,
}

/// `generic_gss_oid_compose` (oid_ops.c:415-462): append `suffix` as one
/// base-128 arc.
fn oid_compose(prefix: &[u8], suffix: u32) -> Vec<u8> {
    let mut arc = Vec::new();
    let mut n = suffix;
    while n != 0 {
        arc.push((n & 0x7f) as u8 | if arc.is_empty() { 0 } else { 0x80 });
        n >>= 7;
    }
    arc.reverse();
    let mut oid = prefix.to_vec();
    oid.extend_from_slice(&arc);
    oid
}

/// `generic_gss_oid_decompose` (oid_ops.c:368-413).
fn oid_decompose(prefix: &[u8], oid: &[u8]) -> Option<i32> {
    let rest = oid.strip_prefix(prefix)?;
    let mut value: i32 = 0;
    for &b in rest {
        value = value.checked_shl(7)? | i32::from(b & 0x7f);
        if b & 0x80 == 0 {
            break;
        }
    }
    Some(value)
}

/// `ssf` column of lib/crypto/krb/etypes.c.
fn enctype_ssf(enctype: i32) -> Option<u32> {
    match enctype {
        16 => Some(112),
        17 | 19 | 25 => Some(128),
        18 | 20 | 26 => Some(256),
        23 | 24 => Some(64),
        _ => None,
    }
}

impl Krb5Context {
    /// MIT `have_acceptor_subkey ? acceptor_subkey : subkey`.
    fn final_key(&self) -> &EncryptionKey {
        self.acceptor_subkey.as_ref().unwrap_or(&self.key)
    }

    /// gss_pseudo_random (prf.c krb5_gss_pseudo_random, RFC 4402):
    /// T(i) = PRF(key, i || prf_in), truncated to `len` bytes.
    pub fn pseudo_random(
        &self,
        prf_key: PrfKey,
        prf_in: &[u8],
        len: usize,
    ) -> Result<Vec<u8>, Krb5Error> {
        let key = match prf_key {
            PrfKey::Full => self.final_key(),
            PrfKey::Partial => &self.key,
        };
        let mut out = Vec::with_capacity(len);
        if len == 0 {
            return Ok(out);
        }
        let profile = find_etype(key.keytype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        let mut ns = vec![0u8; 4];
        ns.extend_from_slice(prf_in);
        let mut i: u32 = 0;
        while out.len() < len {
            ns[..4].copy_from_slice(&i.to_be_bytes());
            let t = profile
                .prf(key.key_bytes(), &ns)
                .map_err(|e| Krb5Error::Crypto(e.to_string()))?;
            let take = t.len().min(len - out.len());
            out.extend_from_slice(&t[..take]);
            i = i.wrapping_add(1);
        }
        Ok(out)
    }

    /// gss_inquire_context (inq_context.c:80-178).
    pub fn inquire(&self) -> ContextInfo {
        let now = chrono::Utc::now();
        let start = if self.initiate {
            now
        } else {
            now - chrono::Duration::seconds(CLOCKSKEW_SECS)
        };
        let lifetime = self
            .endtime
            .with_timezone(&chrono::Utc)
            .signed_duration_since(start)
            .to_std()
            .unwrap_or(Duration::ZERO);
        ContextInfo {
            initiator: (self.initiator.clone(), self.crealm.clone()),
            acceptor: self.acceptor.clone(),
            lifetime,
            mech: self.mech,
            flags: self.flags,
            locally_initiated: self.initiate,
            open: true,
        }
    }

    /// Mechanism of the context (`ctx->mech_used`).
    pub fn mech(&self) -> &'static [u8] {
        self.mech
    }

    /// gss_krb5_get_tkt_flags.
    pub fn ticket_flags(&self) -> TicketFlags {
        *self.ticket_flags
    }

    /// gss_krb5_extract_authtime_from_sec_context.
    pub fn authtime(&self) -> KerberosTime {
        self.authtime
    }

    /// gss_krb5_extract_authz_data_from_sec_context: the `ad_type`
    /// elements of the ticket and authenticator authdata (acceptor only).
    pub fn authz_data(&self, ad_type: i32) -> Vec<&[u8]> {
        self.authdata
            .iter()
            .filter(|ad| ad.ad_type == ad_type)
            .map(|ad| ad.ad_data.as_ref())
            .collect()
    }

    /// GSS_C_INQ_SSPI_SESSION_KEY: the acceptor subkey, else the
    /// initiator subkey or session key.
    pub fn session_key(&self) -> &EncryptionKey {
        self.final_key()
    }

    /// GSS_KRB5_INQ_ODBC_SESSION_KEY: the ticket session key.
    pub fn ticket_session_key(&self) -> &EncryptionKey {
        &self.ticket_key
    }

    /// GET_SEC_CONTEXT_SASL_SSF: the strength of the final key's enctype.
    pub fn sasl_ssf(&self) -> Option<u32> {
        enctype_ssf(self.final_key().keytype)
    }

    /// gss_inquire_sec_context_by_oid (gssapi_krb5.c:344-389): MIT's
    /// buffer-set results for the krb5 mechanism's context OIDs.
    /// GSS_KRB5_EXPORT_LUCID_SEC_CONTEXT returns a C structure pointer in
    /// MIT; use [`Krb5Context::export_lucid_sec_context`] instead.
    pub fn inquire_sec_context_by_oid(&self, oid: &[u8]) -> Result<Vec<Vec<u8>>, Krb5Error> {
        let key_result = |key: &EncryptionKey| {
            vec![
                key.key_bytes().to_vec(),
                oid_compose(SESSION_KEY_ENCTYPE_OID, key.keytype as u32),
            ]
        };
        if oid.starts_with(GET_TKT_FLAGS_OID) {
            Ok(vec![self.ticket_flags.bits().to_ne_bytes().to_vec()])
        } else if oid.starts_with(EXTRACT_AUTHZ_DATA_OID) {
            match oid_decompose(EXTRACT_AUTHZ_DATA_OID, oid) {
                Some(ad_type) if ad_type != 0 => Ok(self
                    .authz_data(ad_type)
                    .into_iter()
                    .map(<[u8]>::to_vec)
                    .collect()),
                _ => Err(gss(GssError::Failure)),
            }
        } else if oid.starts_with(INQ_SSPI_SESSION_KEY_OID) {
            Ok(key_result(self.final_key()))
        } else if oid.starts_with(INQ_ODBC_SESSION_KEY_OID) {
            Ok(key_result(&self.ticket_key))
        } else if oid.starts_with(EXTRACT_AUTHTIME_OID) {
            let t = self.authtime.timestamp() as i32;
            Ok(vec![t.to_ne_bytes().to_vec()])
        } else if oid.starts_with(SASL_SSF_OID) {
            let ssf = self.sasl_ssf().ok_or(gss(GssError::Failure))?;
            Ok(vec![ssf.to_be_bytes().to_vec()])
        } else {
            Err(gss(GssError::Unavailable))
        }
    }
}

/// gss_krb5_lucid_context_v1_t for a CFX (protocol 1) context.
#[derive(Debug, Clone)]
pub struct LucidContext {
    /// Structure version (1).
    pub version: u32,
    /// Whether this side initiated the context.
    pub initiate: bool,
    /// Context expiry (unix seconds).
    pub endtime: u32,
    /// Next send sequence number.
    pub send_seq: u64,
    /// Receive sequence number.
    pub recv_seq: u64,
    /// Protocol (always 1, CFX).
    pub protocol: u32,
    /// cfx_kd.ctx_key: the initiator subkey or session key.
    pub ctx_key: EncryptionKey,
    /// cfx_kd.acceptor_subkey when present.
    pub acceptor_subkey: Option<EncryptionKey>,
}

impl Krb5Context {
    /// gss_krb5_export_lucid_sec_context (lucid_context.c
    /// make_external_lucid_ctx_v1); like MIT this consumes the context.
    pub fn export_lucid_sec_context(self) -> LucidContext {
        LucidContext {
            version: 1,
            initiate: self.initiate,
            endtime: self.endtime.timestamp() as u32,
            send_seq: self.seq_send,
            recv_seq: self.seqstate.base(),
            protocol: 1,
            ctx_key: self.key,
            acceptor_subkey: self.acceptor_subkey,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn ctx(etype: i32, k1: &str, k2: &str) -> Krb5Context {
        let none = PrincipalName {
            name_type: 0,
            name_string: Vec::new(),
        };
        let end = (chrono::Utc::now() + chrono::Duration::hours(1)).fixed_offset();
        let mut c = Krb5Context::partial(
            GssFlags::empty(),
            true,
            none.clone(),
            "R".into(),
            none,
            end,
            EncryptionKey::new(etype, hex(k1)),
            0,
        );
        c.acceptor_subkey = Some(EncryptionKey::new(etype, hex(k2)));
        c
    }

    // MIT src/tests/gssapi/t_prf.c vectors.
    #[test]
    fn pseudo_random_matches_t_prf() {
        let input = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123456789";
        for (etype, k1, o1, k2, o2) in [
            (17, "6C742096EB896230312B73972FA28B5D",
             "94208D982FC1BB7778128BDD77904420B45C9DA699F3117BCE66E39602128EF0296611A6D191A5828530F20F",
             "FA61138C109D834A477D24C7311BE6DA",
             "0FAEDF0F842CC834FEE750487E1B622739286B975FE5B7F45AB053143C75CA0DF5D3D4BBB80F6A616C7C9027"),
            (18, "08FCDAFD5832611B73BA7B497FEBFF8C954B4B58031CAD9B977C3B8C25192FD6",
             "E627EFC14EF5B6D629F830C7109DEA0D3D7D36E8CD57A1F301C5452494A1928F05AFFBEE3360232209D3BE0D",
             "F5B68B7823D8944F33F41541B4E4D38C9B2934F8D16334A796645B066152B4BE",
             "112F2B2D878590653CCC7DE278E9F0AA46FA5A380B6259F774CB7C134FCD37F61A50FD0D9F89BF8FE1A6B593"),
            (19, "089BCA48B105EA6EA77CA5D2F39DC5E7",
             "ED1736209B7C59C9F6A3AE8CCC8A7C97ADFDD11688ADF304F2F74252CBACD311A2D9253211FDA49745CE4F62",
             "3705D96080C17728A0E800EAB6E0D23C",
             "2BB41B183D76D8D5B30CBB049A7EFE9F350EFA058DC2C4D868308D354A7B199BE6FD1F22B53C038BC6036581"),
            (20, "45BD806DBF6A833A9CFFC1C94589A222367A79BC21C413718906E9F578A78467",
             "1C613AE8B77A3B4D783F3DCE6C9178FC025E87F48A44784A69CB5FC697FE266A6141905067EF78566D309085",
             "6D404D37FAF79F9DF0D33568D320669800EB4836472EA8A026D16B7182460C52",
             "D15944B0A44508D1E61213F6455F292A02298F870C01A3F74AD0345A4A6651EBE101976E933F32D44F0B5947"),
        ] {
            let c = ctx(etype, k1, k2);
            assert_eq!(c.pseudo_random(PrfKey::Partial, b"", 44).expect("prf"), hex(o1));
            assert_eq!(c.pseudo_random(PrfKey::Full, input, 44).expect("prf"), hex(o2));
            assert!(c.pseudo_random(PrfKey::Full, input, 0).expect("prf").is_empty());
        }
    }

    #[test]
    fn inquire_and_by_oid() {
        let mut c = ctx(18, &"11".repeat(32), &"22".repeat(32));
        c.authdata = vec![
            AuthorizationDataElement {
                ad_type: 1,
                ad_data: b"x".to_vec().into(),
            },
            AuthorizationDataElement {
                ad_type: 128,
                ad_data: b"pac".to_vec().into(),
            },
        ];
        let info = c.inquire();
        assert!(info.locally_initiated && info.open && info.mech == MECH_KRB5);
        assert!(info.lifetime > Duration::from_secs(3500));
        let key = c
            .inquire_sec_context_by_oid(INQ_SSPI_SESSION_KEY_OID)
            .expect("key");
        assert_eq!(key[0], vec![0x22; 32]);
        assert_eq!(key[1], oid_compose(SESSION_KEY_ENCTYPE_OID, 18));
        assert_eq!(*key[1].last().expect("arc"), 18);
        let odbc = c
            .inquire_sec_context_by_oid(INQ_ODBC_SESSION_KEY_OID)
            .expect("key");
        assert_eq!(odbc[0], vec![0x11; 32]);
        let ad = c
            .inquire_sec_context_by_oid(&oid_compose(EXTRACT_AUTHZ_DATA_OID, 128))
            .expect("ad");
        assert_eq!(ad, vec![b"pac".to_vec()]);
        assert!(c
            .inquire_sec_context_by_oid(EXTRACT_AUTHZ_DATA_OID)
            .is_err());
        assert_eq!(
            c.inquire_sec_context_by_oid(SASL_SSF_OID).expect("ssf"),
            vec![256u32.to_be_bytes().to_vec()]
        );
        assert!(matches!(
            c.inquire_sec_context_by_oid(EXPORT_LUCID_SEC_CONTEXT_OID),
            Err(Krb5Error::Gss(GssError::Unavailable))
        ));
        assert_eq!(oid_compose(b"", 300), vec![0x82, 0x2c]);
        assert_eq!(oid_decompose(b"", &[0x82, 0x2c]), Some(300));
    }
}
