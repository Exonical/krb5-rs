//! MIT-semantics checks for the AP exchange and KRB-SAFE/PRIV/CRED.
//!
//! Grounded in MIT krb5 1.22.2 (krb5-ref): mk_req_ext.c, rd_req_dec.c,
//! mk_rep.c, rd_rep.c, mk_safe.c, rd_safe.c, privsafe.c, mk_priv.c,
//! rd_priv.c, mk_cred.c, rd_cred.c, gen_seqnum.c, valid_times.c,
//! os/timeofday.c, addr_srch.c, os/mk_faddr.c, rcache/rc_base.c.

use chrono::Timelike;
use krb5_rs::crypto::{find_cksumtype, find_etype};
use krb5_rs::protocol::ap::{
    decrypt_ticket, encrypt_ticket_part, ApError, ApReqOptions, AuthContext, AuthContextFlags,
    KeySource,
};
use krb5_rs::types::*;
use krb5_rs::Krb5Error;
use rasn::types::{GeneralString, OctetString};

const REALM: &str = "EXAMPLE.COM";

fn now() -> KerberosTime {
    let t = chrono::Utc::now();
    t.with_nanosecond(0).unwrap_or(t).fixed_offset()
}

fn secs(n: i64) -> KerberosTime {
    (chrono::Utc::now() + chrono::Duration::seconds(n))
        .with_nanosecond(0)
        .expect("valid time")
        .fixed_offset()
}

fn realm() -> Realm {
    GeneralString::from_bytes(REALM.as_bytes()).expect("realm")
}

fn alice() -> PrincipalName {
    PrincipalName::new_principal("alice")
}

fn service() -> PrincipalName {
    PrincipalName::new_srv_hst("HTTP", "www.example.com")
}

fn ipv4(a: u8, b: u8, c: u8, d: u8) -> HostAddress {
    HostAddress {
        addr_type: 2,
        address: OctetString::from(vec![a, b, c, d]),
    }
}

fn random_key(etype: i32) -> EncryptionKey {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let profile = find_etype(etype).expect("etype");
    let tag = COUNTER.fetch_add(1, Ordering::Relaxed) as u8;
    let mut rnd = vec![0u8; profile.key_bytes()];
    for (i, b) in rnd.iter_mut().enumerate() {
        *b = (i as u8)
            .wrapping_mul(37)
            .wrapping_add(etype as u8)
            .wrapping_add(tag);
    }
    EncryptionKey::new(
        etype,
        profile.random_to_key(&rnd).expect("random_to_key").to_vec(),
    )
}

/// Hand-encode an AP-REQ around `cred.ticket` (for cases mk_req rejects
/// locally, e.g. an expired ticket).
fn hand_req(cred: &krb5_rs::protocol::Credential, session: &EncryptionKey) -> Vec<u8> {
    let auth = Authenticator {
        authenticator_vno: 5,
        crealm: realm(),
        cname: alice(),
        cksum: None,
        cusec: 0,
        ctime: now(),
        subkey: None,
        seq_number: None,
        authorization_data: None,
    };
    let cipher = find_etype(session.keytype)
        .expect("etype")
        .encrypt(
            session.key_bytes(),
            11,
            &rasn::der::encode(&auth).expect("encode"),
        )
        .expect("encrypt");
    let ap_req = ApReq {
        pvno: 5,
        msg_type: 14,
        ap_options: KerberosFlags::new(ApOptions::empty()),
        ticket: cred.ticket.clone(),
        authenticator: EncryptedData {
            etype: session.keytype,
            kvno: None,
            cipher: OctetString::from(cipher),
        },
    };
    rasn::der::encode(&ap_req).expect("encode AP-REQ")
}

/// Mint a credential the way a KDC would issue it.
fn mint(
    service_key: &EncryptionKey,
    session_key: &EncryptionKey,
    start: Option<KerberosTime>,
    end: KerberosTime,
    flags: TicketFlags,
    caddr: Option<Vec<HostAddress>>,
) -> krb5_rs::protocol::Credential {
    let part = EncTicketPart {
        flags: KerberosFlags::new(flags),
        key: session_key.clone(),
        crealm: realm(),
        cname: alice(),
        transited: TransitedEncoding {
            tr_type: 1,
            contents: OctetString::from(Vec::new()),
        },
        authtime: now(),
        starttime: start,
        endtime: end,
        renew_till: None,
        caddr: caddr.clone(),
        authorization_data: None,
    };
    let ticket = encrypt_ticket_part(service_key, Some(1), REALM, service(), &part)
        .expect("encrypt_ticket_part");
    krb5_rs::protocol::Credential {
        client: alice(),
        crealm: REALM.to_string(),
        server: service(),
        srealm: REALM.to_string(),
        session_key: session_key.clone(),
        times: krb5_rs::protocol::TicketTimes {
            authtime: part.authtime,
            starttime: start,
            endtime: end,
            renew_till: None,
        },
        ticket,
        flags: KerberosFlags::new(flags),
        addresses: caddr,
        authdata: None,
    }
}

fn good_cred(
    service_key: &EncryptionKey,
    session_key: &EncryptionKey,
) -> krb5_rs::protocol::Credential {
    mint(
        service_key,
        session_key,
        None,
        secs(3600),
        TicketFlags::empty(),
        None,
    )
}

struct OneKey(EncryptionKey);
impl KeySource for OneKey {
    fn get_key(
        &self,
        _server: &PrincipalName,
        _realm: &[u8],
        _kvno: Option<i32>,
        _etype: i32,
    ) -> Result<EncryptionKey, ApError> {
        Ok(self.0.clone())
    }
}

struct WrongKey(EncryptionKey);
impl KeySource for WrongKey {
    fn get_key(
        &self,
        _server: &PrincipalName,
        _realm: &[u8],
        _kvno: Option<i32>,
        _etype: i32,
    ) -> Result<EncryptionKey, ApError> {
        Ok(self.0.clone())
    }
}

struct ErrKey(ApError);
impl KeySource for ErrKey {
    fn get_key(
        &self,
        _server: &PrincipalName,
        _realm: &[u8],
        _kvno: Option<i32>,
        _etype: i32,
    ) -> Result<EncryptionKey, ApError> {
        Err(self.0)
    }
}

fn ap_err(e: Krb5Error) -> ApError {
    match e {
        Krb5Error::Ap(a) => a,
        other => panic!("expected Krb5Error::Ap, got {other:?}"),
    }
}

fn opts() -> ApReqOptions {
    ApReqOptions::default()
}

include!("req_rep.rs");
include!("safe_priv.rs");
include!("cred.rs");
