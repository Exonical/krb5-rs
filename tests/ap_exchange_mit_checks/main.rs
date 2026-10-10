//! MIT-semantics checks for the AP exchange and KRB-SAFE/PRIV/CRED.
//!
//! Grounded in MIT krb5 1.22.2 (krb5-ref): mk_req_ext.c, rd_req_dec.c,
//! mk_rep.c, rd_rep.c, mk_safe.c, rd_safe.c, privsafe.c, mk_priv.c,
//! rd_priv.c, mk_cred.c, rd_cred.c, gen_seqnum.c, valid_times.c,
//! os/timeofday.c, addr_srch.c, os/mk_faddr.c, rcache/rc_base.c.

use krb5_rs::crypto::{find_cksumtype, find_etype};
use krb5_rs::protocol::ap::{
    decrypt_ticket, ApError, ApReqOptions, AuthContext, AuthContextFlags, KeySource,
};
use krb5_rs::types::*;
use krb5_rs::Krb5Error;
use rasn::types::OctetString;

#[path = "../common/mod.rs"]
mod common;
use common::fixtures::{alice, mint_full, now, random_key, realm, secs, service};

fn ipv4(a: u8, b: u8, c: u8, d: u8) -> HostAddress {
    HostAddress {
        addr_type: 2,
        address: OctetString::from(vec![a, b, c, d]),
    }
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
    mint_full(
        service_key,
        session_key,
        service(),
        start,
        end,
        flags,
        caddr,
    )
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
include!("rd_rep.rs");
include!("safe_priv.rs");
include!("cred.rs");
