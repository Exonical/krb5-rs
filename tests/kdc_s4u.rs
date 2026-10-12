#![cfg(feature = "kdc")]
//! S4U2Self / S4U2Proxy (MS-SFU) against the KDC. Happy paths use our
//! `TgsExchange::s4u2self` / `s4u2proxy`; error cases use hand-built
//! requests. MIT references: kdc_util.c:1233-1645, tgs_policy.c:296-572,
//! do_tgs_req.c, kdc_authdata.c.

use chrono::{DateTime, Timelike, Utc};
use hmac::{Hmac, KeyInit, Mac};
use krb5_rs::crypto::{find_etype, key_usage};
use krb5_rs::kdc::{
    ConsistencyGate, GateDecision, GateSubject, Kdc, KdcConfig, MemoryStore, PrincipalAttributes,
};
use krb5_rs::pac::{ticket_pac, verify_ticket_pac, DelegationInfo, PAC_DELEGATION_INFO};
use krb5_rs::protocol::ap::{decrypt_ticket, encrypt_ticket_part};
use krb5_rs::protocol::{
    AsExchange, AsExchangeConfig, Credential, StepResult, TgsExchange, TgsOptions, TgsStepResult,
};
use krb5_rs::types::*;
use krb5_rs::Krb5Error;
use md5::{Digest, Md5};
use rasn::types::{BitString, GeneralString, OctetString};
use std::sync::{Arc, Mutex};

const REALM: &str = "S4U.REALM";
const PW: &str = "s4u-password";
const NONCE: u32 = 0x1111_2222;
const RBCD: u32 = 0x1000_0000;
const REPLY_USAGE_BIT: u32 = 0x2000_0000;

fn gs(s: &str) -> GeneralString {
    GeneralString::from_bytes(s.as_bytes()).expect("string")
}

fn tgs_name() -> PrincipalName {
    PrincipalName::new_srv_inst("krbtgt", REALM)
}

fn alice() -> PrincipalName {
    PrincipalName::new_principal("alice")
}

fn front() -> PrincipalName {
    PrincipalName::new_srv_hst("HTTP", "front.s4u.realm")
}

fn back() -> PrincipalName {
    PrincipalName::new_srv_hst("HTTP", "back.s4u.realm")
}

fn other() -> PrincipalName {
    PrincipalName::new_srv_hst("HTTP", "other.s4u.realm")
}

#[derive(Clone)]
struct Cfg {
    front_attrs: PrincipalAttributes,
    front_to: Vec<&'static str>,
    back_from: Vec<&'static str>,
    alice_pw_expired: bool,
}

impl Default for Cfg {
    fn default() -> Self {
        Self {
            front_attrs: PrincipalAttributes::empty(),
            front_to: Vec::new(),
            back_from: Vec::new(),
            alice_pw_expired: false,
        }
    }
}

struct Fix {
    kdc: Kdc<MemoryStore>,
    tgs_key: EncryptionKey,
    front_key: EncryptionKey,
    back_key: EncryptionKey,
    other_key: EncryptionKey,
}

async fn fixture(cfg: Cfg) -> Fix {
    fixture_with_gate(cfg, AllowGate).await
}

struct AllowGate;

impl ConsistencyGate for AllowGate {
    async fn check(&self, _subjects: &[GateSubject<'_>]) -> GateDecision {
        GateDecision::Allow
    }
}

struct RecordingGate(Arc<Mutex<Vec<PrincipalName>>>);

impl ConsistencyGate for RecordingGate {
    async fn check(&self, subjects: &[GateSubject<'_>]) -> GateDecision {
        self.0
            .lock()
            .expect("gate record lock")
            .extend(subjects.iter().map(|subject| subject.entry.name.clone()));
        GateDecision::Allow
    }
}

async fn fixture_with_gate(cfg: Cfg, gate: impl ConsistencyGate + 'static) -> Fix {
    let mut store = MemoryStore::new();
    let none = PrincipalAttributes::empty();
    store
        .add_random_key(tgs_name(), REALM, 1, &[18, 17], none)
        .expect("krbtgt");
    store
        .add_with_password(alice(), REALM, PW, 1, &[18, 17], none)
        .expect("alice");
    for (name, attrs) in [(front(), cfg.front_attrs), (back(), none), (other(), none)] {
        store
            .add_with_password(name, REALM, PW, 1, &[18, 17], attrs)
            .expect("service");
    }
    let edit = |store: &mut MemoryStore, name: &PrincipalName, f: &dyn Fn(&mut PrincipalEntry)| {
        let mut e = store.get(name, REALM).expect("entry");
        f(&mut e);
        store.insert(e);
    };
    edit(&mut store, &front(), &|e| {
        e.allowed_to_delegate_to = cfg.front_to.iter().map(|s| s.to_string()).collect();
    });
    edit(&mut store, &back(), &|e| {
        e.allowed_to_delegate_from = cfg.back_from.iter().map(|s| s.to_string()).collect();
    });
    if cfg.alice_pw_expired {
        edit(&mut store, &alice(), &|e| {
            e.pw_expiration = Some((Utc::now() - chrono::Duration::days(1)).fixed_offset());
        });
    }
    let key = |store: &MemoryStore, n: &PrincipalName| {
        store.get(n, REALM).expect("entry").keys[0].key.clone()
    };
    let (tgs_key, front_key, back_key, other_key) = (
        key(&store, &tgs_name()),
        key(&store, &front()),
        key(&store, &back()),
        key(&store, &other()),
    );
    let mut config = KdcConfig::new(REALM);
    config.max_renewable_life = std::time::Duration::from_secs(7 * 86400);
    Fix {
        kdc: Kdc::builder(config, store).consistency(gate).build(),
        tgs_key,
        front_key,
        back_key,
        other_key,
    }
}

use krb5_rs::kdc::PrincipalEntry;

impl Fix {
    async fn login(&self, name: &PrincipalName, request_pac: bool) -> Credential {
        let mut config = AsExchangeConfig::new(name.clone(), REALM);
        config.request_pac = request_pac;
        let mut ex = AsExchange::new(config, PW);
        let mut reply = Vec::new();
        while let StepResult::SendToKdc { data, .. } | StepResult::RetryTcp { data, .. } =
            ex.step(&reply).expect("AS step")
        {
            reply = self.kdc.handle(&data).await;
        }
        ex.credential().expect("TGT").clone()
    }

    async fn run(&self, mut ex: TgsExchange) -> Result<Credential, Krb5Error> {
        let mut reply = Vec::new();
        loop {
            match ex.step(&reply)? {
                TgsStepResult::SendToKdc { data, .. } | TgsStepResult::RetryTcp { data, .. } => {
                    reply = self.kdc.handle(&data).await;
                }
                TgsStepResult::Complete => return Ok(ex.credential().expect("cred").clone()),
            }
        }
    }

    async fn s4u2self(
        &self,
        tgt: &Credential,
        user: &PrincipalName,
    ) -> Result<Credential, Krb5Error> {
        self.run(TgsExchange::s4u2self(
            tgt.clone(),
            user.clone(),
            REALM,
            TgsOptions::default(),
        ))
        .await
    }

    async fn s4u2proxy(
        &self,
        tgt: &Credential,
        evidence: &Credential,
        target: &PrincipalName,
    ) -> Result<Credential, Krb5Error> {
        self.run(TgsExchange::s4u2proxy(
            tgt.clone(),
            evidence.clone(),
            target.clone(),
            TgsOptions::default(),
        ))
        .await
    }

    async fn raw(&self, req: Raw<'_>) -> Reply {
        let (bytes, subkey) = req.build();
        let reply = self.kdc.handle(&bytes).await;
        if let Ok(rep) = rasn::der::decode::<TgsRep>(&reply) {
            let plain = find_etype(subkey.keytype)
                .expect("etype")
                .decrypt(
                    subkey.key_bytes(),
                    key_usage::TGS_REP_ENCPART_SUBKEY,
                    rep.0.enc_part.cipher.as_ref(),
                )
                .expect("decrypt enc-part");
            let enc: EncTgsRepPart = rasn::der::decode(&plain).expect("enc part");
            Reply::Ok(Box::new((rep.0, enc.0)), subkey)
        } else {
            Reply::Err(rasn::der::decode(&reply).expect("KRB-ERROR"))
        }
    }
}

enum Reply {
    Ok(Box<(KdcRep, EncKdcRepPart)>, EncryptionKey),
    Err(KrbErrorMsg),
}

impl Reply {
    fn code(&self) -> i32 {
        match self {
            Reply::Err(e) => e.error_code,
            Reply::Ok(..) => 0,
        }
    }

    fn text(&self) -> String {
        match self {
            Reply::Err(e) => e
                .e_text
                .as_ref()
                .map(|t| String::from_utf8_lossy(t.as_bytes()).to_string())
                .unwrap_or_default(),
            Reply::Ok(..) => String::new(),
        }
    }

    fn assert_err(&self, code: i32, text: &str) {
        assert_eq!((self.code(), self.text().as_str()), (code, text));
    }
}

fn subkey() -> EncryptionKey {
    EncryptionKey::new(
        18,
        find_etype(18)
            .expect("etype")
            .random_to_key(&[9u8; 32])
            .expect("key")
            .to_vec(),
    )
}

struct Raw<'a> {
    tgt: &'a Credential,
    sname: PrincipalName,
    opts: KdcOptions,
    padata: Vec<PaData>,
    addl: Option<Vec<Ticket>>,
}

impl<'a> Raw<'a> {
    fn new(tgt: &'a Credential, sname: PrincipalName, opts: KdcOptions) -> Self {
        Self {
            tgt,
            sname,
            opts,
            padata: Vec::new(),
            addl: None,
        }
    }

    fn pa(mut self, p: PaData) -> Self {
        self.padata.push(p);
        self
    }

    fn evidence(mut self, ticket: &Ticket) -> Self {
        self.addl = Some(vec![ticket.clone()]);
        self
    }

    fn build(self) -> (Vec<u8>, EncryptionKey) {
        let session = &self.tgt.session_key;
        let profile = find_etype(session.keytype).expect("etype");
        let till = (Utc::now() + chrono::Duration::hours(1))
            .with_nanosecond(0)
            .expect("valid")
            .fixed_offset();
        let body = KdcReqBody {
            kdc_options: KerberosFlags::new(self.opts),
            cname: None,
            realm: gs(REALM),
            sname: Some(self.sname),
            from: None,
            till,
            rtime: None,
            nonce: NONCE,
            etype: vec![18, 17],
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: self.addl,
        };
        let body_der = rasn::der::encode(&body).expect("body");
        let cksum = Checksum {
            cksumtype: profile.checksum_type(),
            checksum: OctetString::from(
                profile
                    .checksum(
                        session.key_bytes(),
                        key_usage::TGS_REQ_AUTH_CKSUM,
                        &body_der,
                    )
                    .expect("checksum"),
            ),
        };
        let sub = subkey();
        let now: DateTime<Utc> = Utc::now();
        let auth = Authenticator {
            authenticator_vno: 5,
            crealm: gs(&self.tgt.crealm),
            cname: self.tgt.client.clone(),
            cksum: Some(cksum),
            cusec: 0,
            ctime: now.with_nanosecond(0).expect("valid").fixed_offset(),
            subkey: Some(sub.clone()),
            seq_number: None,
            authorization_data: None,
        };
        let cipher = profile
            .encrypt(
                session.key_bytes(),
                key_usage::TGS_REQ_AUTH,
                &rasn::der::encode(&auth).expect("auth"),
            )
            .expect("encrypt");
        let ap = ApReq {
            pvno: 5,
            msg_type: 14,
            ap_options: KerberosFlags::new(ApOptions::empty()),
            ticket: self.tgt.ticket.clone(),
            authenticator: EncryptedData {
                etype: session.keytype,
                kvno: None,
                cipher: OctetString::from(cipher),
            },
        };
        let mut padata = vec![PaData {
            padata_type: 1,
            padata_value: OctetString::from(rasn::der::encode(&ap).expect("ap")),
        }];
        padata.extend(self.padata);
        let req = TgsReq(KdcReq {
            pvno: 5,
            msg_type: 12,
            padata: Some(padata),
            req_body: body,
        });
        (rasn::der::encode(&req).expect("req"), sub)
    }
}

fn hmac_md5(key: &[u8], usage: u32, data: &[u8]) -> Vec<u8> {
    let mut ks = <Hmac<Md5> as KeyInit>::new_from_slice(key).expect("key");
    ks.update(b"signaturekey\0");
    let ks = ks.finalize().into_bytes();
    let mut md5 = Md5::new();
    md5.update(usage.to_le_bytes());
    md5.update(data);
    let mut mac = <Hmac<Md5> as KeyInit>::new_from_slice(&ks).expect("ks");
    mac.update(&md5.finalize());
    mac.finalize().into_bytes().to_vec()
}

fn for_user_pa(tgt: &Credential, user: &PrincipalName, realm: &str, flip: bool) -> PaData {
    let mut data = user.name_type.to_le_bytes().to_vec();
    for c in &user.name_string {
        data.extend_from_slice(c.as_bytes());
    }
    data.extend_from_slice(realm.as_bytes());
    data.extend_from_slice(b"Kerberos");
    let mut sum = hmac_md5(tgt.session_key.key_bytes(), 17, &data);
    if flip {
        sum[0] ^= 1;
    }
    let pa = PaForUser {
        user_name: user.clone(),
        user_realm: gs(realm),
        cksum: Checksum {
            cksumtype: -138,
            checksum: sum.into(),
        },
        auth_package: gs("Kerberos"),
    };
    PaData {
        padata_type: 129,
        padata_value: rasn::der::encode(&pa).expect("for-user").into(),
    }
}

struct X509 {
    user: Option<PrincipalName>,
    realm: &'static str,
    nonce: u32,
    options: u32,
    flip: bool,
}

impl X509 {
    fn new(user: &PrincipalName) -> Self {
        Self {
            user: Some(user.clone()),
            realm: REALM,
            nonce: NONCE,
            options: REPLY_USAGE_BIT,
            flip: false,
        }
    }

    fn pa(&self) -> PaData {
        let user_id = S4uUserId {
            nonce: self.nonce,
            cname: self.user.clone(),
            crealm: gs(self.realm),
            subject_certificate: None,
            options: Some(BitString::from_slice(&self.options.to_be_bytes())),
        };
        let profile = find_etype(18).expect("etype");
        let mut sum = profile
            .checksum(
                subkey().key_bytes(),
                26,
                &rasn::der::encode(&user_id).expect("user id"),
            )
            .expect("checksum");
        if self.flip {
            sum[0] ^= 1;
        }
        let pa = PaS4uX509User {
            user_id,
            cksum: Checksum {
                cksumtype: profile.checksum_type(),
                checksum: sum.into(),
            },
        };
        PaData {
            padata_type: 130,
            padata_value: rasn::der::encode(&pa).expect("x509").into(),
        }
    }
}

fn forwardable(c: &Credential) -> bool {
    c.flags.contains(TicketFlags::FORWARDABLE)
}

fn kdc_err(r: Result<Credential, Krb5Error>) -> (i32, String) {
    match r {
        Err(Krb5Error::KdcError(m)) => (
            m.error_code,
            m.e_text
                .map(|t| String::from_utf8_lossy(t.as_bytes()).to_string())
                .unwrap_or_default(),
        ),
        other => panic!("expected a KDC error, got {other:?}"),
    }
}

const SELF_OK: PrincipalAttributes = PrincipalAttributes::OK_TO_AUTH_AS_DELEGATE;

async fn evidence(f: &Fix) -> (Credential, Credential) {
    let tgt = f.login(&front(), true).await;
    let ev = f.s4u2self(&tgt, &alice()).await.expect("S4U2Self");
    (tgt, ev)
}

// ---------------------------------------------------------------- S4U2Self

#[tokio::test]
async fn s4u2self_issues_a_ticket_for_the_user_to_the_service_with_the_users_pac() {
    let f = fixture(Cfg::default()).await;
    let tgt = f.login(&front(), true).await;
    let cred = f.s4u2self(&tgt, &alice()).await.expect("S4U2Self");
    assert_eq!(cred.client, alice());
    assert_eq!(cred.server, front());
    let part = decrypt_ticket(&f.front_key, &cred.ticket).expect("decrypt");
    assert_eq!(part.cname, alice());
    let pac = ticket_pac(&part).expect("pac").expect("present");
    assert_eq!(pac.client_info().expect("client info").name, "alice");
    verify_ticket_pac(&part, &front(), &f.front_key, Some(&f.tgs_key))
        .expect("signatures")
        .expect("PAC");
    // do_tgs_req.c:739: the subject ticket is the header, so authtime is the
    // service TGT's.
    let tgt_part = decrypt_ticket(&f.tgs_key, &tgt.ticket).expect("tgt");
    assert_eq!(part.authtime, tgt_part.authtime);
}

#[tokio::test]
async fn s4u2self_forwardable_follows_ok_to_auth_as_delegate_and_delegation_targets() {
    // s4u2self_forwardable (kdc_util.c:1626-1644).
    let cases = [
        (Cfg::default(), true),
        (
            Cfg {
                front_to: vec!["HTTP/back.s4u.realm"],
                ..Cfg::default()
            },
            false,
        ),
        (
            Cfg {
                front_attrs: SELF_OK,
                front_to: vec!["HTTP/back.s4u.realm"],
                ..Cfg::default()
            },
            true,
        ),
    ];
    for (cfg, want) in cases {
        let f = fixture(cfg).await;
        let tgt = f.login(&front(), true).await;
        let cred = f.s4u2self(&tgt, &alice()).await.expect("S4U2Self");
        assert_eq!(forwardable(&cred), want);
    }
}

#[tokio::test]
async fn s4u2self_ignores_password_expiration_of_the_user() {
    let f = fixture(Cfg {
        alice_pw_expired: true,
        ..Cfg::default()
    })
    .await;
    let tgt = f.login(&front(), true).await;
    f.s4u2self(&tgt, &alice()).await.expect("S4U2Self");
}

#[tokio::test]
async fn s4u2self_keeps_a_pac_for_services_with_no_auth_data_required() {
    let f = fixture(Cfg {
        front_attrs: PrincipalAttributes::NO_AUTH_DATA_REQUIRED,
        ..Cfg::default()
    })
    .await;
    let tgt = f.login(&front(), true).await;
    let cred = f.s4u2self(&tgt, &alice()).await.expect("S4U2Self");
    let part = decrypt_ticket(&f.front_key, &cred.ticket).expect("decrypt");
    assert!(ticket_pac(&part).expect("pac").is_some());
}

#[tokio::test]
async fn s4u2self_unknown_user_is_c_principal_unknown() {
    let f = fixture(Cfg::default()).await;
    let tgt = f.login(&front(), true).await;
    let err = kdc_err(
        f.s4u2self(&tgt, &PrincipalName::new_principal("nobody"))
            .await,
    );
    assert_eq!(err, (6, "UNKNOWN_S4U2SELF_PRINCIPAL".to_string()));
}

#[tokio::test]
async fn s4u2self_for_a_user_of_another_realm_is_refused_with_policy() {
    let f = fixture(Cfg::default()).await;
    let tgt = f.login(&front(), true).await;
    let r = f
        .run(TgsExchange::s4u2self(
            tgt,
            alice(),
            "OTHER.REALM",
            TgsOptions::default(),
        ))
        .await;
    assert_eq!(kdc_err(r).0, 12);
}

#[tokio::test]
async fn s4u2self_checksum_failures_use_mit_codes() {
    let f = fixture(Cfg::default()).await;
    let tgt = f.login(&front(), true).await;
    let base = || Raw::new(&tgt, front(), KdcOptions::CANONICALIZE);

    // PA-FOR-USER: bad hmac-md5 checksum -> AP_ERR_MODIFIED.
    f.raw(base().pa(for_user_pa(&tgt, &alice(), REALM, true)))
        .await
        .assert_err(41, "INVALID_S4U2SELF_CHECKSUM");
    // PA-S4U-X509-USER: bad checksum, wrong nonce.
    let mut x = X509::new(&alice());
    x.flip = true;
    f.raw(base().pa(x.pa()))
        .await
        .assert_err(41, "INVALID_S4U2SELF_CHECKSUM");
    let mut x = X509::new(&alice());
    x.nonce ^= 1;
    f.raw(base().pa(x.pa()))
        .await
        .assert_err(41, "INVALID_S4U2SELF_CHECKSUM");
    // Empty user and no certificate -> C_PRINCIPAL_UNKNOWN.
    let mut x = X509::new(&alice());
    x.user = None;
    f.raw(base().pa(x.pa()))
        .await
        .assert_err(6, "INVALID_S4U2SELF_REQUEST");
}

#[tokio::test]
async fn s4u2self_reply_carries_a_checksummed_pa_s4u_x509_user() {
    // kdc_make_s4u2self_rep (kdc_util.c:1431-1500): usage 27 when the
    // request set USE_REPLY_KEY_USAGE.
    let f = fixture(Cfg::default()).await;
    let tgt = f.login(&front(), true).await;
    let reply = f
        .raw(
            Raw::new(&tgt, front(), KdcOptions::CANONICALIZE)
                .pa(X509::new(&alice()).pa())
                .pa(for_user_pa(&tgt, &alice(), REALM, false)),
        )
        .await;
    let Reply::Ok(rep, sub) = &reply else {
        panic!("expected a ticket, got {} {}", reply.code(), reply.text());
    };
    let pa = rep
        .0
        .padata
        .as_ref()
        .and_then(|l| l.iter().find(|p| p.padata_type == 130))
        .expect("PA-S4U-X509-USER in the reply");
    let x: PaS4uX509User = rasn::der::decode(pa.padata_value.as_ref()).expect("decode");
    assert_eq!(x.user_id.nonce, NONCE);
    let der = rasn::der::encode(&x.user_id).expect("encode");
    let want = find_etype(18)
        .expect("etype")
        .checksum(sub.key_bytes(), 27, &der)
        .expect("cksum");
    assert_eq!(x.cksum.checksum.as_ref(), want.as_slice());
    assert_eq!(x.user_id.cname, Some(alice()));
}

#[tokio::test]
async fn s4u2self_with_only_pa_for_user_gets_no_reply_padata() {
    let f = fixture(Cfg::default()).await;
    let tgt = f.login(&front(), true).await;
    let reply = f
        .raw(
            Raw::new(&tgt, front(), KdcOptions::CANONICALIZE).pa(for_user_pa(
                &tgt,
                &alice(),
                REALM,
                false,
            )),
        )
        .await;
    let Reply::Ok(rep, _) = &reply else {
        panic!("expected a ticket, got {} {}", reply.code(), reply.text());
    };
    assert!(rep.0.padata.is_none());
    assert_eq!(rep.0.cname, alice());
}

#[tokio::test]
async fn s4u2self_policy_checks_use_mit_codes() {
    let f = fixture(Cfg::default()).await;
    let tgt = f.login(&front(), true).await;
    let pa = || X509::new(&alice()).pa();
    // Request for a service other than the requester.
    f.raw(Raw::new(&tgt, back(), KdcOptions::CANONICALIZE).pa(pa()))
        .await
        .assert_err(36, "INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH");
    // Options invalid for AS-style requests (U2U is not offered here).
    assert_eq!(
        f.raw(Raw::new(&tgt, front(), KdcOptions::ENC_TKT_IN_SKEY).pa(pa()))
            .await
            .code(),
        13
    );
    // The header ticket must carry a PAC.
    let no_pac = f.login(&front(), false).await;
    f.raw(Raw::new(&no_pac, front(), KdcOptions::CANONICALIZE).pa(pa()))
        .await
        .assert_err(20, "S4U2SELF_NO_PAC");
}

// ---------------------------------------------------------------- S4U2Proxy

fn proxy_cfg() -> Cfg {
    Cfg {
        front_attrs: SELF_OK,
        front_to: vec!["HTTP/back.s4u.realm"],
        ..Cfg::default()
    }
}

#[tokio::test]
async fn s4u2proxy_traditional_delegation_issues_ticket_for_the_user_with_delegation_info() {
    let f = fixture(proxy_cfg()).await;
    let (tgt, ev) = evidence(&f).await;
    let cred = f.s4u2proxy(&tgt, &ev, &back()).await.expect("S4U2Proxy");
    assert_eq!(cred.client, alice());
    assert_eq!(cred.server, back());
    let part = decrypt_ticket(&f.back_key, &cred.ticket).expect("decrypt");
    assert_eq!(part.cname, alice());
    let pac = ticket_pac(&part).expect("pac").expect("present");
    assert_eq!(pac.client_info().expect("client info").name, "alice");
    verify_ticket_pac(&part, &back(), &f.back_key, Some(&f.tgs_key))
        .expect("signatures")
        .expect("PAC");
    let di = DelegationInfo::decode(
        pac.get_buffer(PAC_DELEGATION_INFO)
            .expect("delegation info"),
    )
    .expect("decode");
    assert_eq!(di.proxy_target, "HTTP/back.s4u.realm");
    assert_eq!(
        di.transited_services,
        vec!["HTTP/front.s4u.realm@S4U.REALM"]
    );
    // The ticket keeps the evidence ticket's authtime (do_tgs_req.c:750).
    let ev_part = decrypt_ticket(&f.front_key, &ev.ticket).expect("evidence");
    assert_eq!(part.authtime, ev_part.authtime);
}

#[tokio::test]
async fn s4u2proxy_consistency_gate_includes_the_impersonated_client() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let f = fixture_with_gate(proxy_cfg(), RecordingGate(Arc::clone(&seen))).await;
    let (tgt, ev) = evidence(&f).await;
    seen.lock().expect("gate record lock").clear();

    f.s4u2proxy(&tgt, &ev, &back()).await.expect("S4U2Proxy");

    assert!(
        seen.lock().expect("gate record lock").contains(&alice()),
        "gate saw {seen:?}"
    );
}

#[tokio::test]
async fn s4u2proxy_denied_without_a_delegation_entry() {
    let f = fixture(Cfg {
        front_attrs: SELF_OK,
        ..Cfg::default()
    })
    .await;
    let (tgt, ev) = evidence(&f).await;
    let err = kdc_err(f.s4u2proxy(&tgt, &ev, &back()).await);
    assert_eq!(err, (13, "NOT_ALLOWED_TO_DELEGATE".to_string()));
    // A target outside the list is denied too.
    let f = fixture(proxy_cfg()).await;
    let (tgt, ev) = evidence(&f).await;
    let err = kdc_err(f.s4u2proxy(&tgt, &ev, &other()).await);
    assert_eq!(err, (13, "NOT_ALLOWED_TO_DELEGATE".to_string()));
}

#[tokio::test]
async fn s4u2proxy_rbcd_allowed_and_denied() {
    // Resource-based: the resource lists the impersonating service.
    let f = fixture(Cfg {
        front_attrs: SELF_OK,
        back_from: vec!["HTTP/front.s4u.realm@S4U.REALM"],
        ..Cfg::default()
    })
    .await;
    let (tgt, ev) = evidence(&f).await;
    let cred = f.s4u2proxy(&tgt, &ev, &back()).await.expect("RBCD");
    assert_eq!(cred.client, alice());

    let f = fixture(Cfg {
        front_attrs: SELF_OK,
        back_from: vec!["HTTP/other.s4u.realm@S4U.REALM"],
        ..Cfg::default()
    })
    .await;
    let (tgt, ev) = evidence(&f).await;
    let err = kdc_err(f.s4u2proxy(&tgt, &ev, &back()).await);
    assert_eq!(err, (13, "NOT_ALLOWED_TO_DELEGATE".to_string()));
}

#[tokio::test]
async fn s4u2proxy_requires_a_forwardable_evidence_ticket() {
    // Delegation targets without ok-to-auth-as-delegate make the S4U2Self
    // ticket non-forwardable (s4u2self_forwardable).
    let f = fixture(Cfg {
        front_to: vec!["HTTP/back.s4u.realm"],
        ..Cfg::default()
    })
    .await;
    let (tgt, ev) = evidence(&f).await;
    assert!(!forwardable(&ev));
    let err = kdc_err(f.s4u2proxy(&tgt, &ev, &back()).await);
    assert_eq!(err, (13, "EVIDENCE_TKT_NOT_FORWARDABLE".to_string()));
}

#[tokio::test]
async fn s4u2proxy_request_shape_checks_use_mit_codes() {
    let f = fixture(proxy_cfg()).await;
    let (tgt, ev) = evidence(&f).await;
    let rbcd = || PaData {
        padata_type: 167,
        padata_value: rasn::der::encode(&PaPacOptions {
            flags: BitString::from_slice(&RBCD.to_be_bytes()),
        })
        .expect("opts")
        .into(),
    };
    let opts = KdcOptions::CNAME_IN_ADDL_TKT | KdcOptions::CANONICALIZE;
    // No second ticket.
    f.raw(Raw::new(&tgt, back(), opts).pa(rbcd()))
        .await
        .assert_err(13, "NO_2ND_TKT");
    // Options that need a non-TGT header ticket.
    f.raw(Raw::new(&tgt, tgs_name(), opts | KdcOptions::RENEW).evidence(&ev.ticket))
        .await
        .assert_err(13, "INVALID_S4U2PROXY_OPTIONS");
    // A TGT cannot be the target (that would be unconstrained delegation).
    f.raw(Raw::new(&tgt, tgs_name(), opts).evidence(&ev.ticket))
        .await
        .assert_err(12, "NOT_ALLOWED_TO_DELEGATE");
    // The same request done right succeeds, and echoes only the RBCD bit.
    let reply = f
        .raw(Raw::new(&tgt, back(), opts).pa(rbcd()).evidence(&ev.ticket))
        .await;
    let Reply::Ok(rep, _) = &reply else {
        panic!("expected a ticket, got {} {}", reply.code(), reply.text());
    };
    let pa = rep
        .1
        .encrypted_pa_data
        .as_ref()
        .and_then(|l| l.iter().find(|p| p.padata_type == 167))
        .expect("PA-PAC-OPTIONS in enc-padata");
    let o: PaPacOptions = rasn::der::decode(pa.padata_value.as_ref()).expect("decode");
    assert_eq!(o.flags.as_raw_slice(), &RBCD.to_be_bytes());
}

#[tokio::test]
async fn s4u2proxy_pac_option_echo_drops_other_bits() {
    let f = fixture(proxy_cfg()).await;
    let (tgt, ev) = evidence(&f).await;
    let both = PaData {
        padata_type: 167,
        padata_value: rasn::der::encode(&PaPacOptions {
            flags: BitString::from_slice(&(RBCD | 0x4000_0000).to_be_bytes()),
        })
        .expect("opts")
        .into(),
    };
    let opts = KdcOptions::CNAME_IN_ADDL_TKT | KdcOptions::CANONICALIZE;
    let reply = f
        .raw(Raw::new(&tgt, back(), opts).pa(both).evidence(&ev.ticket))
        .await;
    let Reply::Ok(rep, _) = &reply else {
        panic!("expected a ticket, got {} {}", reply.code(), reply.text());
    };
    let pa = rep
        .1
        .encrypted_pa_data
        .as_ref()
        .and_then(|l| l.iter().find(|p| p.padata_type == 167))
        .expect("PA-PAC-OPTIONS");
    let o: PaPacOptions = rasn::der::decode(pa.padata_value.as_ref()).expect("decode");
    assert_eq!(o.flags.as_raw_slice(), &RBCD.to_be_bytes());
}

#[tokio::test]
async fn s4u2proxy_evidence_for_a_different_service_is_server_nomatch() {
    let f = fixture(proxy_cfg()).await;
    let front_tgt = f.login(&front(), true).await;
    let other_tgt = f.login(&other(), true).await;
    let ev_for_other = f.s4u2self(&other_tgt, &alice()).await.expect("evidence");
    let err = kdc_err(f.s4u2proxy(&front_tgt, &ev_for_other, &back()).await);
    assert_eq!(err, (26, "EVIDENCE_TICKET_MISMATCH".to_string()));
}

#[tokio::test]
async fn s4u2proxy_evidence_pac_problems_use_mit_codes() {
    let f = fixture(proxy_cfg()).await;
    let (tgt, ev) = evidence(&f).await;
    let part = decrypt_ticket(&f.front_key, &ev.ticket).expect("evidence");
    let reissue = |part: &EncTicketPart| {
        let mut c = ev.clone();
        c.ticket = encrypt_ticket_part(&f.front_key, Some(1), REALM, ev.ticket.sname.clone(), part)
            .expect("reissue");
        c
    };

    // No PAC in the evidence ticket -> AP_ERR_MODIFIED.
    let mut stripped = part.clone();
    stripped.authorization_data = None;
    let err = kdc_err(f.s4u2proxy(&tgt, &reissue(&stripped), &back()).await);
    assert_eq!(err, (41, "S4U2PROXY_NO_STKT_PAC".to_string()));

    // Changing the ticket after it was signed breaks the ticket checksum.
    let mut changed = part.clone();
    changed.endtime += chrono::Duration::seconds(1);
    let err = kdc_err(f.s4u2proxy(&tgt, &reissue(&changed), &back()).await);
    assert_eq!(err, (41, "2ND_TKT_PAC".to_string()));

    // The evidence server key must decrypt the ticket.
    let mut bad = ev.clone();
    bad.ticket = encrypt_ticket_part(&f.other_key, Some(1), REALM, ev.ticket.sname.clone(), &part)
        .expect("wrong key");
    let err = kdc_err(f.s4u2proxy(&tgt, &bad, &back()).await);
    assert_eq!(err, (31, "2ND_TKT_DECRYPT".to_string()));
}

#[tokio::test]
async fn s4u2proxy_requires_a_pac_in_the_header_ticket() {
    let f = fixture(proxy_cfg()).await;
    let (_, ev) = evidence(&f).await;
    let no_pac = f.login(&front(), false).await;
    let err = kdc_err(f.s4u2proxy(&no_pac, &ev, &back()).await);
    assert_eq!(err, (20, "S4U2PROXY_NO_HEADER_PAC".to_string()));
}

#[tokio::test]
async fn s4u2proxy_second_target_gets_its_own_delegation_info() {
    // A second hop through the same service appends to the delegation info
    // carried by the evidence PAC (update_delegation_info).
    let f = fixture(Cfg {
        front_attrs: SELF_OK,
        front_to: vec!["HTTP/back.s4u.realm", "HTTP/other.s4u.realm"],
        ..Cfg::default()
    })
    .await;
    let (tgt, ev) = evidence(&f).await;
    let first = f.s4u2proxy(&tgt, &ev, &back()).await.expect("first hop");
    assert_eq!(first.client, alice());
    let second = f
        .s4u2proxy(&tgt, &ev, &other())
        .await
        .expect("second target");
    let part = decrypt_ticket(&f.other_key, &second.ticket).expect("decrypt");
    let pac = ticket_pac(&part).expect("pac").expect("present");
    let di = DelegationInfo::decode(pac.get_buffer(PAC_DELEGATION_INFO).expect("buffer"))
        .expect("decode");
    assert_eq!(di.proxy_target, "HTTP/other.s4u.realm");
}
