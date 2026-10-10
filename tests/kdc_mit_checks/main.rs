#![cfg(feature = "kdc")]
//! In-process KDC checks (MIT krb5 1.22.2 reference: kdc/dispatch.c,
//! do_as_req.c, do_tgs_req.c, kdc_util.c, tgs_policy.c, kdc_preauth.c).
//! Our own AsExchange / TgsExchange / AuthContext drive `Kdc::handle`
//! directly; hand-built requests cover options the client cannot send.

use std::time::Duration;

use chrono::{DateTime, Timelike, Utc};
use krb5_rs::crypto::{find_etype, key_usage};
use krb5_rs::kdc::{Kdc, KdcConfig, MemoryStore, PrincipalAttributes, PrincipalStore};
use krb5_rs::protocol::ap::{decrypt_ticket, encrypt_ticket_part};
use krb5_rs::protocol::{
    AsExchange, AsExchangeConfig, Credential, StepResult, TgsExchange, TgsOptions, TgsStepResult,
    TicketTimes,
};
use krb5_rs::types::*;
use krb5_rs::Krb5Error;
use rasn::types::{GeneralString, OctetString};

mod as_req;
mod errors;
mod tgs_req;

const REALM: &str = "TEST.REALM";
const USER: &str = "testuser";
const PASSWORD: &str = "testpassword";
const SHA2_USER: &str = "sha2user";
const SHA2_PASSWORD: &str = "sha2password";
const SERVICE_PASSWORD: &str = "servicepassword";

fn gs(s: &str) -> GeneralString {
    GeneralString::from_bytes(s.as_bytes()).expect("general string")
}

fn user() -> PrincipalName {
    PrincipalName::new_principal(USER)
}

fn service() -> PrincipalName {
    PrincipalName::new_srv_hst("HTTP", "server.test.realm")
}

fn krbtgt() -> PrincipalName {
    PrincipalName::new_srv_inst("krbtgt", REALM)
}

/// A KerberosTime `secs` seconds from now (whole seconds).
fn at(secs: i64) -> KerberosTime {
    let t = Utc::now() + chrono::Duration::seconds(secs);
    t.with_nanosecond(0).expect("valid").fixed_offset()
}

/// Test realm plus the long-term keys tests need to decrypt tickets.
struct Fixture {
    kdc: Kdc<MemoryStore>,
    tgs_key: EncryptionKey,
    service_key: EncryptionKey,
}

#[derive(Default)]
struct FixtureOptions {
    krbtgt_etypes: Option<Vec<i32>>,
    max_life: Option<Duration>,
    max_renewable_life: Option<Duration>,
}

fn first_key(store: &MemoryStore, name: &PrincipalName, etype: i32) -> EncryptionKey {
    store
        .lookup(name, REALM)
        .expect("lookup")
        .expect("principal present")
        .keys
        .into_iter()
        .find(|k| k.key.keytype == etype)
        .expect("key of etype")
        .key
}

fn fixture_with(opts: FixtureOptions) -> Fixture {
    let mut store = MemoryStore::new();
    let tgt_etypes = opts.krbtgt_etypes.unwrap_or_else(|| vec![18, 17]);
    store
        .add_random_key(
            krbtgt(),
            REALM,
            1,
            &tgt_etypes,
            PrincipalAttributes::empty(),
        )
        .expect("krbtgt");
    store
        .add_with_password(
            user(),
            REALM,
            PASSWORD,
            1,
            &[18, 17],
            PrincipalAttributes::REQUIRES_PRE_AUTH,
        )
        .expect("testuser");
    store
        .add_with_password(
            PrincipalName::new_principal(SHA2_USER),
            REALM,
            SHA2_PASSWORD,
            1,
            &[20, 19],
            PrincipalAttributes::empty(),
        )
        .expect("sha2user");
    store
        .add_with_password(
            PrincipalName::new_principal("norenew"),
            REALM,
            PASSWORD,
            1,
            &[18, 17],
            PrincipalAttributes::DISALLOW_RENEWABLE,
        )
        .expect("norenew");
    store
        .add_with_password(
            PrincipalName::new_principal("nofwd"),
            REALM,
            PASSWORD,
            1,
            &[18, 17],
            PrincipalAttributes::DISALLOW_FORWARDABLE,
        )
        .expect("nofwd");
    store
        .add_with_password(
            service(),
            REALM,
            SERVICE_PASSWORD,
            1,
            &[18, 17],
            PrincipalAttributes::empty(),
        )
        .expect("service");
    let tgs_key = first_key(&store, &krbtgt(), 18);
    let service_key = first_key(&store, &service(), 18);

    let mut config = KdcConfig::new(REALM);
    config.max_renewable_life = opts
        .max_renewable_life
        .unwrap_or(Duration::from_secs(7 * 24 * 3600));
    if let Some(l) = opts.max_life {
        config.max_life = l;
    }
    Fixture {
        kdc: Kdc::new(config, store),
        tgs_key,
        service_key,
    }
}

fn fixture() -> Fixture {
    fixture_with(FixtureOptions::default())
}

/// Result of an in-process exchange plus every KDC reply seen.
struct Run<T> {
    result: Result<T, Krb5Error>,
    replies: Vec<Vec<u8>>,
}

fn run_as(kdc: &Kdc<MemoryStore>, config: AsExchangeConfig, password: &str) -> Run<Credential> {
    let mut exchange = AsExchange::new(config, password);
    let mut replies: Vec<Vec<u8>> = Vec::new();
    let mut input: Vec<u8> = Vec::new();
    let result = loop {
        match exchange.step(&input) {
            Ok(StepResult::SendToKdc { data, .. }) | Ok(StepResult::RetryTcp { data, .. }) => {
                input = kdc.handle(&data);
                replies.push(input.clone());
            }
            Ok(StepResult::Complete) => break exchange.credential().cloned(),
            Err(e) => break Err(e),
        }
    };
    Run { result, replies }
}

fn as_config(name: &str) -> AsExchangeConfig {
    AsExchangeConfig::new(PrincipalName::new_principal(name), REALM)
}

fn get_tgt(f: &Fixture) -> Credential {
    run_as(&f.kdc, as_config(USER), PASSWORD)
        .result
        .expect("AS exchange")
}

fn run_tgs(
    kdc: &Kdc<MemoryStore>,
    tgt: &Credential,
    target: PrincipalName,
    options: TgsOptions,
) -> Run<Credential> {
    let mut exchange = TgsExchange::new(tgt.clone(), target, options);
    let mut replies: Vec<Vec<u8>> = Vec::new();
    let mut input: Vec<u8> = Vec::new();
    let result = loop {
        match exchange.step(&input) {
            Ok(TgsStepResult::SendToKdc { data, .. })
            | Ok(TgsStepResult::RetryTcp { data, .. }) => {
                input = kdc.handle(&data);
                replies.push(input.clone());
            }
            Ok(TgsStepResult::Complete) => break exchange.credential().cloned(),
            Err(e) => break Err(e),
        }
    };
    Run { result, replies }
}

/// KDC error code carried by a client-side error.
fn kdc_code(e: &Krb5Error) -> i32 {
    match e {
        Krb5Error::KdcError(m) => m.error_code,
        other => panic!("expected KDC error, got {other:?}"),
    }
}

fn krb_error(reply: &[u8]) -> KrbErrorMsg {
    rasn::der::decode(reply).expect("reply decodes as KRB-ERROR")
}

fn method_data(e: &KrbErrorMsg) -> Vec<PaData> {
    rasn::der::decode(e.e_data.as_ref().expect("e-data").as_ref()).expect("METHOD-DATA")
}

/// Mint a TGT-shaped credential directly (as a KDC would issue it) so tests
/// control flags and times that the real clock-bound client flow cannot.
fn mint_tgt(
    f: &Fixture,
    flags: TicketFlags,
    authtime: KerberosTime,
    starttime: KerberosTime,
    endtime: KerberosTime,
    renew_till: Option<KerberosTime>,
) -> Credential {
    mint_ticket(
        &f.tgs_key,
        krbtgt(),
        flags,
        authtime,
        starttime,
        endtime,
        renew_till,
    )
}

fn mint_ticket(
    key: &EncryptionKey,
    sname: PrincipalName,
    flags: TicketFlags,
    authtime: KerberosTime,
    starttime: KerberosTime,
    endtime: KerberosTime,
    renew_till: Option<KerberosTime>,
) -> Credential {
    let profile = find_etype(18).expect("etype");
    let session = EncryptionKey::new(
        18,
        profile
            .random_to_key(&[7u8; 32])
            .expect("random_to_key")
            .to_vec(),
    );
    let part = EncTicketPart {
        flags: KerberosFlags::new(flags),
        key: session.clone(),
        crealm: gs(REALM),
        cname: user(),
        transited: TransitedEncoding {
            tr_type: 1,
            contents: OctetString::from(Vec::new()),
        },
        authtime,
        starttime: Some(starttime),
        endtime,
        renew_till,
        caddr: None,
        authorization_data: None,
    };
    let ticket = encrypt_ticket_part(key, Some(1), REALM, sname.clone(), &part).expect("ticket");
    Credential {
        client: user(),
        crealm: REALM.to_string(),
        server: sname,
        srealm: REALM.to_string(),
        session_key: session,
        times: TicketTimes {
            authtime,
            starttime: Some(starttime),
            endtime,
            renew_till,
        },
        ticket,
        flags: KerberosFlags::new(flags),
        addresses: None,
        authdata: None,
    }
}

/// Knobs for [`build_tgs_req`].
struct TgsReqSpec {
    sname: PrincipalName,
    options: KdcOptions,
    till: KerberosTime,
    rtime: Option<KerberosTime>,
    from: Option<KerberosTime>,
    addresses: Option<Vec<HostAddress>>,
    /// Replace the authenticator checksum (`Some(None)` omits it).
    checksum: Option<Option<Checksum>>,
    /// Mutate the body after the checksum was computed.
    tamper: Option<fn(&mut KdcReqBody)>,
}

impl TgsReqSpec {
    fn new(sname: PrincipalName, options: KdcOptions) -> Self {
        Self {
            sname,
            options,
            till: at(3600),
            rtime: None,
            from: None,
            addresses: None,
            checksum: None,
            tamper: None,
        }
    }
}

/// Hand-build a TGS-REQ with `tgt` as header ticket: keyed checksum (usage
/// 6) over the DER req-body, authenticator encrypted with usage 7.
/// Returns the request DER and the authenticator subkey.
fn build_tgs_req(tgt: &Credential, spec: TgsReqSpec) -> (Vec<u8>, EncryptionKey) {
    let session = &tgt.session_key;
    let profile = find_etype(session.keytype).expect("etype");
    let mut body = KdcReqBody {
        kdc_options: KerberosFlags::new(spec.options),
        cname: None,
        realm: gs(REALM),
        sname: Some(spec.sname),
        from: spec.from,
        till: spec.till,
        rtime: spec.rtime,
        nonce: 0x1234_5678,
        etype: vec![18, 17],
        addresses: spec.addresses,
        enc_authorization_data: None,
        additional_tickets: None,
    };
    let body_der = rasn::der::encode(&body).expect("encode body");
    let cksum = match spec.checksum {
        Some(over) => over,
        None => Some(Checksum {
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
        }),
    };
    if let Some(tamper) = spec.tamper {
        tamper(&mut body);
    }

    let subkey = EncryptionKey::new(
        18,
        profile
            .random_to_key(&[9u8; 32])
            .expect("random_to_key")
            .to_vec(),
    );
    let now: DateTime<Utc> = Utc::now();
    let auth = Authenticator {
        authenticator_vno: 5,
        crealm: gs(&tgt.crealm),
        cname: tgt.client.clone(),
        cksum,
        cusec: 0,
        ctime: now.with_nanosecond(0).expect("valid").fixed_offset(),
        subkey: Some(subkey.clone()),
        seq_number: None,
        authorization_data: None,
    };
    let cipher = profile
        .encrypt(
            session.key_bytes(),
            key_usage::TGS_REQ_AUTH,
            &rasn::der::encode(&auth).expect("encode authenticator"),
        )
        .expect("encrypt authenticator");
    let ap = ApReq {
        pvno: 5,
        msg_type: 14,
        ap_options: KerberosFlags::new(ApOptions::empty()),
        ticket: tgt.ticket.clone(),
        authenticator: EncryptedData {
            etype: session.keytype,
            kvno: None,
            cipher: OctetString::from(cipher),
        },
    };
    let req = TgsReq(KdcReq {
        pvno: 5,
        msg_type: 12,
        padata: Some(vec![PaData {
            padata_type: 1,
            padata_value: OctetString::from(rasn::der::encode(&ap).expect("encode AP-REQ")),
        }]),
        req_body: body,
    });
    (rasn::der::encode(&req).expect("encode TGS-REQ"), subkey)
}

/// Decrypt a TGS-REP with the authenticator subkey (usage 9).
fn open_tgs_rep(reply: &[u8], subkey: &EncryptionKey) -> (KdcRep, EncKdcRepPart) {
    let rep: TgsRep = rasn::der::decode(reply).expect("reply decodes as TGS-REP");
    let plain = find_etype(subkey.keytype)
        .expect("etype")
        .decrypt(
            subkey.key_bytes(),
            key_usage::TGS_REP_ENCPART_SUBKEY,
            rep.0.enc_part.cipher.as_ref(),
        )
        .expect("decrypt enc-part");
    let enc: EncTgsRepPart = rasn::der::decode(&plain).expect("EncTGSRepPart");
    (rep.0, enc.0)
}

/// Hand-built AS-REQ for cases the client state machine cannot produce.
fn build_as_req(name: &str, options: KdcOptions, etypes: Vec<i32>, padata: Vec<PaData>) -> Vec<u8> {
    let body = KdcReqBody {
        kdc_options: KerberosFlags::new(options),
        cname: Some(PrincipalName::new_principal(name)),
        realm: gs(REALM),
        sname: Some(krbtgt()),
        from: None,
        till: at(3600),
        rtime: None,
        nonce: 42,
        etype: etypes,
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: None,
    };
    let req = AsReq(KdcReq {
        pvno: 5,
        msg_type: 10,
        padata: if padata.is_empty() {
            None
        } else {
            Some(padata)
        },
        req_body: body,
    });
    rasn::der::encode(&req).expect("encode AS-REQ")
}

/// PA-ENC-TIMESTAMP for `name` with the default salt, stamped at `when`.
fn enc_timestamp_padata(name: &str, password: &str, when: KerberosTime) -> PaData {
    let profile = find_etype(18).expect("etype");
    let salt = format!("{REALM}{name}");
    let key = profile
        .string_to_key(password.as_bytes(), salt.as_bytes(), None)
        .expect("string_to_key");
    let ts = PaEncTsEnc {
        patimestamp: when,
        pausec: Some(0),
    };
    let cipher = profile
        .encrypt(
            &key,
            key_usage::PA_ENC_TIMESTAMP,
            &rasn::der::encode(&ts).expect("encode"),
        )
        .expect("encrypt");
    let enc = EncryptedData {
        etype: 18,
        kvno: None,
        cipher: OctetString::from(cipher),
    };
    PaData {
        padata_type: 2,
        padata_value: OctetString::from(rasn::der::encode(&enc).expect("encode")),
    }
}
