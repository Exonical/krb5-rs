#![cfg(feature = "kdc")]
//! MS-PAC issuing and verification by the KDC (MIT kdc_authdata.c
//! `handle_pac`, kdc_util.c `get_verified_pac`, tgs_policy.c
//! `check_normal_tgs_pac`).

use krb5_rs::kdc::{Kdc, KdcConfig, MemoryStore, PrincipalAttributes};
use krb5_rs::pac::{
    ticket_pac, verify_ticket_pac, Pac, PAC_CLIENT_INFO, PAC_FULL_CHECKSUM, PAC_PRIVSVR_CHECKSUM,
    PAC_SERVER_CHECKSUM, PAC_TICKET_CHECKSUM,
};
use krb5_rs::protocol::ap::{decrypt_ticket, encrypt_ticket_part};
use krb5_rs::protocol::{
    AsExchange, AsExchangeConfig, Credential, StepResult, TgsExchange, TgsOptions, TgsStepResult,
};
use krb5_rs::types::{
    AuthorizationDataElement, EncTicketPart, EncryptionKey, PrincipalName, Ticket,
};
use krb5_rs::Krb5Error;

const REALM: &str = "PAC.REALM";
const PASSWORD: &str = "pac-password";

fn gs(s: &str) -> rasn::types::GeneralString {
    rasn::types::GeneralString::from_bytes(s.as_bytes()).expect("string")
}

fn tgs_name() -> PrincipalName {
    PrincipalName {
        name_type: 2,
        name_string: vec![gs("krbtgt"), gs(REALM)],
    }
}

fn svc() -> PrincipalName {
    PrincipalName::new_srv_hst("HTTP", "server.pac.realm")
}

fn noauth_svc() -> PrincipalName {
    PrincipalName::new_srv_hst("HTTP", "noauth.pac.realm")
}

fn alice() -> PrincipalName {
    PrincipalName::new_principal("alice")
}

struct Fix {
    kdc: Kdc<MemoryStore>,
    tgs_key: EncryptionKey,
    svc_key: EncryptionKey,
    noauth_key: EncryptionKey,
}

async fn fixture(tweak: impl FnOnce(&mut KdcConfig)) -> Fix {
    let mut store = MemoryStore::new();
    let none = PrincipalAttributes::empty();
    store
        .add_random_key(tgs_name(), REALM, 1, &[18, 17], none)
        .expect("krbtgt");
    store
        .add_with_password(alice(), REALM, PASSWORD, 1, &[18, 17], none)
        .expect("alice");
    store
        .add_random_key(svc(), REALM, 1, &[18, 17], none)
        .expect("svc");
    store
        .add_random_key(
            noauth_svc(),
            REALM,
            1,
            &[18, 17],
            PrincipalAttributes::NO_AUTH_DATA_REQUIRED,
        )
        .expect("noauth svc");
    let key = |name: &PrincipalName| store.get(name, REALM).expect("entry").keys[0].key.clone();
    let (tgs_key, svc_key, noauth_key) = (key(&tgs_name()), key(&svc()), key(&noauth_svc()));
    let mut config = KdcConfig::new(REALM);
    tweak(&mut config);
    Fix {
        kdc: Kdc::new(config, store),
        tgs_key,
        svc_key,
        noauth_key,
    }
}

impl Fix {
    async fn login_with(&self, request_pac: bool) -> Credential {
        let mut config = AsExchangeConfig::new(alice(), REALM);
        config.request_pac = request_pac;
        let mut ex = AsExchange::new(config, PASSWORD);
        let mut reply = Vec::new();
        while let StepResult::SendToKdc { data, .. } | StepResult::RetryTcp { data, .. } =
            ex.step(&reply).expect("AS step")
        {
            reply = self.kdc.handle(&data).await;
        }
        ex.credential().expect("TGT").clone()
    }

    async fn login(&self) -> Credential {
        self.login_with(true).await
    }

    async fn tgs(&self, tgt: &Credential, target: PrincipalName) -> Result<Credential, Krb5Error> {
        let mut ex = TgsExchange::new(tgt.clone(), target, TgsOptions::default());
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

    fn tgt_part(&self, tgt: &Credential) -> EncTicketPart {
        decrypt_ticket(&self.tgs_key, &tgt.ticket).expect("decrypt TGT")
    }

    fn reissue_tgt(&self, tgt: &Credential, part: &EncTicketPart) -> Credential {
        let ticket: Ticket = encrypt_ticket_part(
            &self.tgs_key,
            Some(1),
            REALM,
            tgt.ticket.sname.clone(),
            part,
        )
        .expect("re-encrypt TGT");
        let mut out = tgt.clone();
        out.ticket = ticket;
        out
    }
}

fn kdc_code(e: &Krb5Error) -> i32 {
    match e {
        Krb5Error::KdcError(m) => m.error_code,
        other => panic!("expected KDC error, got {other:?}"),
    }
}

fn pac_of(part: &EncTicketPart) -> Pac {
    ticket_pac(part).expect("parse PAC").expect("PAC present")
}

fn if_relevant(inner: &[AuthorizationDataElement]) -> AuthorizationDataElement {
    AuthorizationDataElement {
        ad_type: 1,
        ad_data: rasn::der::encode(&inner.to_vec()).expect("encode").into(),
    }
}

fn pac_container(pac_bytes: Vec<u8>) -> AuthorizationDataElement {
    if_relevant(&[AuthorizationDataElement {
        ad_type: 128,
        ad_data: pac_bytes.into(),
    }])
}

#[tokio::test]
async fn as_tgt_carries_pac_verifiable_with_the_krbtgt_key() {
    let f = fixture(|_| {}).await;
    let tgt = f.login().await;
    let part = f.tgt_part(&tgt);

    let authdata = part.authorization_data.as_ref().expect("authdata");
    assert_eq!(authdata.len(), 1);
    assert_eq!(authdata[0].ad_type, 1, "AD-IF-RELEVANT");

    let pac = pac_of(&part);
    // A TGT carries no ticket or full checksum (pac.c:579-588).
    assert_eq!(
        pac.types(),
        vec![PAC_CLIENT_INFO, PAC_SERVER_CHECKSUM, PAC_PRIVSVR_CHECKSUM]
    );
    let authtime = part.authtime.timestamp();
    pac.verify(
        authtime,
        Some((&alice(), REALM)),
        Some(&f.tgs_key),
        Some(&f.tgs_key),
    )
    .expect("PAC verifies");
    verify_ticket_pac(&part, &tgs_name(), &f.tgs_key, None)
        .expect("server signature")
        .expect("PAC");
    assert_eq!(pac.client_info().expect("client info").name, "alice");
}

#[tokio::test]
async fn tgs_service_ticket_carries_pac_signed_for_service_and_kdc() {
    let f = fixture(|_| {}).await;
    let tgt = f.login().await;
    let cred = f.tgs(&tgt, svc()).await.expect("service ticket");
    let part = decrypt_ticket(&f.svc_key, &cred.ticket).expect("decrypt");
    let pac = pac_of(&part);
    assert_eq!(
        pac.types(),
        vec![
            PAC_CLIENT_INFO,
            PAC_TICKET_CHECKSUM,
            PAC_SERVER_CHECKSUM,
            PAC_PRIVSVR_CHECKSUM,
            PAC_FULL_CHECKSUM
        ]
    );
    let authtime = part.authtime.timestamp();
    pac.verify(
        authtime,
        Some((&alice(), REALM)),
        Some(&f.svc_key),
        Some(&f.tgs_key),
    )
    .expect("server and KDC signatures");
    verify_ticket_pac(&part, &svc(), &f.svc_key, Some(&f.tgs_key))
        .expect("ticket and full checksums")
        .expect("PAC");
    verify_ticket_pac(&part, &svc(), &f.svc_key, None).expect("service side verification");
    assert!(verify_ticket_pac(&part, &svc(), &f.svc_key, Some(&f.noauth_key)).is_err());
    assert!(verify_ticket_pac(&part, &svc(), &f.noauth_key, None).is_err());

    // A client-visible ticket change after signing breaks the ticket checksum.
    let mut changed = part.clone();
    changed.endtime += chrono::Duration::seconds(1);
    assert!(verify_ticket_pac(&changed, &svc(), &f.svc_key, Some(&f.tgs_key)).is_err());
    assert!(verify_ticket_pac(&changed, &svc(), &f.svc_key, None).is_ok());

    // The client name and authtime are the TGT's.
    assert_eq!(part.cname, alice());
    assert_eq!(part.authtime, f.tgt_part(&tgt).authtime);
}

#[tokio::test]
async fn tampered_pac_in_tgt_is_rejected_with_ap_err_modified() {
    let f = fixture(|_| {}).await;
    let tgt = f.login().await;
    let mut part = f.tgt_part(&tgt);
    let mut bytes = pac_of(&part).encode();
    // Flip a bit in the client info name.
    let pac = Pac::parse(&bytes).expect("parse");
    let name = pac
        .get_buffer(PAC_CLIENT_INFO)
        .expect("client info")
        .to_vec();
    let at = bytes
        .windows(name.len())
        .position(|w| w == name.as_slice())
        .expect("locate client info");
    bytes[at + name.len() - 1] ^= 1;
    part.authorization_data = Some(vec![pac_container(bytes)]);
    let bad = f.reissue_tgt(&tgt, &part);
    let err = f.tgs(&bad, svc()).await.expect_err("must fail");
    assert_eq!(kdc_code(&err), 41);
}

#[tokio::test]
async fn pac_signed_for_another_client_is_rejected_as_bad_option() {
    let f = fixture(|_| {}).await;
    let tgt = f.login().await;
    let mut part = f.tgt_part(&tgt);
    let mut forged = Pac::new();
    let mallory = PrincipalName::new_principal("mallory");
    let bytes = forged
        .sign(
            part.authtime.timestamp(),
            (&mallory, REALM),
            &f.tgs_key,
            &f.tgs_key,
        )
        .expect("sign");
    part.authorization_data = Some(vec![pac_container(bytes)]);
    let bad = f.reissue_tgt(&tgt, &part);
    let err = f.tgs(&bad, svc()).await.expect_err("must fail");
    assert_eq!(kdc_code(&err), 13);
}

#[tokio::test]
async fn pac_with_wrong_authtime_is_rejected_as_bad_option() {
    let f = fixture(|_| {}).await;
    let tgt = f.login().await;
    let mut part = f.tgt_part(&tgt);
    let mut forged = Pac::new();
    let bytes = forged
        .sign(
            part.authtime.timestamp() - 5,
            (&alice(), REALM),
            &f.tgs_key,
            &f.tgs_key,
        )
        .expect("sign");
    part.authorization_data = Some(vec![pac_container(bytes)]);
    let bad = f.reissue_tgt(&tgt, &part);
    assert_eq!(
        kdc_code(&f.tgs(&bad, svc()).await.expect_err("must fail")),
        13
    );
}

#[tokio::test]
async fn tgt_without_pac_yields_service_ticket_without_pac() {
    let f = fixture(|_| {}).await;
    let tgt = f.login_with(false).await;
    assert!(f.tgt_part(&tgt).authorization_data.is_none());
    let cred = f.tgs(&tgt, svc()).await.expect("service ticket");
    let part = decrypt_ticket(&f.svc_key, &cred.ticket).expect("decrypt");
    assert!(part.authorization_data.is_none());
}

#[tokio::test]
async fn disable_pac_issues_no_pac() {
    let f = fixture(|c| c.disable_pac = true).await;
    let tgt = f.login().await;
    assert!(f.tgt_part(&tgt).authorization_data.is_none());
    let cred = f.tgs(&tgt, svc()).await.expect("service ticket");
    let part = decrypt_ticket(&f.svc_key, &cred.ticket).expect("decrypt");
    assert!(part.authorization_data.is_none());
}

#[tokio::test]
async fn no_auth_data_required_server_gets_no_pac() {
    let f = fixture(|_| {}).await;
    let tgt = f.login().await;
    assert!(f.tgt_part(&tgt).authorization_data.is_some());
    let cred = f.tgs(&tgt, noauth_svc()).await.expect("service ticket");
    let part = decrypt_ticket(&f.noauth_key, &cred.ticket).expect("decrypt");
    assert!(part.authorization_data.is_none());
}

#[tokio::test]
async fn non_pac_header_authdata_is_copied_after_the_new_pac() {
    let f = fixture(|_| {}).await;
    let tgt = f.login().await;
    let mut part = f.tgt_part(&tgt);
    let extra = if_relevant(&[AuthorizationDataElement {
        ad_type: 77,
        ad_data: b"keep me".to_vec().into(),
    }]);
    let kdc_issued = AuthorizationDataElement {
        ad_type: 4,
        ad_data: vec![1, 2, 3].into(),
    };
    part.authorization_data
        .as_mut()
        .expect("authdata")
        .extend([extra.clone(), kdc_issued]);
    let cred = f
        .tgs(&f.reissue_tgt(&tgt, &part), svc())
        .await
        .expect("service ticket");
    let issued = decrypt_ticket(&f.svc_key, &cred.ticket).expect("decrypt");
    let list = issued.authorization_data.expect("authdata");
    assert_eq!(list.len(), 2, "new PAC plus the copied container");
    assert!(Pac::parse(&decode_pac(&list[0])).is_ok());
    assert_eq!(list[1].ad_data, extra.ad_data);
}

fn decode_pac(container: &AuthorizationDataElement) -> Vec<u8> {
    let inner: Vec<AuthorizationDataElement> =
        rasn::der::decode(container.ad_data.as_ref()).expect("inner");
    assert_eq!(inner[0].ad_type, 128);
    inner[0].ad_data.to_vec()
}

#[tokio::test]
async fn mandatory_for_kdc_header_authdata_is_refused() {
    let f = fixture(|_| {}).await;
    let tgt = f.login().await;
    let mut part = f.tgt_part(&tgt);
    part.authorization_data
        .as_mut()
        .expect("authdata")
        .push(AuthorizationDataElement {
            ad_type: 8,
            ad_data: vec![0].into(),
        });
    let err = f
        .tgs(&f.reissue_tgt(&tgt, &part), svc())
        .await
        .expect_err("must fail");
    assert_eq!(kdc_code(&err), 12);
}
