//! IAKERB (draft-ietf-kitten-iakerb): the acceptor proxies the
//! initiator's KDC exchanges, as MIT krb5 1.22.2 lib/gssapi/krb5/iakerb.c.

use rasn::prelude::*;

use crate::crypto::{find_cksumtype, find_etype};
use crate::error::Krb5Error;
use crate::protocol::ap::KeySource;
use crate::protocol::{
    AsExchange, AsExchangeConfig, Credential, StepResult, TgsExchange, TgsOptions, TgsStepResult,
};
use crate::types::{Checksum, EncryptionKey, KrbErrorMsg, PrincipalName};

use super::krb5::{
    AcceptStep, ChannelBindings, InitStep, Krb5Acceptor, Krb5Context, Krb5Initiator, MECH_IAKERB,
};
use super::token::{make_token_header, parse_token_header};
use super::{GssError, GssFlags};

/// IAKERB_TOK_PROXY (gssapiP_krb5.h:108).
pub const TOK_PROXY: u16 = 0x0501;
/// KRB5_KEYUSAGE_FINISHED.
pub const KEYUSAGE_FINISHED: i32 = 41;
/// KRB_AP_ERR_IAKERB_KDC_NOT_FOUND (k5-int.h:415).
pub const KRB_AP_ERR_IAKERB_KDC_NOT_FOUND: i32 = 85;
/// KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE (k5-int.h:417).
pub const KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE: i32 = 86;
/// IAKERB_MAX_HOPS: MAX_IN_TKT_LOOPS + KRB5_REFERRAL_MAXHOPS (iakerb.c:55).
const MAX_HOPS: usize = 16 + 10;

/// IAKERB-HEADER (asn1_k_encode.c:1095-1100).
#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct IakerbHeader {
    /// Realm of the KDC the enclosed message is for.
    #[rasn(tag(explicit(context, 1)))]
    pub target_realm: Utf8String,
    /// Opaque acceptor state echoed by the initiator.
    #[rasn(tag(explicit(context, 2)))]
    pub cookie: Option<OctetString>,
}

/// IAKERB-FINISHED (asn1_k_encode.c:1103-1107).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct IakerbFinished {
    /// Checksum of every IAKERB token, under the AP-REQ subkey.
    #[rasn(tag(explicit(context, 1)))]
    pub checksum: Checksum,
}

fn crypto(e: impl std::fmt::Display) -> Krb5Error {
    Krb5Error::Crypto(e.to_string())
}

fn defective() -> Krb5Error {
    Krb5Error::Gss(GssError::DefectiveToken)
}

/// `iakerb_make_finished` (iakerb.c:125-150): the key's mandatory checksum
/// over the conversation.
pub(crate) fn make_finished(key: &EncryptionKey, conv: &[u8]) -> Result<Vec<u8>, Krb5Error> {
    let profile = find_etype(key.keytype).map_err(crypto)?;
    let sum = profile
        .checksum(key.key_bytes(), KEYUSAGE_FINISHED, conv)
        .map_err(crypto)?;
    let iaf = IakerbFinished {
        checksum: Checksum {
            cksumtype: profile.checksum_type(),
            checksum: sum.into(),
        },
    };
    rasn::der::encode(&iaf).map_err(|e| Krb5Error::Protocol(e.to_string()))
}

/// `iakerb_verify_finished` (iakerb.c:156-180).
pub(crate) fn verify_finished(
    key: &EncryptionKey,
    conv: &[u8],
    finished: &[u8],
) -> Result<(), Krb5Error> {
    let iaf: IakerbFinished =
        rasn::der::decode(finished).map_err(|_| Krb5Error::Gss(GssError::Failure))?;
    let profile =
        find_cksumtype(iaf.checksum.cksumtype).map_err(|_| Krb5Error::Gss(GssError::Failure))?;
    profile
        .verify_checksum(
            key.key_bytes(),
            KEYUSAGE_FINISHED,
            conv,
            &iaf.checksum.checksum,
        )
        .map_err(|_| Krb5Error::Gss(GssError::Failure))
}

/// `iakerb_make_token` (iakerb.c:267-330), without the conversation save.
fn make_token(realm: &str, cookie: Option<&[u8]>, msg: &[u8]) -> Result<Vec<u8>, Krb5Error> {
    let header = IakerbHeader {
        target_realm: realm.to_owned(),
        cookie: cookie.map(|c| c.to_vec().into()),
    };
    let mut body = rasn::der::encode(&header).map_err(|e| Krb5Error::Protocol(e.to_string()))?;
    body.extend_from_slice(msg);
    let mut token = make_token_header(MECH_IAKERB, body.len(), Some(TOK_PROXY));
    token.extend_from_slice(&body);
    Ok(token)
}

/// Length of the DER element at the start of `b`.
fn der_element_len(b: &[u8]) -> Option<usize> {
    let (&first, rest) = b.get(1).map(|f| (f, &b[2..]))?;
    let (len, hdr) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n].iter().fold(0usize, |a, &x| (a << 8) | x as usize);
        (len, 2 + n)
    };
    hdr.checked_add(len).filter(|&t| t <= b.len())
}

/// A parsed IAKERB token.
struct Parsed<'a> {
    realm: String,
    cookie: Option<Vec<u8>>,
    message: &'a [u8],
}

/// `iakerb_parse_token` (iakerb.c:205-265).
fn parse_token(token: &[u8]) -> Result<Parsed<'_>, Krb5Error> {
    if token.is_empty() {
        return Err(defective());
    }
    let (mech, body) = parse_token_header(token).ok_or_else(defective)?;
    if mech != MECH_IAKERB || body.len() < 2 || body[..2] != TOK_PROXY.to_be_bytes() {
        return Err(defective());
    }
    let body = &body[2..];
    if body.first() != Some(&0x30) {
        return Err(defective());
    }
    let n = der_element_len(body).ok_or_else(defective)?;
    let header: IakerbHeader = rasn::der::decode(&body[..n]).map_err(|_| defective())?;
    Ok(Parsed {
        realm: header.target_realm,
        cookie: header.cookie.map(|c| c.to_vec()),
        message: &body[n..],
    })
}

/// `iakerb_is_iakerb_token` (iakerb.c:827-835).
pub fn is_iakerb_token(token: &[u8]) -> bool {
    matches!(parse_token_header(token),
        Some((mech, body)) if mech == MECH_IAKERB && body.len() >= 2 && body[..2] == TOK_PROXY.to_be_bytes())
}

/// `krb5_is_krb_error`: an [APPLICATION 30] tag.
fn is_krb_error(msg: &[u8]) -> bool {
    msg.first() == Some(&0x7e)
}

/// `iakerb_mk_error` (iakerb.c:83-101): a KRB-ERROR naming `server`, or
/// the anonymous principal when the acceptor has no name.
fn mk_error(code: i32, server: Option<(&PrincipalName, &str)>) -> Result<Vec<u8>, Krb5Error> {
    let anon = PrincipalName {
        name_type: 11,
        name_string: vec![
            rasn::types::GeneralString::from_bytes(b"WELLKNOWN").expect("ascii"),
            rasn::types::GeneralString::from_bytes(b"ANONYMOUS").expect("ascii"),
        ],
    };
    let (sname, realm) = match server {
        Some((p, r)) => (p.clone(), r.to_owned()),
        None => (anon, "WELLKNOWN:ANONYMOUS".to_owned()),
    };
    let epoch = chrono::DateTime::from_timestamp(0, 0)
        .expect("epoch")
        .fixed_offset();
    let err = KrbErrorMsg {
        pvno: 5,
        msg_type: 30,
        ctime: None,
        cusec: None,
        stime: epoch,
        susec: 0,
        error_code: code,
        crealm: None,
        cname: None,
        realm: rasn::types::GeneralString::from_bytes(realm.as_bytes())
            .map_err(|e| Krb5Error::Protocol(e.to_string()))?,
        sname,
        e_text: None,
        e_data: None,
    };
    rasn::der::encode(&err).map_err(|e| Krb5Error::Protocol(e.to_string()))
}

/// The initiator's IAKERB credential (MIT's krb5_gss_cred_id_rec with
/// `iakerb_mech` set).
#[derive(Clone)]
pub struct IakerbCred {
    /// Client principal name.
    pub client: PrincipalName,
    /// Client realm; empty starts with realm discovery (`e:` names in
    /// MIT's t_iakerb).
    pub realm: String,
    /// Password for the AS exchange (gss_acquire_cred_with_password).
    pub password: Option<String>,
    /// An existing TGT.
    pub tgt: Option<Credential>,
    /// A cached ticket for the target, which skips IAKERB entirely.
    pub service: Option<Credential>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    RealmDiscovery,
    AsReq,
    TgsReq,
    ApReq,
}

/// IAKERB initiator (`iakerb_gss_init_sec_context`, iakerb.c:932-1064).
/// Every KDC message travels inside an IAKERB token to the acceptor; the
/// AP exchange then runs as the krb5 mechanism under the IAKERB OID.
pub struct IakerbInitiator {
    state: State,
    cred: IakerbCred,
    target: PrincipalName,
    tgs_options: TgsOptions,
    req_flags: GssFlags,
    cb: Option<ChannelBindings>,
    as_ex: Option<AsExchange>,
    tgs_ex: Option<TgsExchange>,
    conv: Vec<u8>,
    krb5: Option<Krb5Initiator>,
}

impl IakerbInitiator {
    /// `iakerb_get_initial_state` (iakerb.c:712-770): no realm means realm
    /// discovery; a cached service ticket goes straight to the AP-REQ; a
    /// TGT starts with the TGS request; otherwise the AS request.
    pub fn new(
        cred: IakerbCred,
        target: PrincipalName,
        tgs_options: TgsOptions,
        req_flags: GssFlags,
        cb: Option<ChannelBindings>,
    ) -> Self {
        let state = if cred.realm.is_empty() {
            State::RealmDiscovery
        } else if cred.service.is_some() {
            State::ApReq
        } else if cred.tgt.is_some() {
            State::TgsReq
        } else {
            State::AsReq
        };
        IakerbInitiator {
            state,
            cred,
            target,
            tgs_options,
            req_flags,
            cb,
            as_ex: None,
            tgs_ex: None,
            conv: Vec::new(),
            krb5: None,
        }
    }

    /// The client realm, as learned by realm discovery.
    pub fn client_realm(&self) -> &str {
        &self.cred.realm
    }

    /// The TGT obtained (or supplied), for storing in a cache.
    pub fn tgt(&self) -> Option<&Credential> {
        self.cred.tgt.as_ref()
    }

    /// The service ticket obtained (or supplied).
    pub fn service_ticket(&self) -> Option<&Credential> {
        self.cred.service.as_ref()
    }

    fn emit(
        &mut self,
        realm: &str,
        cookie: Option<&[u8]>,
        msg: &[u8],
    ) -> Result<InitStep, Krb5Error> {
        let token = make_token(realm, cookie, msg)?;
        self.conv.extend_from_slice(&token);
        Ok(InitStep::Continue(token))
    }

    /// Drive the exchange one step; `input` is the acceptor's last token.
    pub fn step(&mut self, input: Option<&[u8]>) -> Result<InitStep, Krb5Error> {
        if self.state != State::ApReq {
            if let Some(out) = self.iakerb_step(input)? {
                return Ok(out);
            }
        }
        let first = self.krb5.is_none();
        if first {
            let service = self
                .cred
                .service
                .clone()
                .ok_or(Krb5Error::Gss(GssError::NoCred))?;
            let init = Krb5Initiator::new(
                service,
                self.cred.tgt.clone(),
                self.req_flags,
                self.cb.clone(),
            )?
            .with_iakerb(self.conv.clone());
            self.krb5 = Some(init);
        }
        let krb5 = self.krb5.as_mut().expect("set above");
        krb5.step(if first { None } else { input })
    }

    /// `iakerb_initiator_step` (iakerb.c:570-705).  `None` means the KDC
    /// exchanges are done and the AP-REQ is next.
    fn iakerb_step(&mut self, input: Option<&[u8]>) -> Result<Option<InitStep>, Krb5Error> {
        let mut kdc_in: Vec<u8> = Vec::new();
        let mut cookie = None;
        let mut server_realm = String::new();
        let first = input.is_none_or(|t| t.is_empty());
        if let Some(token) = input.filter(|_| !first) {
            let parsed = parse_token(token)?;
            self.conv.extend_from_slice(token);
            server_realm = parsed.realm;
            cookie = parsed.cookie;
            kdc_in = parsed.message.to_vec();
            if is_krb_error(&kdc_in) {
                let err: KrbErrorMsg =
                    rasn::der::decode(&kdc_in).map_err(|e| Krb5Error::Protocol(e.to_string()))?;
                if err.error_code == KRB_AP_ERR_IAKERB_KDC_NOT_FOUND
                    && self.state == State::RealmDiscovery
                {
                    return Err(Krb5Error::Protocol(
                        "The IAKERB proxy could not determine its realm".into(),
                    ));
                }
                if err.error_code == KRB_AP_ERR_IAKERB_KDC_NOT_FOUND
                    || err.error_code == KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE
                {
                    return Err(Krb5Error::KdcError(Box::new(err)));
                }
            }
        }
        let cookie = cookie.as_deref();
        loop {
            match self.state {
                State::RealmDiscovery => {
                    if first {
                        return self.emit("", cookie, &[]).map(Some);
                    }
                    if server_realm.is_empty() {
                        return Err(defective());
                    }
                    self.cred.realm = std::mem::take(&mut server_realm);
                    self.state = State::AsReq;
                    kdc_in.clear();
                }
                State::AsReq => {
                    if self.as_ex.is_none() {
                        let password = self
                            .cred
                            .password
                            .clone()
                            .ok_or(Krb5Error::Gss(GssError::NoCred))?;
                        let config = AsExchangeConfig::new(
                            self.cred.client.clone(),
                            self.cred.realm.clone(),
                        );
                        self.as_ex = Some(AsExchange::new(config, password));
                    }
                    let ex = self.as_ex.as_mut().expect("set above");
                    match ex.step(&kdc_in) {
                        Err(e) => {
                            // :641-646 — a refresh failure keeps the TGT.
                            if self.cred.tgt.is_none() {
                                return Err(e);
                            }
                        }
                        Ok(StepResult::SendToKdc { data, realm })
                        | Ok(StepResult::RetryTcp { data, realm }) => {
                            return self.emit(&realm, cookie, &data).map(Some);
                        }
                        Ok(StepResult::Complete) => {
                            self.cred.tgt = Some(ex.credential()?.clone());
                        }
                    }
                    self.as_ex = None;
                    self.state = State::TgsReq;
                    kdc_in.clear();
                }
                State::TgsReq => {
                    if self.tgs_ex.is_none() {
                        let tgt = self
                            .cred
                            .tgt
                            .clone()
                            .ok_or(Krb5Error::Gss(GssError::NoCred))?;
                        self.tgs_ex = Some(TgsExchange::new(
                            tgt,
                            self.target.clone(),
                            self.tgs_options.clone(),
                        ));
                    }
                    let ex = self.tgs_ex.as_mut().expect("set above");
                    match ex.step(&kdc_in)? {
                        TgsStepResult::SendToKdc { data, realm }
                        | TgsStepResult::RetryTcp { data, realm } => {
                            return self.emit(&realm, cookie, &data).map(Some);
                        }
                        TgsStepResult::Complete => {
                            self.cred.service = Some(ex.credential()?.clone());
                        }
                    }
                    self.tgs_ex = None;
                    self.state = State::ApReq;
                }
                State::ApReq => return Ok(None),
            }
        }
    }

    /// Extract the established context.
    pub fn context(self) -> Result<Krb5Context, Krb5Error> {
        self.krb5
            .ok_or(Krb5Error::Gss(GssError::NoContext))?
            .context()
    }
}

/// Result of an IAKERB acceptor step.
#[derive(Debug)]
pub enum IakerbAcceptStep {
    /// Send this token to the initiator and wait for its next token.
    Continue(Vec<u8>),
    /// Send `data` to a KDC for `realm` (MIT's krb5_sendto_kdc, retrying
    /// over TCP on KRB_ERR_RESPONSE_TOO_BIG), then pass the outcome to
    /// [`IakerbAcceptor::kdc_reply`].
    SendToKdc {
        /// Realm named by the initiator.
        realm: String,
        /// The initiator's KDC request.
        data: Vec<u8>,
    },
    /// The krb5 AP exchange finished.
    Complete {
        /// AP-REP token for the initiator, if mutual.
        token: Option<Vec<u8>>,
    },
}

/// IAKERB acceptor (`iakerb_gss_accept_sec_context`, iakerb.c:846-930).
pub struct IakerbAcceptor {
    keys: Option<Box<dyn KeySource + Send>>,
    server: Option<PrincipalName>,
    realm: Option<String>,
    cb: Option<ChannelBindings>,
    conv: Vec<u8>,
    count: usize,
    pending: Option<String>,
    krb5: Option<Krb5Acceptor>,
}

impl IakerbAcceptor {
    /// `realm` answers realm discovery: the verifier credential's realm,
    /// else the default realm (`iakerb_acceptor_realm`, iakerb.c:333-370).
    pub fn new(
        keys: Box<dyn KeySource + Send>,
        server: Option<PrincipalName>,
        realm: Option<String>,
        cb: Option<ChannelBindings>,
    ) -> Self {
        IakerbAcceptor {
            keys: Some(keys),
            server,
            realm,
            cb,
            conv: Vec::new(),
            count: 0,
            pending: None,
            krb5: None,
        }
    }

    fn server_ref(&self) -> Option<(&PrincipalName, &str)> {
        self.server.as_ref().zip(self.realm.as_deref())
    }

    fn emit(&mut self, realm: &str, msg: &[u8]) -> Result<Vec<u8>, Krb5Error> {
        let token = make_token(realm, None, msg)?;
        self.conv.extend_from_slice(&token);
        self.count += 1;
        Ok(token)
    }

    /// Process a token from the initiator.
    pub fn step(&mut self, input: &[u8]) -> Result<IakerbAcceptStep, Krb5Error> {
        if is_iakerb_token(input) {
            if self.krb5.is_some() || self.pending.is_some() {
                return Err(defective());
            }
            // iakerb_acceptor_step (:379-460).
            if self.count >= MAX_HOPS {
                return Err(Krb5Error::Protocol(
                    "Cannot contact any KDC for requested realm".into(),
                ));
            }
            let parsed = parse_token(input)?;
            let (realm, message) = (parsed.realm, parsed.message.to_vec());
            self.conv.extend_from_slice(input);
            if realm.is_empty() && message.is_empty() {
                let token = match self.realm.clone() {
                    Some(r) => self.emit(&r, &[])?,
                    None => {
                        let err = mk_error(KRB_AP_ERR_IAKERB_KDC_NOT_FOUND, self.server_ref())?;
                        self.emit("", &err)?
                    }
                };
                return Ok(IakerbAcceptStep::Continue(token));
            }
            if realm.is_empty() || message.is_empty() {
                return Err(defective());
            }
            self.pending = Some(realm.clone());
            return Ok(IakerbAcceptStep::SendToKdc {
                realm,
                data: message,
            });
        }
        if self.pending.is_some() {
            return Err(defective());
        }
        if self.krb5.is_none() {
            let keys = self
                .keys
                .take()
                .ok_or(Krb5Error::Gss(GssError::NoContext))?;
            self.krb5 = Some(
                Krb5Acceptor::new(keys, self.server.clone(), self.cb.clone())
                    .with_iakerb(self.conv.clone()),
            );
        }
        match self.krb5.as_mut().expect("set above").step(input)? {
            AcceptStep::Complete { token } => Ok(IakerbAcceptStep::Complete { token }),
            AcceptStep::ContinueNeeded(token) => Ok(IakerbAcceptStep::Continue(token)),
        }
    }

    /// Wrap the KDC's reply (or the failure to reach one) for the
    /// initiator: an unreachable KDC becomes KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE
    /// and an unknown realm KRB_AP_ERR_IAKERB_KDC_NOT_FOUND (iakerb.c:436-447).
    pub fn kdc_reply(&mut self, reply: Result<Vec<u8>, Krb5Error>) -> Result<Vec<u8>, Krb5Error> {
        let realm = self
            .pending
            .take()
            .ok_or(Krb5Error::Gss(GssError::NoContext))?;
        let reply = match reply {
            Ok(r) => r,
            Err(e) => match unreachable_code(&e) {
                Some(code) => mk_error(code, self.server_ref())?,
                None => return Err(e),
            },
        };
        self.emit(&realm, &reply)
    }

    /// Extract the established context.
    pub fn context(self) -> Result<Krb5Context, Krb5Error> {
        self.krb5
            .ok_or(Krb5Error::Gss(GssError::NoContext))?
            .context()
    }

    /// Credentials delegated by the initiator.
    pub fn delegated_creds(&self) -> Option<&[Credential]> {
        self.krb5.as_ref()?.delegated_creds()
    }
}

#[cfg(feature = "tokio")]
fn unreachable_code(e: &Krb5Error) -> Option<i32> {
    use crate::locate::LocateError;
    use crate::transport::sendto::SendtoError;
    match e {
        Krb5Error::Sendto(SendtoError::KdcUnreach) => Some(KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE),
        Krb5Error::Locate(LocateError::RealmUnknown) => Some(KRB_AP_ERR_IAKERB_KDC_NOT_FOUND),
        _ => None,
    }
}

#[cfg(not(feature = "tokio"))]
fn unreachable_code(e: &Krb5Error) -> Option<i32> {
    use crate::locate::LocateError;
    match e {
        Krb5Error::Locate(LocateError::RealmUnknown) => Some(KRB_AP_ERR_IAKERB_KDC_NOT_FOUND),
        _ => None,
    }
}

#[cfg(all(test, feature = "kdc", feature = "tokio"))]
#[path = "iakerb_tests.rs"]
mod tests;
