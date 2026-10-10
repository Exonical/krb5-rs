//! One-line request summaries in the style of MIT `log_as_req` /
//! `log_tgs_req` (kdc/kdc_log.c): request type, enctypes, peer, outcome,
//! client and server.

use std::fmt;
use std::net::SocketAddr;

use crate::types::{AsReq, KdcReq, KrbErrorMsg, TgsReq};

const TAG_AS_REQ: u8 = 0x6A;
const TAG_TGS_REQ: u8 = 0x6C;
const TAG_AS_REP: u8 = 0x6B;
const TAG_TGS_REP: u8 = 0x6D;
const TAG_KRB_ERROR: u8 = 0x7E;

/// How a request reached the KDC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// A UDP datagram (replies above `max_dgram_reply_size` are replaced).
    Udp,
    /// A TCP connection.
    Tcp,
}

/// The kind of request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    /// AS-REQ.
    As,
    /// TGS-REQ.
    Tgs,
    /// Not a decodable AS-REQ or TGS-REQ.
    Unknown,
}

/// What the KDC answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A ticket was issued.
    Issued,
    /// A KRB-ERROR was returned.
    Error {
        /// The KRB-ERROR error-code.
        code: i32,
        /// The e-text (MIT's status string), when present.
        status: Option<String>,
    },
}

/// A summary of one request and its reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestSummary {
    /// AS-REQ or TGS-REQ.
    pub kind: RequestKind,
    /// How it arrived.
    pub transport: Transport,
    /// The client as `name@REALM`: from the AS-REQ, or from the reply
    /// (TGS-REQs carry the client only inside the ticket).
    pub client: Option<String>,
    /// The requested server as `name@REALM`.
    pub server: Option<String>,
    /// Enctypes the request listed, in order.
    pub etypes: Vec<i32>,
    /// ISSUE or the error.
    pub outcome: Outcome,
    /// Enctype of the reply's encrypted part (`rep=` in MIT's log).
    pub reply_etype: Option<i32>,
    /// Enctype of the issued ticket (`tkt=`).
    pub ticket_etype: Option<i32>,
    /// The consistency gate refused the request (`KDC_ERR_SVC_UNAVAILABLE`,
    /// the only source of that code here): the hook for a
    /// rejected-for-staleness metric.
    pub gate_rejected: bool,
}

impl RequestSummary {
    pub(crate) fn new(request: &[u8], reply: &[u8], transport: Transport) -> Self {
        let decoded: Option<(RequestKind, KdcReq)> = match request.first() {
            Some(&TAG_AS_REQ) => rasn::der::decode::<AsReq>(request)
                .ok()
                .map(|r| (RequestKind::As, r.0)),
            Some(&TAG_TGS_REQ) => rasn::der::decode::<TgsReq>(request)
                .ok()
                .map(|r| (RequestKind::Tgs, r.0)),
            _ => None,
        };
        let (kind, mut client, server, etypes) = match &decoded {
            Some((kind, req)) => {
                let realm = String::from_utf8_lossy(req.req_body.realm.as_bytes()).to_string();
                (
                    *kind,
                    req.req_body.cname.as_ref().map(|c| format!("{c}@{realm}")),
                    req.req_body.sname.as_ref().map(|s| format!("{s}@{realm}")),
                    req.req_body.etype.clone(),
                )
            }
            None => (RequestKind::Unknown, None, None, Vec::new()),
        };

        let mut reply_etype = None;
        let mut ticket_etype = None;
        let outcome = match reply.first() {
            Some(&TAG_AS_REP) | Some(&TAG_TGS_REP) => {
                let rep = if reply[0] == TAG_AS_REP {
                    rasn::der::decode::<crate::types::AsRep>(reply)
                        .ok()
                        .map(|r| r.0)
                } else {
                    rasn::der::decode::<crate::types::TgsRep>(reply)
                        .ok()
                        .map(|r| r.0)
                };
                if let Some(rep) = rep {
                    client = Some(format!(
                        "{}@{}",
                        rep.cname,
                        String::from_utf8_lossy(rep.crealm.as_bytes())
                    ));
                    reply_etype = Some(rep.enc_part.etype);
                    ticket_etype = Some(rep.ticket.enc_part.etype);
                }
                Outcome::Issued
            }
            Some(&TAG_KRB_ERROR) => match rasn::der::decode::<KrbErrorMsg>(reply) {
                Ok(e) => {
                    if client.is_none() {
                        if let (Some(n), Some(r)) = (&e.cname, &e.crealm) {
                            client = Some(format!("{n}@{}", String::from_utf8_lossy(r.as_bytes())));
                        }
                    }
                    Outcome::Error {
                        code: e.error_code,
                        status: e
                            .e_text
                            .map(|t| String::from_utf8_lossy(t.as_bytes()).to_string()),
                    }
                }
                Err(_) => Outcome::Error {
                    code: -1,
                    status: None,
                },
            },
            _ => Outcome::Error {
                code: -1,
                status: None,
            },
        };

        let gate_rejected = matches!(
            outcome,
            Outcome::Error { code, .. } if code == crate::types::error_codes::KDC_ERR_SVC_UNAVAILABLE
        );
        Self {
            kind,
            transport,
            client,
            server,
            etypes,
            outcome,
            reply_etype,
            ticket_etype,
            gate_rejected,
        }
    }

    /// The MIT-style log line for a request from `peer`, e.g.
    /// `AS_REQ (2 etypes {18 17}) 10.0.0.1:50000: ISSUE: user@R for krbtgt/R@R, etypes {rep=18 tkt=18}`
    /// or `AS_REQ (1 etypes {18}) 10.0.0.1:50000: NEEDED_PREAUTH: user@R for krbtgt/R@R, error 25`.
    pub fn log_line(&self, peer: SocketAddr) -> String {
        let kind = match self.kind {
            RequestKind::As => "AS_REQ",
            RequestKind::Tgs => "TGS_REQ",
            RequestKind::Unknown => "UNKNOWN_REQ",
        };
        let etypes: Vec<String> = self.etypes.iter().map(i32::to_string).collect();
        let who = match (&self.client, &self.server) {
            (Some(c), Some(s)) => format!("{c} for {s}"),
            (Some(c), None) => c.clone(),
            (None, Some(s)) => format!("(unknown client) for {s}"),
            (None, None) => "(unparseable request)".to_string(),
        };
        let tail = match &self.outcome {
            Outcome::Issued => {
                let mut s = "ISSUE".to_string();
                s.push_str(&format!(": {who}"));
                if let (Some(rep), Some(tkt)) = (self.reply_etype, self.ticket_etype) {
                    s.push_str(&format!(", etypes {{rep={rep} tkt={tkt}}}"));
                }
                s
            }
            Outcome::Error { code, status } => format!(
                "{}: {who}, error {code}",
                status.as_deref().unwrap_or("UNKNOWN_ERROR")
            ),
        };
        format!(
            "{kind} ({} etypes {{{}}}) {peer}: {tail}",
            self.etypes.len(),
            etypes.join(" ")
        )
    }
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Transport::Udp => "udp",
            Transport::Tcp => "tcp",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdc::{Kdc, KdcConfig, MemoryStore, PrincipalAttributes};
    use crate::protocol::{
        AsExchange, AsExchangeConfig, StepResult, TgsExchange, TgsOptions, TgsStepResult,
    };
    use crate::types::PrincipalName;

    const REALM: &str = "R";

    fn kdc() -> Kdc<MemoryStore> {
        let mut store = MemoryStore::new();
        store
            .add_random_key(
                PrincipalName::new_srv_inst("krbtgt", REALM),
                REALM,
                1,
                &[18],
                PrincipalAttributes::empty(),
            )
            .expect("krbtgt");
        store
            .add_with_password(
                PrincipalName::new_principal("alice"),
                REALM,
                "pw",
                1,
                &[18],
                PrincipalAttributes::REQUIRES_PRE_AUTH,
            )
            .expect("alice");
        store
            .add_random_key(
                PrincipalName::new_srv_hst("HTTP", "h.r"),
                REALM,
                1,
                &[18],
                PrincipalAttributes::empty(),
            )
            .expect("service");
        Kdc::new(KdcConfig::new(REALM), store)
    }

    fn peer() -> SocketAddr {
        "192.0.2.7:4000".parse().expect("addr")
    }

    #[tokio::test]
    async fn preauth_required_is_summarised_with_mits_status_and_code() {
        let kdc = kdc();
        let mut ex = AsExchange::new(
            AsExchangeConfig::new(PrincipalName::new_principal("alice"), REALM),
            "pw",
        );
        let StepResult::SendToKdc { data, .. } = ex.step(&[]).expect("step") else {
            panic!("expected a request");
        };
        let (_, s) = kdc.handle_summarized(&data, Transport::Udp).await;
        assert_eq!(s.kind, RequestKind::As);
        assert_eq!(s.client.as_deref(), Some("alice@R"));
        assert_eq!(s.server.as_deref(), Some("krbtgt/R@R"));
        assert_eq!(s.etypes, vec![18, 17, 20, 19]);
        assert_eq!(
            s.outcome,
            Outcome::Error {
                code: 25,
                status: Some("NEEDED_PREAUTH".into())
            }
        );
        assert_eq!(
            s.log_line(peer()),
            "AS_REQ (4 etypes {18 17 20 19}) 192.0.2.7:4000: NEEDED_PREAUTH: \
             alice@R for krbtgt/R@R, error 25"
        );
    }

    #[tokio::test]
    async fn issued_as_and_tgs_requests_report_the_client_and_enctypes() {
        let kdc = kdc();
        let mut ex = AsExchange::new(
            AsExchangeConfig::new(PrincipalName::new_principal("alice"), REALM),
            "pw",
        );
        let mut input = Vec::new();
        let mut last = None;
        while let StepResult::SendToKdc { data, .. } | StepResult::RetryTcp { data, .. } =
            ex.step(&input).expect("step")
        {
            let (reply, s) = kdc.handle_summarized(&data, Transport::Tcp).await;
            input = reply;
            last = Some(s);
        }
        let s = last.expect("a request");
        assert_eq!(s.outcome, Outcome::Issued);
        assert_eq!(s.client.as_deref(), Some("alice@R"));
        assert_eq!((s.reply_etype, s.ticket_etype), (Some(18), Some(18)));
        assert!(s
            .log_line(peer())
            .contains("ISSUE: alice@R for krbtgt/R@R, etypes {rep=18 tkt=18}"));

        let tgt = ex.credential().expect("TGT").clone();
        let mut tgs = TgsExchange::new(
            tgt,
            PrincipalName::new_srv_hst("HTTP", "h.r"),
            TgsOptions::default(),
        );
        let mut input = Vec::new();
        let mut last = None;
        while let TgsStepResult::SendToKdc { data, .. } | TgsStepResult::RetryTcp { data, .. } =
            tgs.step(&input).expect("step")
        {
            let (reply, s) = kdc.handle_summarized(&data, Transport::Udp).await;
            input = reply;
            last = Some(s);
        }
        let s = last.expect("a request");
        assert_eq!(s.kind, RequestKind::Tgs);
        assert_eq!(s.outcome, Outcome::Issued);
        assert_eq!(s.client.as_deref(), Some("alice@R"));
        assert_eq!(s.server.as_deref(), Some("HTTP/h.r@R"));
    }

    #[tokio::test]
    async fn garbage_is_an_unknown_request_error() {
        let (reply, s) = kdc().handle_summarized(&[1, 2, 3], Transport::Udp).await;
        assert!(!reply.is_empty());
        assert_eq!(s.kind, RequestKind::Unknown);
        assert_eq!(
            s.outcome,
            Outcome::Error {
                code: 40,
                status: Some("BAD_MESSAGE_TYPE".into())
            }
        );
        assert_eq!(
            s.log_line(peer()),
            "UNKNOWN_REQ (0 etypes {}) 192.0.2.7:4000: BAD_MESSAGE_TYPE: (unparseable request), error 40"
        );
    }
}
