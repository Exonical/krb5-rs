//! KDC policy (`kdc/policy.c`, `kdcpolicy_plugin.h`) and audit
//! (`kdc/kdc_audit.c`, `audit_plugin.h`) modules, and authdata modules
//! (`kdc/kdc_authdata.c`, `kdcauthdata_plugin.h`).

use std::sync::Arc;

use sha2::{Digest, Sha256};

pub mod greet;
pub mod rpc;

/// `KRB5KDC_ERR_POLICY`.
pub const KDC_ERR_POLICY: i32 = 12;

/// The request a [`KdcPolicy`] module sees.
#[derive(Debug, Clone, Default)]
pub struct PolicyRequest {
    /// The request's client principal, unparsed (AS only).
    pub client: Option<String>,
    /// The request's server principal, unparsed.
    pub server: String,
    /// The ticket client (TGS only), unparsed.
    pub ticket_client: Option<String>,
    /// The request's authentication indicators.
    pub auth_indicators: Vec<String>,
}

/// A policy refusal: the Kerberos error code and KDC status string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRefusal {
    /// The Kerberos error code.
    pub code: i32,
    /// The KDC status string logged for the request.
    pub status: String,
}

/// Lifetimes a [`KdcPolicy`] module grants, in seconds; zero leaves the
/// time alone.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PolicyLimits {
    /// Maximum ticket lifetime.
    pub lifetime: i64,
    /// Maximum renewable lifetime.
    pub renew_lifetime: i64,
}

/// A kdcpolicy module (`krb5_kdcpolicy_vtable`).
pub trait KdcPolicy: Send + Sync {
    /// The module name.
    fn name(&self) -> &str;

    /// `init`: an error refuses the module; `PLUGIN_NO_HANDLE` skips it.
    fn init(&self) -> Result<(), i32> {
        Ok(())
    }

    /// `fini`, when the KDC unloads the module.
    fn fini(&self) {}

    /// `check_as`.
    fn check_as(&self, _req: &PolicyRequest) -> Result<PolicyLimits, PolicyRefusal> {
        Ok(PolicyLimits::default())
    }

    /// `check_tgs`.
    fn check_tgs(&self, _req: &PolicyRequest) -> Result<PolicyLimits, PolicyRefusal> {
        Ok(PolicyLimits::default())
    }
}

/// MIT's `update_ticket_times` (`policy.c`): cap the end and renew-till
/// times at `now` plus the granted lifetimes.
pub fn update_ticket_times(endtime: &mut i64, renew_till: &mut i64, now: i64, l: PolicyLimits) {
    if l.lifetime != 0 {
        *endtime = (*endtime).min(now.saturating_add(l.lifetime));
    }
    if l.renew_lifetime != 0 {
        *renew_till = (*renew_till).min(now.saturating_add(l.renew_lifetime));
    }
}

/// `check_kdcpolicy_as` / `check_kdcpolicy_tgs`: run every module in order;
/// the first refusal is returned, and each module's lifetimes cap the
/// times.
pub fn check_policy(
    modules: &[Arc<dyn KdcPolicy>],
    tgs: bool,
    req: &PolicyRequest,
    now: i64,
    endtime: &mut i64,
    renew_till: &mut i64,
) -> Result<(), PolicyRefusal> {
    for m in modules {
        let l = if tgs {
            m.check_tgs(req)?
        } else {
            m.check_as(req)?
        };
        update_ticket_times(endtime, renew_till, now, l);
    }
    Ok(())
}

/// `krb5_audit_state.stage`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(i32)]
pub enum AuditStage {
    /// `AUTHN_REQ_CL`.
    #[default]
    AuthnReqCl = 1,
    /// `SRVC_PRINC`.
    SrvcPrinc = 2,
    /// `VALIDATE_POL`.
    ValidatePol = 3,
    /// `ISSUE_TKT`.
    IssueTkt = 4,
    /// `ENCR_REP`.
    EncrRep = 5,
}

/// `krb5_audit_state.violation`: `PROT_CONSTRAINT`.
pub const PROT_CONSTRAINT: i32 = 1;
/// `krb5_audit_state.violation`: `LOCAL_POLICY`.
pub const LOCAL_POLICY: i32 = 2;

/// `krb5_audit_state`, with principals unparsed.
#[derive(Debug, Clone, Default)]
pub struct AuditState {
    /// `req_id`: 32 random alphanumeric characters.
    pub req_id: String,
    /// `cl_addr`, or `None` when unknown.
    pub cl_addr: Option<std::net::IpAddr>,
    /// `cl_port`.
    pub cl_port: u16,
    /// `stage`.
    pub stage: AuditStage,
    /// `status`.
    pub status: Option<String>,
    /// The request's client principal.
    pub client: Option<String>,
    /// The request's server principal.
    pub server: Option<String>,
    /// The reply's Kerberos error code, 0 on success.
    pub error_code: i32,
    /// `tkt_in_id`.
    pub tkt_in_id: Option<String>,
    /// `tkt_out_id`.
    pub tkt_out_id: Option<String>,
    /// `evid_tkt_id`.
    pub evid_tkt_id: Option<String>,
    /// `cl_realm`.
    pub cl_realm: Option<String>,
    /// `s4u2self_user`.
    pub s4u2self_user: Option<String>,
    /// `violation`.
    pub violation: i32,
}

impl AuditState {
    /// `kau_init_kdc_req`.
    pub fn new(peer: Option<std::net::SocketAddr>) -> Self {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let req_id = (0..31)
            .map(|_| CHARS[rand::random_range(0..CHARS.len())] as char)
            .collect();
        Self {
            req_id,
            cl_addr: peer.map(|p| p.ip()),
            cl_port: peer.map_or(0, |p| p.port()),
            ..Self::default()
        }
    }
}

/// `kau_make_tkt_id`: the upper-case hex SHA-256 of a ticket's ciphertext.
pub fn ticket_id(ciphertext: &[u8]) -> String {
    Sha256::digest(ciphertext)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect()
}

/// An audit module (`krb5_audit_vtable`). Errors are ignored, as in MIT.
pub trait Audit: Send + Sync {
    /// The module name.
    fn name(&self) -> &str;

    /// `open`: an error stops the KDC.
    fn open(&self) -> Result<(), i32> {
        Ok(())
    }

    /// `close`, when the KDC unloads the module.
    fn close(&self) {}
    /// `kdc_start`.
    fn kdc_start(&self, _success: bool) {}
    /// `kdc_stop`.
    fn kdc_stop(&self, _success: bool) {}
    /// `as_req`.
    fn as_req(&self, _success: bool, _state: &AuditState) {}
    /// `tgs_req`.
    fn tgs_req(&self, _success: bool, _state: &AuditState) {}
    /// `tgs_s4u2self`.
    fn s4u2self(&self, _success: bool, _state: &AuditState) {}
    /// `tgs_s4u2proxy`.
    fn s4u2proxy(&self, _success: bool, _state: &AuditState) {}
    /// `tgs_u2u`.
    fn u2u(&self, _success: bool, _state: &AuditState) {}
}

/// `KRB5_KDB_FLAG_*` values (kdb.h) in [`AuthdataRequest::flags`].
pub mod kdb_flags {
    /// `KRB5_KDB_FLAG_REFERRAL_OK`.
    pub const REFERRAL_OK: i32 = 0x10;
    /// `KRB5_KDB_FLAG_CLIENT`.
    pub const CLIENT: i32 = 0x40;
    /// `KRB5_KDB_FLAG_PROTOCOL_TRANSITION`.
    pub const PROTOCOL_TRANSITION: i32 = 0x100;
    /// `KRB5_KDB_FLAG_CONSTRAINED_DELEGATION`.
    pub const CONSTRAINED_DELEGATION: i32 = 0x200;
    /// `KRB5_KDB_FLAG_USER_TO_USER`.
    pub const USER_TO_USER: i32 = 0x800;
    /// `KRB5_KDB_FLAG_CROSS_REALM`.
    pub const CROSS_REALM: i32 = 0x1000;
    /// `KRB5_KDB_FLAG_ISSUING_REFERRAL`.
    pub const ISSUING_REFERRAL: i32 = 0x4000;
}

/// `KRB5_AS_REQ`.
pub const MSG_AS_REQ: i32 = 10;
/// `KRB5_TGS_REQ`.
pub const MSG_TGS_REQ: i32 = 12;

/// A principal and its realm.
pub type Principal = (crate::types::PrincipalName, String);

/// The arguments of `krb5_kdcauthdata_handle_fn` other than the reply
/// ticket.
#[derive(Debug, Clone, Default)]
pub struct AuthdataRequest {
    /// `flags`: [`kdb_flags`].
    pub flags: i32,
    /// [`MSG_AS_REQ`] or [`MSG_TGS_REQ`] (`req->msg_type`).
    pub msg_type: i32,
    /// `client`: the client's database entry, if it has one.
    pub client: Option<Principal>,
    /// `server`.
    pub server: Option<Principal>,
    /// `header_server`: for TGS, the server of the header or evidence
    /// ticket.
    pub header_server: Option<Principal>,
    /// `client_key`: the client's long-term key (AS) or the TGS reply key
    /// (subkey or header ticket session key).
    pub client_key: Option<crate::types::EncryptionKey>,
    /// `server_key`: the key the new ticket is encrypted in.
    pub server_key: Option<crate::types::EncryptionKey>,
    /// `header_key`: for TGS, the key of the header or evidence ticket.
    pub header_key: Option<crate::types::EncryptionKey>,
    /// `req_pkt`: the DER request.
    pub req_pkt: Vec<u8>,
    /// `for_user_princ`: the S4U client.
    pub for_user: Option<Principal>,
    /// `enc_tkt_req`: for TGS, the header or evidence ticket.
    pub enc_tkt_req: Option<crate::types::EncTicketPart>,
    /// The database entry of [`Self::client`] (`client`), if it has one.
    pub client_entry: Option<super::PrincipalEntry>,
    /// The database entry of [`Self::server`] (`server`).
    pub server_entry: Option<super::PrincipalEntry>,
    /// The database entry of [`Self::header_server`] (`header_server`).
    pub header_server_entry: Option<super::PrincipalEntry>,
}

/// A KDC authdata module (`krb5_kdcauthdata_vtable`).
pub trait KdcAuthdata: Send + Sync {
    /// The module name.
    fn name(&self) -> &str;
    /// `init`: an error skips the module, as in MIT.
    fn init(&self) -> Result<(), i32> {
        Ok(())
    }
    /// `fini`.
    fn fini(&self) {}
    /// `handle`: may add authorization data to `reply`. An error is
    /// logged by the KDC and the ticket is issued anyway, as in MIT
    /// (kdc_authdata.c:601-612).
    fn handle(
        &self,
        req: &AuthdataRequest,
        reply: &mut crate::types::EncTicketPart,
    ) -> Result<(), i32>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(&'static str, PolicyLimits, bool);

    impl KdcPolicy for Fixed {
        fn name(&self) -> &str {
            self.0
        }
        fn check_as(&self, _req: &PolicyRequest) -> Result<PolicyLimits, PolicyRefusal> {
            if self.2 {
                return Err(PolicyRefusal {
                    code: KDC_ERR_POLICY,
                    status: "LOCAL_POLICY".into(),
                });
            }
            Ok(self.1)
        }
    }

    #[test]
    fn modules_cap_times_and_first_refusal_wins() {
        let l = |lifetime, renew_lifetime| PolicyLimits {
            lifetime,
            renew_lifetime,
        };
        let mods: Vec<Arc<dyn KdcPolicy>> = vec![
            Arc::new(Fixed("a", l(7 * 3600, 0), false)),
            Arc::new(Fixed("b", l(0, 2 * 3600), false)),
        ];
        let (mut end, mut till) = (1000 + 86400, 1000 + 7 * 86400);
        let req = PolicyRequest::default();
        check_policy(&mods, false, &req, 1000, &mut end, &mut till).expect("allowed");
        assert_eq!((end, till), (1000 + 7 * 3600, 1000 + 2 * 3600));
        // A larger grant never extends a time.
        update_ticket_times(&mut end, &mut till, 1000, l(86400, 86400));
        assert_eq!((end, till), (1000 + 7 * 3600, 1000 + 2 * 3600));
        let mods: Vec<Arc<dyn KdcPolicy>> = vec![
            Arc::new(Fixed("deny", l(0, 0), true)),
            Arc::new(Fixed("never", l(1, 1), false)),
        ];
        let e = check_policy(&mods, false, &req, 0, &mut end, &mut till).expect_err("refused");
        assert_eq!(e.status, "LOCAL_POLICY");
        assert_eq!((end, till), (1000 + 7 * 3600, 1000 + 2 * 3600));
    }

    #[test]
    fn ticket_ids_are_upper_hex_sha256() {
        assert_eq!(
            ticket_id(b""),
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        );
        let s = AuditState::new(None);
        assert_eq!(s.req_id.len(), 31);
        assert!(s.req_id.bytes().all(|b| b.is_ascii_alphanumeric()));
    }
}
