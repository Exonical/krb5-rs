//! Internal KDC error type and KRB-ERROR construction (MIT do_as_req.c
//! `prepare_error_as`, do_tgs_req.c `prepare_error_tgs`, kdc_util.c
//! `errcode_to_protocol`).

use chrono::{DateTime, Timelike, Utc};
use rasn::types::{GeneralString, OctetString};
use rasn::{AsnType, Decode, Decoder, Encode, Encoder};

use crate::protocol::ap::ApError;
use crate::types::error_codes::*;
use crate::types::{KrbErrorMsg, PaData, PrincipalName};
use crate::Krb5Error;

/// KRB_AP_ERR_ILL_CR_TKT (not in [`crate::types::error_codes`]).
pub(crate) const KRB_AP_ERR_ILL_CR_TKT: i32 = 43;

/// A KDC processing failure: protocol error code plus optional text/e-data.
#[derive(Debug, Clone)]
pub(crate) struct KdcError {
    /// KRB-ERROR error-code.
    pub code: i32,
    /// KRB-ERROR e-text (MIT status string).
    pub e_text: Option<String>,
    /// KRB-ERROR e-data.
    pub e_data: Option<Vec<u8>>,
    /// `e_data` is a METHOD-DATA list that goes on the wire as TYPED-DATA
    /// unless the error is armored (MIT `typed_e_data`, do_as_req.c:811-816).
    pub typed_e_data: bool,
}

impl KdcError {
    /// An error with a short status string.
    pub(crate) fn new(code: i32, text: &str) -> Self {
        Self {
            code,
            e_text: Some(text.to_string()),
            e_data: None,
            typed_e_data: false,
        }
    }

    /// `KRB_ERR_GENERIC` with a status string.
    pub(crate) fn generic(text: &str) -> Self {
        Self::new(KRB_ERR_GENERIC, text)
    }

    /// Attach e-data.
    pub(crate) fn with_e_data(mut self, e_data: Vec<u8>) -> Self {
        self.e_data = Some(e_data);
        self
    }

    #[cfg(feature = "pkinit")]
    /// Attach a typed e-data list (the elements plus the trailing
    /// PA-FX-COOKIE `prepare_error_as` appends, do_as_req.c:783-797).
    pub(crate) fn with_typed_e_data(mut self, items: Vec<PaData>) -> Result<Self, KdcError> {
        let mut list = items;
        list.push(PaData {
            padata_type: 133,
            padata_value: OctetString::from(b"MIT".to_vec()),
        });
        self.e_data = Some(rasn::der::encode(&list)?);
        self.typed_e_data = true;
        Ok(self)
    }
}

impl From<rasn::error::EncodeError> for KdcError {
    fn from(_: rasn::error::EncodeError) -> Self {
        Self::generic("ENCODE_FAILURE")
    }
}

impl From<Krb5Error> for KdcError {
    fn from(e: Krb5Error) -> Self {
        match e {
            Krb5Error::Ap(a) => Self::new(ap_error_code(a), "AP_ERROR"),
            _ => Self::generic("INTERNAL_ERROR"),
        }
    }
}

/// Protocol code for an AP-layer error (`errcode_to_protocol`, kdc_util.c:
/// 692-698; codes outside the protocol range become `KRB_ERR_GENERIC`).
pub(crate) fn ap_error_code(e: ApError) -> i32 {
    match e {
        ApError::BadIntegrity => KRB_AP_ERR_BAD_INTEGRITY,
        ApError::TktExpired => KRB_AP_ERR_TKT_EXPIRED,
        ApError::TktNyv | ApError::TktInvalid => KRB_AP_ERR_TKT_NYV,
        ApError::Repeat => KRB_AP_ERR_REPEAT,
        ApError::NotUs => KRB_AP_ERR_NOT_US,
        ApError::BadMatch => KRB_AP_ERR_BADMATCH,
        ApError::Skew => KRB_AP_ERR_SKEW,
        ApError::BadAddr => KRB_AP_ERR_BADADDR,
        ApError::BadVersion => KRB_AP_ERR_BADVERSION,
        ApError::MsgType => KRB_AP_ERR_MSG_TYPE,
        ApError::Modified => KRB_AP_ERR_MODIFIED,
        ApError::BadOrder => KRB_AP_ERR_BADORDER,
        ApError::BadKeyver => KRB_AP_ERR_BADKEYVER,
        ApError::NoKey => KRB_AP_ERR_NOKEY,
        ApError::MutualFailed => KRB_AP_ERR_MUT_FAIL,
        ApError::InappCksum => KRB_AP_ERR_INAPP_CKSUM,
        ApError::SumTypeNoSupp => KDC_ERR_SUMTYPE_NOSUPP,
        ApError::IllCrTkt => KRB_AP_ERR_ILL_CR_TKT,
        ApError::NoPermEtype | ApError::LocalAddrRequired | ApError::NoTktSupplied => {
            KRB_ERR_GENERIC
        }
    }
}

/// Request-derived fields echoed in a KRB-ERROR.
#[derive(Debug, Clone)]
pub(crate) struct ErrorContext {
    /// Server realm (KRB-ERROR `realm`).
    pub realm: String,
    /// Server name (KRB-ERROR `sname`).
    pub sname: PrincipalName,
    /// Client realm, if known.
    pub crealm: Option<String>,
    /// Client name, if known.
    pub cname: Option<PrincipalName>,
    /// FAST state once an armor key exists (errors are then armored).
    pub fast: Option<super::fast::KdcFastState>,
}

/// A failure bundled with the context for its KRB-ERROR.
#[derive(Debug, Clone)]
pub(crate) struct Failure {
    /// The error.
    pub err: KdcError,
    /// KRB-ERROR echo fields.
    pub ctx: ErrorContext,
}

/// Convert text to a GeneralString.
pub(crate) fn general_string(s: &str) -> Result<GeneralString, KdcError> {
    GeneralString::from_bytes(s.as_bytes()).map_err(|_| KdcError::generic("INVALID_STRING"))
}

/// `krbtgt/REALM` (name type NT-SRV-INST).
pub(crate) fn krbtgt_name(realm: &str) -> Result<PrincipalName, KdcError> {
    Ok(PrincipalName {
        name_type: 2,
        name_string: vec![general_string("krbtgt")?, general_string(realm)?],
    })
}

/// Build a DER KRB-ERROR (MIT krb5_mk_error as used by prepare_error_as /
/// prepare_error_tgs: ctime/cusec unset, stime/susec = KDC time). With an
/// armor key the error is wrapped per `kdc_fast_handle_error`
/// (fast_util.c:364-424) and, if requested, the client is hidden
/// (do_as_req.c:831-832, do_tgs_req.c:235-236).
pub(crate) fn build_krb_error(err: &KdcError, ctx: &ErrorContext, now: DateTime<Utc>) -> Vec<u8> {
    let fallback = |s: &str| GeneralString::from_bytes(s.as_bytes()).unwrap_or_default();
    let make = |crealm: Option<&str>, cname: Option<&PrincipalName>, e_data: Option<Vec<u8>>| {
        KrbErrorMsg {
            pvno: 5,
            msg_type: 30,
            ctime: None,
            cusec: None,
            // RFC 4120 §5.2.3: no fractional seconds (MIT rejects them).
            stime: now.with_nanosecond(0).unwrap_or(now).fixed_offset(),
            susec: i32::try_from(now.timestamp_subsec_micros()).unwrap_or(0),
            error_code: err.code,
            crealm: crealm.map(fallback),
            cname: cname.cloned(),
            realm: fallback(&ctx.realm),
            sname: ctx.sname.clone(),
            e_text: err.e_text.as_deref().map(fallback),
            e_data: e_data.map(OctetString::from),
        }
    };

    let mut crealm = ctx.crealm.clone();
    let mut cname = ctx.cname.clone();
    let mut e_data = err.e_data.clone();
    if let Some(state) = ctx.fast.as_ref().filter(|s| s.armor_key.is_some()) {
        let in_padata: Vec<PaData> = err
            .e_data
            .as_deref()
            .and_then(|d| rasn::der::decode(d).ok())
            .unwrap_or_default();
        let inner = make(ctx.crealm.as_deref(), ctx.cname.as_ref(), None);
        if let Ok(outer) = super::fast::wrap_error(state, &inner, in_padata) {
            e_data = Some(outer);
            if state.hide_client() && cname.is_some() {
                if let Ok((realm, name)) = super::fast::anonymous_client() {
                    crealm = Some(realm);
                    cname = Some(name);
                }
            }
        }
    }
    if err.typed_e_data && ctx.fast.as_ref().is_none_or(|s| s.armor_key.is_none()) {
        e_data = err.e_data.as_deref().and_then(typed_data_from_method_data);
    }
    rasn::der::encode(&make(crealm.as_deref(), cname.as_ref(), e_data)).unwrap_or_default()
}

/// TYPED-DATA element: `{ data-type [0], data-value [1] }`.
#[derive(AsnType, Encode, Decode)]
struct TypedDataElement {
    #[rasn(tag(explicit(context, 0)))]
    data_type: i32,
    #[rasn(tag(explicit(context, 1)))]
    data_value: Option<OctetString>,
}

/// Re-encode METHOD-DATA as TYPED-DATA (`encode_krb5_typed_data`).
fn typed_data_from_method_data(method_data: &[u8]) -> Option<Vec<u8>> {
    let list: Vec<PaData> = rasn::der::decode(method_data).ok()?;
    let typed: Vec<TypedDataElement> = list
        .into_iter()
        .map(|p| TypedDataElement {
            data_type: p.padata_type,
            data_value: Some(p.padata_value),
        })
        .collect();
    rasn::der::encode(&typed).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ap_error_code_maps_protocol_codes() {
        assert_eq!(ap_error_code(ApError::TktExpired), 32);
        assert_eq!(ap_error_code(ApError::BadIntegrity), 31);
        assert_eq!(ap_error_code(ApError::Skew), 37);
        assert_eq!(ap_error_code(ApError::BadKeyver), 44);
        assert_eq!(ap_error_code(ApError::NoKey), 45);
        assert_eq!(ap_error_code(ApError::NoPermEtype), 60);
    }

    #[test]
    fn build_krb_error_stime_has_no_fractional_seconds() {
        let ctx = ErrorContext {
            realm: "R".into(),
            sname: krbtgt_name("R").expect("name"),
            crealm: None,
            cname: None,
            fast: None,
        };
        let now = DateTime::<Utc>::from_timestamp(1_700_000_000, 731_854_900).expect("time");
        let der = build_krb_error(&KdcError::new(6, "X"), &ctx, now);
        assert!(
            !der.contains(&b'.'),
            "GeneralizedTime must not carry a fraction"
        );
        let got: KrbErrorMsg = rasn::der::decode(&der).expect("decode");
        assert_eq!(got.stime.timestamp_subsec_nanos(), 0);
        assert_eq!(got.susec, 731_854);
    }

    #[test]
    fn build_krb_error_roundtrips_fields() {
        let ctx = ErrorContext {
            realm: "R".into(),
            sname: krbtgt_name("R").expect("name"),
            crealm: None,
            cname: None,
            fast: None,
        };
        let der = build_krb_error(&KdcError::new(6, "CLIENT_NOT_FOUND"), &ctx, Utc::now());
        let got: KrbErrorMsg = rasn::der::decode(&der).expect("decode");
        assert_eq!(got.error_code, 6);
        assert_eq!(got.msg_type, 30);
        assert!(got.ctime.is_none() && got.cusec.is_none());
        assert_eq!(
            got.e_text.as_ref().map(|t| t.as_bytes().to_vec()),
            Some(b"CLIENT_NOT_FOUND".to_vec())
        );
    }
}
