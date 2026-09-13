//! Credential retrieval matching — cc_retr.c.

use super::{CcCredential, CcError, MatchCred, MatchFlags};
use crate::types::{AuthorizationDataElement, PrincipalName};

/// Principal compare: realm + components; name type is NOT compared
/// (princ_comp.c).
fn princ_eq(p: &(PrincipalName, String), name: &PrincipalName, realm: &str) -> bool {
    p.1 == realm && p.0.name_string == name.name_string
}

/// krb5int_cc_creds_match_request (cc_retr.c:148-190).
pub fn creds_match_request(flags: MatchFlags, m: &MatchCred, c: &CcCredential) -> bool {
    // princs_match
    if let Some(client) = &m.client {
        if !princ_eq(client, &c.client, &c.crealm) {
            return false;
        }
    }
    if let Some(server) = &m.server {
        let ok = if flags.contains(MatchFlags::SRV_NAMEONLY) {
            server.0.name_string == c.server.name_string
        } else {
            princ_eq(server, &c.server, &c.srealm)
        };
        if !ok {
            return false;
        }
    }

    // Only match user-to-user creds when explicitly asked (cc_retr.c:160-164).
    let want_skey = flags.contains(MatchFlags::IS_SKEY) && m.is_skey;
    if c.is_skey != want_skey {
        return false;
    }

    if flags.contains(MatchFlags::FLAGS_EXACT) && m.ticket_flags != c.ticket_flags {
        return false;
    }
    if flags.contains(MatchFlags::FLAGS) && (c.ticket_flags & m.ticket_flags) != m.ticket_flags {
        return false;
    }

    if flags.contains(MatchFlags::TIMES_EXACT)
        && (m.authtime, m.starttime, m.endtime, m.renew_till)
            != (c.authtime, c.starttime, c.endtime, c.renew_till)
    {
        return false;
    }
    // times_match: requested expiration must not be later than stored.
    if flags.contains(MatchFlags::TIMES)
        && ((m.renew_till != 0 && m.renew_till > c.renew_till)
            || (m.endtime != 0 && m.endtime > c.endtime))
    {
        return false;
    }

    if flags.contains(MatchFlags::AUTHDATA) {
        let md: &[AuthorizationDataElement] = m.authdata.as_deref().unwrap_or(&[]);
        let cd: &[AuthorizationDataElement] = &c.authdata;
        let eq = md.len() == cd.len()
            && md
                .iter()
                .zip(cd.iter())
                .all(|(a, b)| a.ad_type == b.ad_type && a.ad_data == b.ad_data);
        if !eq {
            return false;
        }
    }

    if flags.contains(MatchFlags::SECOND_TKT) {
        let want: &[u8] = m.second_ticket.as_deref().unwrap_or(&[]);
        if want != &c.second_ticket[..] {
            return false;
        }
    }

    if flags.contains(MatchFlags::KTYPE) && m.etype != c.keyblock.keytype {
        return false;
    }

    true
}

/// krb5_cc_retrieve_cred_seq (cc_retr.c:195-251): first match, or with
/// `ktypes` the matching entry whose enctype appears earliest in the
/// list.  A match with no listed enctype yields NotKtype.
pub(crate) fn retrieve_in(
    creds: &[CcCredential],
    flags: MatchFlags,
    m: &MatchCred,
    ktypes: Option<&[i32]>,
) -> Result<CcCredential, CcError> {
    let mut best: Option<(usize, CcCredential)> = None;
    let mut nomatch = CcError::NotFound;
    for c in creds {
        if !creds_match_request(flags, m, c) {
            continue;
        }
        if let Some(ktypes) = ktypes {
            match ktypes.iter().position(|&t| t == c.keyblock.keytype) {
                None => nomatch = CcError::NotKtype,
                Some(pref) => {
                    if best.as_ref().is_none_or(|(p, _)| pref < *p) {
                        best = Some((pref, c.clone()));
                    }
                }
            }
        } else {
            return Ok(c.clone());
        }
    }
    match best {
        Some((_, c)) => Ok(c),
        None => Err(nomatch),
    }
}
