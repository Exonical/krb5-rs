//! Shared KDC reply helpers for the AS and TGS state machines
//! (decode_kdc.c): KRB-ERROR decode checks and enc-part decrypt+decode.

use super::credential::{Credential, TicketTimes};
use crate::crypto::find_etype;
use crate::types::{
    EncAsRepPart, EncKdcRepPart, EncTgsRepPart, EncryptedData, EncryptionKey, KdcRep, KrbErrorMsg,
};
use crate::Krb5Error;

/// Decode a KRB-ERROR, checking pvno/msg-type (decode_kdc.c).
pub(crate) fn decode_krb_error(bytes: &[u8]) -> Result<KrbErrorMsg, Krb5Error> {
    let err: KrbErrorMsg = rasn::der::decode(bytes)?;
    if err.pvno != 5 || err.msg_type != 30 {
        return Err(Krb5Error::ReplyValidation(
            "invalid KRB-ERROR pvno/msg_type",
        ));
    }
    Ok(err)
}

/// Decode an AS-REP enc-part: EncAsRepPart [APPLICATION 25], then
/// EncTgsRepPart [APPLICATION 26] (some KDCs, e.g. Heimdal, use 26 for
/// AS-REP).
pub(crate) fn decode_enc_as_rep_part(plaintext: &[u8]) -> Result<EncKdcRepPart, Krb5Error> {
    if let Ok(enc_as) = rasn::der::decode::<EncAsRepPart>(plaintext) {
        return Ok(enc_as.0);
    }
    let enc_tgs: EncTgsRepPart = rasn::der::decode(plaintext)?;
    Ok(enc_tgs.0)
}

/// Decode a TGS-REP enc-part: EncTgsRepPart [APPLICATION 26], then a bare
/// `EncKdcRepPart` (Heimdal interop).
pub(crate) fn decode_enc_tgs_rep_part(plaintext: &[u8]) -> Result<EncKdcRepPart, Krb5Error> {
    if let Ok(enc_tgs) = rasn::der::decode::<EncTgsRepPart>(plaintext) {
        return Ok(enc_tgs.0);
    }
    rasn::der::decode::<EncKdcRepPart>(plaintext).map_err(Krb5Error::Asn1Decode)
}

/// Decrypt a KDC-REP enc-part trying each `(key, usage)` candidate in
/// order; the first candidate whose plaintext decodes via `decode` wins.
///
/// AS uses a single candidate (reply key, usage 3) with
/// [`decode_enc_as_rep_part`]; TGS tries the subkey (usage 9) then the TGT
/// session key (usage 8) with [`decode_enc_tgs_rep_part`].
pub(crate) fn decrypt_enc_kdc_rep_part(
    key_usages: &[(EncryptionKey, i32)],
    enc_part: &EncryptedData,
    decode: fn(&[u8]) -> Result<EncKdcRepPart, Krb5Error>,
) -> Result<EncKdcRepPart, Krb5Error> {
    let etype = enc_part.etype;
    let profile = find_etype(etype).map_err(|_| Krb5Error::UnsupportedEtype(etype))?;
    let mut last_err = Krb5Error::DecryptionFailed;
    for (key, usage) in key_usages {
        match profile.decrypt(key.key_bytes(), *usage, enc_part.cipher.as_ref()) {
            Ok(plaintext) => match decode(&plaintext) {
                Ok(part) => return Ok(part),
                Err(e) => last_err = e,
            },
            Err(_) => last_err = Krb5Error::DecryptionFailed,
        }
    }
    Err(last_err)
}

/// Build a client `Credential` from a decoded KDC-REP and its decrypted
/// enc-part — identical for AS-REP and TGS-REP.
pub(crate) fn credential_from_rep(rep: &KdcRep, enc_part: &EncKdcRepPart) -> Credential {
    Credential {
        client: rep.cname.clone(),
        crealm: String::from_utf8_lossy(rep.crealm.as_bytes()).to_string(),
        server: enc_part.sname.clone(),
        srealm: String::from_utf8_lossy(enc_part.srealm.as_bytes()).to_string(),
        session_key: enc_part.key.clone(),
        times: TicketTimes {
            authtime: enc_part.authtime,
            starttime: enc_part.starttime,
            endtime: enc_part.endtime,
            renew_till: enc_part.renew_till,
        },
        ticket: rep.ticket.clone(),
        flags: enc_part.flags,
        addresses: enc_part.caddr.clone(),
        authdata: None,
    }
}
