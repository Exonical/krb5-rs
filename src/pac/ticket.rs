//! Ticket-level PAC signing and verification (MIT pac_sign.c
//! `krb5_kdc_sign_ticket`, pac.c `krb5_kdc_verify_ticket`).

use super::*;

/// `k5_pac_should_have_ticket_signature` (pac.c:579-588): not for TGS or
/// `kadmin/changepw` principals (MS-PAC 2.8.3).
pub(crate) fn should_have_ticket_signature(server: &PrincipalName) -> bool {
    let n = &server.name_string;
    if n.len() == 2 && n[0].as_bytes() == b"krbtgt" {
        return false;
    }
    !(n.len() == 2 && n[0].as_bytes() == b"kadmin" && n[1].as_bytes() == b"changepw")
}

fn if_relevant(list: &[AuthorizationDataElement]) -> Result<AuthorizationDataElement> {
    let der = rasn::der::encode(&list.to_vec())
        .map_err(|e| PacError::Generic(format!("encoding authdata: {e}")))?;
    Ok(AuthorizationDataElement {
        ad_type: AD_IF_RELEVANT,
        ad_data: der.into(),
    })
}

fn pac_element(data: Vec<u8>) -> AuthorizationDataElement {
    AuthorizationDataElement {
        ad_type: AD_WIN2K_PAC,
        ad_data: data.into(),
    }
}

fn encode_enc_tkt(enc: &EncTicketPart) -> Result<Vec<u8>> {
    rasn::der::encode(enc).map_err(|e| PacError::Generic(format!("encoding ticket: {e}")))
}

#[cfg_attr(
    not(any(feature = "kdc", test)),
    expect(dead_code, reason = "used by the KDC")
)]
/// `krb5_kdc_sign_ticket` (pac_sign.c:331-402): put a PAC signed for
/// `server_key` first in the ticket's authorization data. The ticket
/// signature (service tickets only) covers the ticket encoded with a
/// one-byte dummy PAC in that position.
pub(crate) fn kdc_sign_ticket(
    enc_tkt: &mut EncTicketPart,
    pac: &mut Pac,
    server_princ: &PrincipalName,
    client: Option<(&PrincipalName, &str)>,
    server_key: &EncryptionKey,
    privsvr_key: &EncryptionKey,
    with_realm: bool,
) -> Result<()> {
    let dummy = if_relevant(&[pac_element(vec![0])])?;
    let mut list = enc_tkt.authorization_data.take().unwrap_or_default();
    list.insert(0, dummy);
    enc_tkt.authorization_data = Some(list);

    let is_service_tkt = should_have_ticket_signature(server_princ);
    if is_service_tkt {
        let der = encode_enc_tkt(enc_tkt)?;
        let (cksumtype, _) = pac.insert_checksum(PAC_TICKET_CHECKSUM, privsvr_key)?;
        pac.write_checksum(PAC_TICKET_CHECKSUM, privsvr_key, cksumtype, &der)?;
    }
    let data = pac.sign_pac(
        enc_tkt.authtime.timestamp(),
        client,
        server_key,
        privsvr_key,
        with_realm,
        is_service_tkt,
    )?;
    let real = if_relevant(&[pac_element(data)])?;
    if let Some(list) = enc_tkt.authorization_data.as_mut() {
        list[0] = real;
    }
    Ok(())
}

/// Locate the first AD-IF-RELEVANT container holding a PAC element:
/// (container index, decoded container, PAC element index).
fn find_pac(
    authdata: &[AuthorizationDataElement],
) -> Result<Option<(usize, Vec<AuthorizationDataElement>, usize)>> {
    for (i, el) in authdata.iter().enumerate() {
        if el.ad_type != AD_IF_RELEVANT {
            continue;
        }
        let inner = decode_if_relevant(el)?;
        if let Some(j) = inner.iter().position(|e| e.ad_type == AD_WIN2K_PAC) {
            return Ok(Some((i, inner, j)));
        }
    }
    Ok(None)
}

/// `krb5_kdc_verify_ticket` (pac.c:590-675): verify the PAC in a decrypted
/// ticket. With a `privsvr` key and a service-ticket server the ticket
/// checksum is checked over the ticket re-encoded with the PAC replaced by
/// one zero byte; the PAC checksums follow. `Ok(None)` if there is no PAC.
pub(crate) fn kdc_verify_ticket(
    enc_tkt: &EncTicketPart,
    server_princ: &PrincipalName,
    server: &EncryptionKey,
    privsvr: Option<&EncryptionKey>,
) -> Result<Option<Pac>> {
    let Some(authdata) = enc_tkt.authorization_data.as_deref() else {
        return Ok(None);
    };
    let Some((i, mut inner, j)) = find_pac(authdata)? else {
        return Ok(None);
    };
    let pac = Pac::parse(inner[j].ad_data.as_ref())?;
    let is_service_tkt = should_have_ticket_signature(server_princ);
    if let (Some(privsvr), true) = (privsvr, is_service_tkt) {
        inner[j] = pac_element(vec![0]);
        let mut recoded = enc_tkt.clone();
        if let Some(list) = recoded.authorization_data.as_mut() {
            list[i] = if_relevant(&inner)?;
        }
        let der = encode_enc_tkt(&recoded)?;
        pac.verify_checksum(PAC_TICKET_CHECKSUM, privsvr, &der)?;
    }
    pac.verify_checksums(is_service_tkt, Some(server), privsvr)?;
    Ok(Some(pac))
}
