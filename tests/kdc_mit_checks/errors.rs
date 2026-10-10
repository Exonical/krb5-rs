//! Dispatch-level errors (dispatch.c:89-175).

use super::*;

#[test]
fn dispatch_garbage_bytes_return_msg_type_error() {
    let f = fixture();
    for input in [&[0x01u8, 0x02, 0x03][..], &[][..], &[0x30, 0x00][..]] {
        let err = krb_error(&f.kdc.handle(input));
        assert_eq!(err.error_code, 40, "input {input:?}");
        assert_eq!(err.realm.as_bytes(), REALM.as_bytes());
        assert_eq!(err.sname, krbtgt());
    }
}

#[test]
fn dispatch_ap_req_tag_returns_msg_type_error() {
    let f = fixture();
    let tgt = get_tgt(&f);
    let mut ctx = krb5_rs::protocol::ap::AuthContext::new();
    let ap_req = ctx
        .mk_req(&krb5_rs::protocol::ap::ApReqOptions::default(), None, &tgt)
        .expect("mk_req");
    assert_eq!(ap_req[0], 0x6E);
    assert_eq!(krb_error(&f.kdc.handle(&ap_req)).error_code, 40);
}

#[test]
fn dispatch_truncated_as_req_returns_generic_error() {
    let f = fixture();
    let req = build_as_req(USER, KdcOptions::empty(), vec![18], vec![]);
    let err = krb_error(&f.kdc.handle(&req[..req.len() / 2]));
    assert_eq!(err.error_code, 60);
}

#[test]
fn dispatch_bad_pvno_returns_bad_pvno() {
    let f = fixture();
    let mut req: AsReq =
        rasn::der::decode(&build_as_req(USER, KdcOptions::empty(), vec![18], vec![]))
            .expect("decode");
    req.0.pvno = 4;
    let der = rasn::der::encode(&req).expect("encode");
    assert_eq!(krb_error(&f.kdc.handle(&der)).error_code, 3);
}

#[test]
fn dispatch_as_req_with_tgs_msg_type_returns_generic_error() {
    let f = fixture();
    let mut req: AsReq =
        rasn::der::decode(&build_as_req(USER, KdcOptions::empty(), vec![18], vec![]))
            .expect("decode");
    req.0.msg_type = 12;
    let der = rasn::der::encode(&req).expect("encode");
    assert_eq!(krb_error(&f.kdc.handle(&der)).error_code, 60);
}

#[test]
fn dispatch_missing_local_krbtgt_returns_generic_error() {
    let mut store = MemoryStore::new();
    for (name, pw) in [(user(), PASSWORD), (service(), SERVICE_PASSWORD)] {
        store
            .add_with_password(name, REALM, pw, 1, &[18], PrincipalAttributes::empty())
            .expect("principal");
    }
    let kdc = Kdc::new(KdcConfig::new(REALM), store);
    let mut req: AsReq =
        rasn::der::decode(&build_as_req(USER, KdcOptions::empty(), vec![18], vec![]))
            .expect("decode");
    req.0.req_body.sname = Some(service());
    let der = rasn::der::encode(&req).expect("encode");
    // do_as_req.c:618-624 get_local_tgt failure -> KRB_ERR_GENERIC.
    assert_eq!(krb_error(&kdc.handle(&der)).error_code, 60);
}
