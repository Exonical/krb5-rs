//! JSON encoding of KDC audit events, as MIT's `plugins/audit/kdc_j_encode.c`
//! does with `k5_json_encode` (`util/support/json.c`): keys in insertion
//! order, no whitespace, and MIT's string escaping.

use super::{AuditAddress, AuditPrincipal, AuditReply, AuditRequest, AuditState};

const ADDRTYPE_INET: i32 = 2;
const ADDRTYPE_INET6: i32 = 24;
const ADDRTYPE_UNIXSOCK: i32 = 0x8000 | 0x0001;
const KDC_OPT_RENEW: i32 = 0x0000_0002;
const KDC_OPT_VALIDATE: i32 = 0x0000_0001;
const T_RENEWED: i64 = 1;
const T_NOT_RENEWED: i64 = 2;
const T_VALIDATED: i64 = 1;
const T_NOT_VALIDATED: i64 = 2;

enum Value {
    Str(Vec<u8>),
    Num(i64),
    Bool(bool),
    Arr(Vec<Value>),
    Obj(Obj),
}

/// `k5_json_object`: setting an existing key replaces its value in place.
#[derive(Default)]
struct Obj(Vec<(&'static str, Value)>);

impl Obj {
    fn set(&mut self, key: &'static str, v: Value) {
        match self.0.iter_mut().find(|(k, _)| *k == key) {
            Some(e) => e.1 = v,
            None => self.0.push((key, v)),
        }
    }
    /// `string_to_value`: nothing for `NULL`.
    fn string(&mut self, key: &'static str, s: Option<&str>) {
        if let Some(s) = s {
            self.set(key, Value::Str(s.as_bytes().to_vec()));
        }
    }
    /// `data_to_value`: nothing for empty data.
    fn data(&mut self, key: &'static str, d: &[u8]) {
        if !d.is_empty() {
            self.set(key, Value::Str(d.to_vec()));
        }
    }
    fn int(&mut self, key: &'static str, n: i64) {
        self.set(key, Value::Num(n));
    }
    fn bool(&mut self, key: &'static str, b: bool) {
        self.set(key, Value::Bool(b));
    }
    /// `princ_to_value`.
    fn princ(&mut self, key: &'static str, p: Option<&AuditPrincipal>) {
        let Some(p) = p else { return };
        let mut o = Obj::default();
        o.set(
            "components",
            Value::Arr(p.components.iter().map(|c| Value::Str(c.clone())).collect()),
        );
        o.data("realm", &p.realm);
        o.int("length", p.components.len() as i64);
        o.int("type", i64::from(p.name_type));
        self.set(key, Value::Obj(o));
    }
    /// `eventinfo_to_value`.
    fn event(&mut self, name: &str, stage: i32, ok: bool) {
        self.string("event_name", Some(name));
        self.int("stage", i64::from(stage));
        self.bool("event_success", ok);
    }
    fn encode(self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_value(&mut out, &Value::Obj(self));
        out
    }
}

/// `encode_string`: the string ends at the first NUL, as a C string does.
fn encode_string(out: &mut Vec<u8>, s: &[u8]) {
    out.push(b'"');
    for &c in s.iter().take_while(|&&c| c != 0) {
        match c {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0c => out.extend_from_slice(b"\\f"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            c if c < 0x20 => out.extend_from_slice(format!("\\u00{c:02X}").as_bytes()),
            c => out.push(c),
        }
    }
    out.push(b'"');
}

fn encode_value(out: &mut Vec<u8>, v: &Value) {
    match v {
        Value::Str(s) => encode_string(out, s),
        Value::Num(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Value::Arr(a) => {
            out.push(b'[');
            for (i, v) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                encode_value(out, v);
            }
            out.push(b']');
        }
        Value::Obj(o) => {
            out.push(b'{');
            for (i, (k, v)) in o.0.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                encode_string(out, k.as_bytes());
                out.push(b':');
                encode_value(out, v);
            }
            out.push(b'}');
        }
    }
}

/// `addr_to_obj`.
fn addr_obj(o: &mut Obj, (addrtype, contents): &AuditAddress) {
    if contents.is_empty() {
        return;
    }
    o.int("type", i64::from(*addrtype));
    o.int("length", contents.len() as i64);
    if *addrtype == ADDRTYPE_INET || *addrtype == ADDRTYPE_INET6 {
        let ip = contents.iter().map(|b| Value::Num(i64::from(*b))).collect();
        o.set("ip", Value::Arr(ip));
    } else if *addrtype == ADDRTYPE_UNIXSOCK {
        o.set("path", Value::Str(contents.clone()));
    }
}

/// `krb5_address` for the client's address, as `kau_init_kdc_req` copies it.
fn client_address(st: &AuditState) -> Option<AuditAddress> {
    Some(match st.cl_addr? {
        std::net::IpAddr::V4(a) => (ADDRTYPE_INET, a.octets().to_vec()),
        std::net::IpAddr::V6(a) => (ADDRTYPE_INET6, a.octets().to_vec()),
    })
}

/// `addr_to_value` and `fromport` for the client.
fn from(o: &mut Obj, st: &AuditState) {
    o.int("fromport", i64::from(st.cl_port));
    if let Some(a) = client_address(st) {
        let mut ao = Obj::default();
        addr_obj(&mut ao, &a);
        o.set("fromaddr", Value::Obj(ao));
    }
}

/// `map_patype`.
fn patype_name(t: i32) -> Option<&'static str> {
    Some(match t {
        2 => "ENC_TIMESTAMP",
        3 => "PW_SALT",
        5 => "ENC_UNIX_TIME",
        12 => "SAM_CHALLENGE",
        13 => "SAM_RESPONSE",
        14 => "PK_AS_REQ_OLD",
        15 => "PK_AS_REP_OLD",
        16 => "PK_AS_REQ",
        17 => "PK_AS_REP",
        19 => "ETYPE_INFO2",
        30 => "SAM_CHALLENGE_2",
        31 => "SAM_RESPONSE_2",
        128 => "PAC_REQUEST",
        129 => "FOR_USER",
        130 => "S4U_X509_USER",
        138 => "ENCRYPTED_CHALLENGE",
        141 => "OTP_CHALLENGE",
        142 => "OTP_REQUEST",
        144 => "OTP_PIN_CHANGE",
        _ => return None,
    })
}

fn pa_names(types: &[i32]) -> Value {
    Value::Arr(
        types
            .iter()
            .filter_map(|t| patype_name(*t))
            .map(|n| Value::Str(n.as_bytes().to_vec()))
            .collect(),
    )
}

/// `req_to_value`.
fn request(o: &mut Obj, req: Option<&AuditRequest>, ok: bool) {
    let Some(req) = req else { return };
    o.princ("req.client", req.client.as_ref());
    o.princ("req.server", req.server.as_ref());
    o.int("req.kdc_options", i64::from(req.kdc_options));
    o.int("req.tkt_start", i64::from(req.from));
    o.int("req.tkt_end", i64::from(req.till));
    o.int("req.tkt_renew_till", i64::from(req.rtime));
    let etypes = req
        .etypes
        .iter()
        .filter(|e| **e > 0)
        .map(|e| Value::Num(i64::from(*e)))
        .collect();
    o.set("req.avail_etypes", Value::Arr(etypes));
    if ok {
        if let Some(pa) = &req.pa_types {
            o.set("req.pa_type", pa_names(pa));
        }
    }
    if let Some(addrs) = &req.addresses {
        let list = addrs
            .iter()
            .map(|a| {
                let mut ao = Obj::default();
                addr_obj(&mut ao, a);
                Value::Obj(ao)
            })
            .collect();
        o.set("req.addresses", Value::Arr(list));
    }
}

/// `rep_to_value` and `tkt_to_value`.
fn reply(o: &mut Obj, rep: Option<&AuditReply>, ok: bool) {
    let Some(rep) = rep else { return };
    if !ok {
        if let Some(pa) = &rep.pa_types {
            o.set("rep.pa_type", pa_names(pa));
        }
        return;
    }
    if let Some(server) = &rep.ticket_server {
        let mut t = Obj::default();
        // MIT records the server as "cname" first; enc_part2 replaces it.
        t.princ("cname", Some(server));
        t.princ("sname", Some(server));
        if rep.ticket_etype != 0 {
            t.int("srv_etype", i64::from(rep.ticket_etype));
        }
        if let Some(p) = &rep.ticket_part {
            t.princ("cname", Some(&p.client));
            t.int("flags", i64::from(p.flags));
            t.int("sess_etype", i64::from(p.session_etype));
            t.int("start", i64::from(p.start));
            t.int("end", i64::from(p.end));
            t.int("renew_till", i64::from(p.renew_till));
            t.int("authtime", i64::from(p.authtime));
            t.data("tr_contents", &p.tr_contents);
        }
        o.set("rep.ticket", Value::Obj(t));
    }
    o.int("rep_etype", i64::from(rep.etype));
}

/// `kau_j_kdc_start`.
pub fn kdc_start(ok: bool) -> Vec<u8> {
    let mut o = Obj::default();
    o.string("event_name", Some("KDC_START"));
    o.bool("event_success", ok);
    o.encode()
}

/// `kau_j_kdc_stop`.
pub fn kdc_stop(ok: bool) -> Vec<u8> {
    let mut o = Obj::default();
    o.string("event_name", Some("KDC_STOP"));
    o.bool("event_success", ok);
    o.encode()
}

/// `kau_j_as_req`.
pub fn as_req(ok: bool, st: &AuditState) -> Vec<u8> {
    let mut o = Obj::default();
    o.event("AS_REQ", st.stage as i32, ok);
    o.string("tkt_out_id", st.tkt_out_id.as_deref());
    o.string("req_id", Some(&st.req_id));
    from(&mut o, st);
    o.string("kdc_status", st.status.as_deref());
    o.data(
        "clreferral_realm",
        st.cl_realm.as_deref().unwrap_or("").as_bytes(),
    );
    request(&mut o, st.request.as_ref(), ok);
    reply(&mut o, st.reply.as_ref(), ok);
    o.encode()
}

/// `kau_j_tgs_req`.
pub fn tgs_req(ok: bool, st: &AuditState) -> Vec<u8> {
    let mut o = Obj::default();
    o.event("TGS_REQ", st.stage as i32, ok);
    o.string("tkt_in_id", st.tkt_in_id.as_deref());
    o.string("tkt_out_id", st.tkt_out_id.as_deref());
    o.string("req_id", Some(&st.req_id));
    from(&mut o, st);
    let (mut renewed, mut validated) = (0, 0);
    if let (true, Some(req)) = (ok, &st.request) {
        renewed = if req.kdc_options & KDC_OPT_RENEW != 0 {
            T_RENEWED
        } else {
            T_NOT_RENEWED
        };
        validated = if req.kdc_options & KDC_OPT_VALIDATE != 0 {
            T_VALIDATED
        } else {
            T_NOT_VALIDATED
        };
    }
    o.int("tkt_renewed", renewed);
    o.int("tkt_validated", validated);
    o.string("kdc_status", st.status.as_deref());
    request(&mut o, st.request.as_ref(), ok);
    reply(&mut o, st.reply.as_ref(), ok);
    o.encode()
}

/// `kau_j_tgs_s4u2self`.
pub fn s4u2self(ok: bool, st: &AuditState) -> Vec<u8> {
    let mut o = Obj::default();
    o.event("S4U2SELF", st.stage as i32, ok);
    o.string("tkt_in_id", st.tkt_in_id.as_deref());
    o.string("tkt_out_id", st.tkt_out_id.as_deref());
    o.string("req_id", Some(&st.req_id));
    if !ok {
        o.string("kdc_status", st.status.as_deref());
        o.int("violation", i64::from(st.violation));
    }
    o.princ("s4u2self_user", st.s4u2self_principal.as_ref());
    o.encode()
}

fn second_ticket(st: &AuditState) -> Option<&(AuditPrincipal, i32)> {
    st.request.as_ref()?.second_ticket.as_ref()
}

/// `kau_j_tgs_s4u2proxy`.
pub fn s4u2proxy(ok: bool, st: &AuditState) -> Vec<u8> {
    let mut o = Obj::default();
    o.event("S4U2PROXY", st.stage as i32, ok);
    o.string("tkt_in_id", st.tkt_in_id.as_deref());
    o.string("tkt_out_id", st.tkt_out_id.as_deref());
    o.string("evidence_tkt_id", st.evid_tkt_id.as_deref());
    o.string("req_id", Some(&st.req_id));
    if !ok {
        o.string("kdc_status", st.status.as_deref());
        o.int("violation", i64::from(st.violation));
    }
    o.princ("s4u2proxy_user", second_ticket(st).map(|t| &t.0));
    o.encode()
}

/// `kau_j_tgs_u2u`.
pub fn u2u(ok: bool, st: &AuditState) -> Vec<u8> {
    let mut o = Obj::default();
    o.event("U2U", st.stage as i32, ok);
    o.string("tkt_in_id", st.tkt_in_id.as_deref());
    o.string("tkt_out_id", st.tkt_out_id.as_deref());
    o.string("req_id", Some(&st.req_id));
    if !ok {
        o.string("kdc_status", st.status.as_deref());
    }
    if let Some((client, etype)) = second_ticket(st) {
        o.princ("u2u_user", Some(client));
        o.int("srv_etype", i64::from(*etype));
    }
    o.encode()
}

#[cfg(test)]
mod tests {
    use super::super::{AuditStage, AuditTicketPart};
    use super::*;

    fn princ(c: &[&str], realm: &str) -> AuditPrincipal {
        AuditPrincipal {
            name_type: 1,
            components: c.iter().map(|c| c.as_bytes().to_vec()).collect(),
            realm: realm.as_bytes().to_vec(),
        }
    }

    fn state() -> AuditState {
        AuditState {
            req_id: "REQ".into(),
            cl_addr: Some("10.0.0.1".parse().expect("ip")),
            cl_port: 88,
            stage: AuditStage::EncrRep,
            status: Some("ISSUE".into()),
            tkt_in_id: Some("IN".into()),
            tkt_out_id: Some("OUT".into()),
            request: Some(AuditRequest {
                client: Some(princ(&["user"], "R")),
                server: Some(princ(&["krbtgt", "R"], "R")),
                kdc_options: 0x0000_0010,
                from: 0,
                till: 100,
                rtime: 0,
                etypes: vec![18, 17],
                pa_types: Some(vec![2, 149, 128]),
                addresses: None,
                second_ticket: None,
            }),
            reply: Some(AuditReply {
                ticket_server: Some(princ(&["krbtgt", "R"], "R")),
                ticket_etype: 18,
                ticket_part: Some(AuditTicketPart {
                    client: princ(&["user"], "R"),
                    flags: 0x0041_0000,
                    session_etype: 18,
                    start: 5,
                    end: 100,
                    renew_till: 0,
                    authtime: 5,
                    tr_contents: Vec::new(),
                }),
                etype: 18,
                pa_types: Some(vec![19]),
            }),
            ..AuditState::default()
        }
    }

    #[test]
    fn as_req_is_kau_j_as_req() {
        let p = r#"{"components":["user"],"realm":"R","length":1,"type":1}"#;
        let t = r#"{"components":["krbtgt","R"],"realm":"R","length":2,"type":1}"#;
        let want = format!(
            concat!(
                r#"{{"event_name":"AS_REQ","stage":5,"event_success":true,"tkt_out_id":"OUT","#,
                r#""req_id":"REQ","fromport":88,"fromaddr":{{"type":2,"length":4,"ip":[10,0,0,1]}},"#,
                r#""kdc_status":"ISSUE","req.client":{p},"req.server":{t},"req.kdc_options":16,"#,
                r#""req.tkt_start":0,"req.tkt_end":100,"req.tkt_renew_till":0,"#,
                r#""req.avail_etypes":[18,17],"req.pa_type":["ENC_TIMESTAMP","PAC_REQUEST"],"#,
                r#""rep.ticket":{{"cname":{p},"sname":{t},"srv_etype":18,"flags":4259840,"#,
                r#""sess_etype":18,"start":5,"end":100,"renew_till":0,"authtime":5}},"rep_etype":18}}"#
            ),
            p = p,
            t = t
        );
        assert_eq!(
            String::from_utf8(as_req(true, &state())).expect("utf8"),
            want
        );
    }

    #[test]
    fn failures_carry_reply_padata_not_the_ticket() {
        let mut st = state();
        st.stage = AuditStage::AuthnReqCl;
        st.status = Some("NEEDED_PREAUTH".into());
        let j = String::from_utf8(as_req(false, &st)).expect("utf8");
        assert!(
            j.contains(r#""req.avail_etypes":[18,17],"rep.pa_type":["ETYPE_INFO2"]}"#),
            "{j}"
        );
        assert!(!j.contains("rep.ticket") && !j.contains("req.pa_type"));
    }

    #[test]
    fn tgs_records_renewal_and_validation_only_on_success() {
        let mut st = state();
        st.request.as_mut().expect("req").kdc_options = KDC_OPT_RENEW;
        let ok = String::from_utf8(tgs_req(true, &st)).expect("utf8");
        assert!(ok.contains(r#""tkt_renewed":1,"tkt_validated":2,"#), "{ok}");
        let bad = String::from_utf8(tgs_req(false, &st)).expect("utf8");
        assert!(
            bad.contains(r#""tkt_renewed":0,"tkt_validated":0,"#),
            "{bad}"
        );
    }

    #[test]
    fn s4u_and_u2u_events() {
        let mut st = state();
        st.s4u2self_principal = Some(princ(&["alice"], "R"));
        st.violation = super::super::LOCAL_POLICY;
        st.evid_tkt_id = Some("EV".into());
        st.request.as_mut().expect("req").second_ticket = Some((princ(&["bob"], "R"), 17));
        assert_eq!(
            String::from_utf8(s4u2self(false, &st)).expect("utf8"),
            concat!(
                r#"{"event_name":"S4U2SELF","stage":5,"event_success":false,"tkt_in_id":"IN","#,
                r#""tkt_out_id":"OUT","req_id":"REQ","kdc_status":"ISSUE","violation":2,"#,
                r#""s4u2self_user":{"components":["alice"],"realm":"R","length":1,"type":1}}"#
            )
        );
        let p = String::from_utf8(s4u2proxy(true, &st)).expect("utf8");
        assert!(
            p.contains(
                r#""evidence_tkt_id":"EV","req_id":"REQ","s4u2proxy_user":{"components":["bob"]"#
            ),
            "{p}"
        );
        let u = String::from_utf8(u2u(true, &st)).expect("utf8");
        assert!(u.ends_with(r#""u2u_user":{"components":["bob"],"realm":"R","length":1,"type":1},"srv_etype":17}"#), "{u}");
    }

    #[test]
    fn strings_are_escaped_like_k5_json() {
        let mut out = Vec::new();
        encode_string(&mut out, b"a\"\\/\x08\x0c\n\r\t\x01b\0c");
        assert_eq!(out, br#""a\"\\/\b\f\n\r\t\u0001b""#.to_vec());
        assert_eq!(
            kdc_start(true),
            br#"{"event_name":"KDC_START","event_success":true}"#.to_vec()
        );
        assert_eq!(
            kdc_stop(false),
            br#"{"event_name":"KDC_STOP","event_success":false}"#.to_vec()
        );
    }
}
