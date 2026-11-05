//! OTP pre-authentication, KDC side (MIT `plugins/preauth/otp/main.c` and
//! `otp_state.c`): a PA-OTP-CHALLENGE for principals with an `otp` string
//! attribute, and PA-OTP-REQUEST checked by a RADIUS server per token.

use std::path::Path;
use std::time::Duration;

use rasn::types::OctetString;

use super::error::KdcError;
use crate::crypto::find_etype;
use crate::otp::{
    flags_to_bits, OtpTokenInfo, PaOtpChallenge, PaOtpEncRequest, PaOtpRequest,
    KEYUSAGE_PA_OTP_REQUEST, PA_OTP_CHALLENGE,
};
use crate::profile::Profile;
use crate::types::error_codes::*;
use crate::types::{EncryptionKey, PaData, PaEncTsEnc};

/// `DEFAULT_TYPE_NAME`.
pub const DEFAULT_TYPE_NAME: &str = "DEFAULT";
/// MIT `KDC_RUN_DIR` (osconf.hin:73, `RUNSTATEDIR` defaulting to
/// `$(localstatedir)/run`).
pub const KDC_RUN_DIR: &str = "/usr/local/var/run/krb5kdc";
const DEFAULT_TIMEOUT: i64 = 5;
const DEFAULT_RETRIES: i64 = 3;
const MAX_SECRET_LEN: usize = 1024;

/// An `[otp]` token type (`token_type`, otp_state.c:48-56).
#[derive(Clone, PartialEq, Eq)]
pub struct TokenType {
    /// Subsection name.
    pub name: String,
    /// RADIUS server: an absolute Unix socket path or `host[:port]`.
    pub server: String,
    /// Shared secret (empty for Unix sockets without `secret`).
    pub secret: String,
    /// Total time allowed for one RADIUS request.
    pub timeout: Duration,
    /// Retries per server address (UDP only).
    pub retries: usize,
    /// Send the principal without its realm as User-Name.
    pub strip_realm: bool,
    /// `indicator` values asserted on success.
    pub indicators: Vec<String>,
}

impl std::fmt::Debug for TokenType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenType")
            .field("name", &self.name)
            .field("server", &self.server)
            .field("timeout", &self.timeout)
            .field("retries", &self.retries)
            .field("strip_realm", &self.strip_realm)
            .field("indicators", &self.indicators)
            .finish_non_exhaustive()
    }
}

/// `token_type_default` (otp_state.c:144-176).
pub fn default_type() -> TokenType {
    TokenType {
        name: DEFAULT_TYPE_NAME.into(),
        server: format!("{KDC_RUN_DIR}/{DEFAULT_TYPE_NAME}.socket"),
        secret: String::new(),
        timeout: Duration::from_secs(DEFAULT_TIMEOUT as u64),
        retries: DEFAULT_RETRIES as usize,
        strip_realm: false,
        indicators: Vec::new(),
    }
}

/// `read_secret_file` (otp_state.c:95-141): the first line of the file,
/// relative to `KDC_DIR`, trimmed.
fn read_secret_file(kdc_dir: &Path, file: &str) -> Result<String, String> {
    use std::io::BufRead;
    let path = kdc_dir.join(file);
    let f = std::fs::File::open(&path)
        .map_err(|e| format!("Unable to open secret file '{}': {e}", path.display()))?;
    let mut line = Vec::new();
    std::io::BufReader::new(f)
        .take(MAX_SECRET_LEN as u64 - 1)
        .read_until(b'\n', &mut line)
        .map_err(|e| format!("Unable to read secret file '{}': {e}", path.display()))?;
    if line.is_empty() {
        return Err(format!("Unable to read secret file '{}'", path.display()));
    }
    let s = String::from_utf8_lossy(&line);
    Ok(s.trim_matches(|c: char| c.is_ascii_whitespace())
        .to_string())
}

use std::io::Read as _;

/// `token_types_decode` (otp_state.c:297-344) over the KDC profile
/// (kdc.conf, then krb5.conf): `DEFAULT` first unless configured, then
/// each `[otp]` subsection. An error disables the module, as a failed
/// `otp_init` does.
pub fn token_types(
    kdc_conf: &Profile,
    krb5_conf: Option<&Profile>,
    kdc_dir: &Path,
) -> Result<Vec<TokenType>, String> {
    let profiles: Vec<&Profile> = std::iter::once(kdc_conf).chain(krb5_conf).collect();
    let mut names: Vec<String> = Vec::new();
    for p in &profiles {
        for n in p.subsection_names(&["otp"]) {
            if !names.contains(&n) {
                names.push(n);
            }
        }
    }
    let pick = |path: &[&str]| {
        profiles
            .iter()
            .copied()
            .find(|p| p.get_string(path).is_some())
            .unwrap_or(kdc_conf)
    };
    let mut out = Vec::new();
    if !names.iter().any(|n| n == DEFAULT_TYPE_NAME) {
        out.push(default_type());
    }
    for name in names {
        let n = name.as_str();
        let strip_realm = pick(&["otp", n, "strip_realm"])
            .get_boolean(&["otp", n, "strip_realm"], true)
            .map_err(|e| e.to_string())?;
        let server = pick(&["otp", n, "server"])
            .get_string(&["otp", n, "server"])
            .unwrap_or_else(|| format!("{KDC_RUN_DIR}/{n}.socket"));
        let secret = match pick(&["otp", n, "secret"]).get_string(&["otp", n, "secret"]) {
            Some(file) => read_secret_file(kdc_dir, &file)?,
            None if server.starts_with('/') => String::new(),
            None => return Err(format!("Secret missing (token type '{n}')")),
        };
        let timeout = pick(&["otp", n, "timeout"])
            .get_integer(&["otp", n, "timeout"], DEFAULT_TIMEOUT)
            .map_err(|e| e.to_string())?;
        let retries = pick(&["otp", n, "retries"])
            .get_integer(&["otp", n, "retries"], DEFAULT_RETRIES)
            .map_err(|e| e.to_string())?;
        let indicators = pick(&["otp", n, "indicator"]).get_values(&["otp", n, "indicator"]);
        out.push(TokenType {
            name: name.clone(),
            server,
            secret,
            timeout: Duration::from_millis(
                u64::try_from(timeout.saturating_mul(1000)).unwrap_or(0),
            ),
            retries: usize::try_from(retries).unwrap_or(0),
            strip_realm,
            indicators,
        });
    }
    Ok(out)
}

/// One configured token (`token`, otp_state.c:58-62).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Token<'a> {
    ty: &'a TokenType,
    username: String,
    indicators: Option<Vec<String>>,
}

/// `tokens_decode` (otp_state.c:404-550): the `otp` attribute is a JSON
/// array of objects (`[{}]` when absent or empty) with optional `type`,
/// `username` and `indicators`.
fn tokens<'a>(
    types: &'a [TokenType],
    config: &str,
    principal: &str,
) -> Result<Vec<Token<'a>>, String> {
    use serde_json::Value;
    let val: Value = serde_json::from_str(config).map_err(|e| e.to_string())?;
    let mut arr = match val {
        Value::Array(a) => a,
        _ => return Err("otp config is not an array".into()),
    };
    if arr.is_empty() {
        arr.push(Value::Object(Default::default()));
    }
    let mut out = Vec::new();
    for v in arr {
        let Value::Object(obj) = v else {
            return Err("otp token is not an object".into());
        };
        let name = match obj.get("type") {
            Some(Value::String(s)) => s.as_str(),
            _ => DEFAULT_TYPE_NAME,
        };
        // The last type of that name (otp_state.c:422-425).
        let ty = types
            .iter()
            .rev()
            .find(|t| t.name == name)
            .ok_or_else(|| format!("unknown token type '{name}'"))?;
        let username = match obj.get("username") {
            Some(Value::String(s)) => s.clone(),
            _ if ty.strip_realm => strip_realm(principal).to_string(),
            _ => principal.to_string(),
        };
        let indicators = match obj.get("indicators") {
            None => None,
            Some(Value::Array(a)) => Some(
                a.iter()
                    .map(|i| match i {
                        Value::String(s) => Ok(s.clone()),
                        _ => Err("otp indicator is not a string".to_string()),
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            Some(_) => return Err("otp indicators is not an array".into()),
        };
        out.push(Token {
            ty,
            username,
            indicators,
        });
    }
    Ok(out)
}

/// The unparsed name without its realm (`KRB5_PRINCIPAL_UNPARSE_NO_REALM`):
/// everything before the last unescaped `@`.
fn strip_realm(name: &str) -> &str {
    let mut esc = false;
    let mut at = None;
    for (i, c) in name.char_indices() {
        match c {
            _ if esc => esc = false,
            '\\' => esc = true,
            '@' => at = Some(i),
            _ => {}
        }
    }
    at.map_or(name, |i| &name[..i])
}

/// `nonce_generate` (main.c:57-80): the KDC time, big-endian, then random
/// bytes the length of the armor key.
fn nonce(now: i64, len: usize) -> Vec<u8> {
    let mut n: Vec<u8> = (0..4 + len).map(|_| rand::random::<u8>()).collect();
    n[..4].copy_from_slice(&(now as u32).to_be_bytes());
    n
}

/// `otp_edata` (main.c:219-275): one empty token info.
pub(crate) fn challenge(armor: &EncryptionKey, now: i64) -> Result<PaData, KdcError> {
    let chl = PaOtpChallenge {
        nonce: OctetString::from(nonce(now, armor.key_bytes().len())),
        service: None,
        tokeninfo: vec![OtpTokenInfo {
            flags: flags_to_bits(0),
            vendor: None,
            challenge: None,
            length: None,
            format: None,
            token_id: None,
            alg_id: None,
            supported_hash_alg: None,
            iteration_count: None,
        }],
        salt: None,
        s2kparams: None,
    };
    Ok(PaData {
        padata_type: PA_OTP_CHALLENGE,
        padata_value: OctetString::from(rasn::der::encode(&chl)?),
    })
}

fn in_skew(ts: i64, now: i64, clockskew: Duration) -> Result<(), KdcError> {
    let skew = i64::try_from(clockskew.as_secs()).unwrap_or(i64::MAX);
    if (ts - now).abs() > skew {
        return Err(KdcError::new(KRB_AP_ERR_SKEW, "PREAUTH_FAILED"));
    }
    Ok(())
}

/// `nonce_verify` then `timestamp_verify` (main.c:82-139). As in MIT, a
/// nonce of another length than the one issued is not time-checked.
fn verify_nonce(
    plain: &[u8],
    armor: &EncryptionKey,
    now: i64,
    clockskew: Duration,
) -> Result<(), KdcError> {
    let nonce_ok = rasn::der::decode::<PaOtpEncRequest>(plain)
        .map_err(|_| KdcError::new(KDC_ERR_PREAUTH_FAILED, "PREAUTH_FAILED"))
        .and_then(|er| {
            let n = er.nonce.as_ref();
            if n.len() != armor.key_bytes().len() + 4 {
                return Ok(());
            }
            let ts = u32::from_be_bytes([n[0], n[1], n[2], n[3]]);
            in_skew(i64::from(ts as i32), now, clockskew)
        });
    if nonce_ok.is_ok() {
        return Ok(());
    }
    let et: PaEncTsEnc = rasn::der::decode(plain)
        .map_err(|_| KdcError::new(KDC_ERR_PREAUTH_FAILED, "PREAUTH_FAILED"))?;
    in_skew(et.patimestamp.timestamp(), now, clockskew)
}

/// The machine's host name, MIT's NAS-Identifier (`gethostname`).
fn host_name() -> String {
    #[cfg(unix)]
    {
        rustix::system::uname()
            .nodename()
            .to_string_lossy()
            .into_owned()
    }
    #[cfg(not(unix))]
    {
        std::env::var("COMPUTERNAME").unwrap_or_default()
    }
}

/// `otp_verify` and `on_response` (main.c:277-398, otp_state.c:627-722):
/// decrypt the request with the armor key, check the nonce or timestamp,
/// then ask each configured token's RADIUS server in turn. An
/// Access-Accept returns the indicators to assert; a reject moves to the
/// next token; a transport failure ends the attempt.
pub(crate) async fn verify(
    types: &[TokenType],
    pa_value: &[u8],
    armor: Option<&EncryptionKey>,
    principal: &str,
    config: Option<&str>,
    now: i64,
    clockskew: Duration,
) -> Result<Vec<String>, KdcError> {
    let failed = || KdcError::new(KDC_ERR_PREAUTH_FAILED, "PREAUTH_FAILED");
    let armor = armor.ok_or_else(failed)?;
    let req: PaOtpRequest = rasn::der::decode(pa_value).map_err(|_| failed())?;
    if req.enc_data.etype != armor.keytype {
        return Err(failed());
    }
    let plain = find_etype(armor.keytype)
        .map_err(|_| failed())?
        .decrypt(
            armor.key_bytes(),
            KEYUSAGE_PA_OTP_REQUEST,
            req.enc_data.cipher.as_ref(),
        )
        .map_err(|_| failed())?;
    verify_nonce(&plain, armor, now, clockskew)?;
    let config = config.ok_or_else(failed)?;
    let tokens = tokens(types, config, principal).map_err(|_| failed())?;
    let value = req
        .otp_value
        .as_ref()
        .map(|v| v.to_vec())
        .unwrap_or_default();
    let base = vec![
        (crate::krad::attr::NAS_IDENTIFIER, host_name().into_bytes()),
        (
            crate::krad::attr::SERVICE_TYPE,
            crate::krad::SERVICE_TYPE_AUTHENTICATE_ONLY
                .to_be_bytes()
                .to_vec(),
        ),
        (crate::krad::attr::USER_PASSWORD, value),
    ];
    for tok in &tokens {
        let mut attrs = base.clone();
        attrs.push((
            crate::krad::attr::USER_NAME,
            tok.username.clone().into_bytes(),
        ));
        let rsp = crate::krad::send(
            &tok.ty.server,
            &tok.ty.secret,
            crate::krad::code::ACCESS_REQUEST,
            &attrs,
            tok.ty.timeout,
            tok.ty.retries,
        )
        .await
        .map_err(|_| failed())?;
        if rsp.code == crate::krad::code::ACCESS_ACCEPT {
            return Ok(tok
                .indicators
                .clone()
                .unwrap_or_else(|| tok.ty.indicators.clone()));
        }
    }
    Err(failed())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn types() -> Vec<TokenType> {
        let mut udp = default_type();
        udp.name = "udp".into();
        udp.strip_realm = true;
        udp.indicators = vec!["typeind".into()];
        vec![default_type(), udp]
    }

    #[test]
    fn tokens_decode_like_mit() {
        let t = types();
        let got = tokens(&t, "[]", "user@R").unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].ty.name, "DEFAULT");
        assert_eq!(got[0].username, "user@R");
        let got = tokens(
            &t,
            r#"[{"type":"udp"},{"type":"udp","username":"u2","indicators":["a","b"]}]"#,
            "us\\@er@R",
        )
        .unwrap();
        assert_eq!(got[0].username, "us\\@er");
        assert_eq!(got[0].indicators, None);
        assert_eq!(got[1].username, "u2");
        assert_eq!(got[1].indicators, Some(vec!["a".into(), "b".into()]));
        assert!(tokens(&t, r#"[{"type":"nope"}]"#, "u@R").is_err());
        assert!(tokens(&t, r#"{}"#, "u@R").is_err());
        assert!(tokens(&t, r#"[1]"#, "u@R").is_err());
        assert!(tokens(&t, r#"[{"indicators":"x"}]"#, "u@R").is_err());
    }

    #[test]
    fn token_types_from_profile() {
        let dir = std::env::temp_dir().join(format!("otp-secret-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("sec"), "  s3cret \nnext\n").unwrap();
        let p = Profile::parse(
            "[otp]\n udp = {\n  server = 127.0.0.1:1812\n  secret = sec\n  timeout = 2\n  retries = 1\n  indicator = x\n  indicator = y\n }\n",
        )
        .unwrap();
        let t = token_types(&p, None, &dir).unwrap();
        assert_eq!(t[0], default_type());
        assert_eq!(t[1].secret, "s3cret");
        assert_eq!(t[1].timeout, Duration::from_secs(2));
        assert_eq!(t[1].retries, 1);
        assert!(t[1].strip_realm);
        assert_eq!(t[1].indicators, vec!["x", "y"]);
        let p = Profile::parse("[otp]\n udp = {\n  server = h:1\n }\n").unwrap();
        assert!(token_types(&p, None, &dir).is_err());
        let p = Profile::parse("[otp]\n DEFAULT = {\n  strip_realm = false\n }\n").unwrap();
        let t = token_types(&p, None, &dir).unwrap();
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].server, format!("{KDC_RUN_DIR}/DEFAULT.socket"));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
