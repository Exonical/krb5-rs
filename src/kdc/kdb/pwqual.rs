//! Password quality modules (`lib/kadm5/srv/pwqual.c`, `pwqual_plugin.h`):
//! after the policy's length and character-class checks, every enabled
//! module checks a new password in turn, and the first refusal wins
//! (`passwd_check`, `server_misc.c:107-138`).
//!
//! The built-in modules are MIT's `dict` (`pwqual_dict.c`), `empty`
//! (`pwqual_empty.c`), `hesiod` (`pwqual_hesiod.c`, which does nothing
//! without Hesiod support, as in MIT's default build) and `princ`
//! (`pwqual_princ.c`).

use std::path::Path;
use std::sync::Arc;

use super::kadm5::code;
use crate::kdc::store::StoreError;
use crate::types::PrincipalName;

/// The built-in modules in MIT's registration order (`server_misc.c:44-56`).
pub const BUILTIN: [&str; 4] = ["dict", "empty", "hesiod", "princ"];

/// `KADM5_PASS_Q_DICT` (`kadm_err.et:31`).
pub const PASS_Q_DICT: &str = "Password is in the password dictionary";
/// `KADM5_PASS_Q_GENERIC` (`kadm_err.et:64`).
pub const PASS_Q_GENERIC: &str = "Unspecified password quality failure";

/// A password refusal: `code` (a kadm5 or com_err code) with `message`.
#[must_use]
pub fn refusal(code: u32, message: impl Into<String>) -> StoreError {
    StoreError::rejected(message).with_code(code)
}

/// A password quality module (`krb5_pwqual_vtable`).
pub trait PwQual: Send + Sync {
    /// The module name used by `enable_only` and `disable`.
    fn name(&self) -> &str;

    /// Check `password` for `princ@realm`, whose password policy is
    /// `policy` (`None` without one).
    fn check(
        &self,
        password: &str,
        policy: Option<&str>,
        princ: &PrincipalName,
        realm: &str,
    ) -> Result<(), StoreError>;
}

/// MIT's `dict` module: with a policy, a password equal, ignoring ASCII
/// case, to a newline-terminated word of `dict_file` is refused.
#[derive(Debug, Default, Clone)]
pub struct DictModule {
    words: Vec<Vec<u8>>,
}

fn fold(s: &[u8]) -> Vec<u8> {
    s.iter().map(u8::to_ascii_lowercase).collect()
}

/// `strcasecmp` semantics: the comparison stops at the first NUL.
fn c_str(s: &[u8]) -> &[u8] {
    s.split(|&b| b == 0).next().unwrap_or(s)
}

impl DictModule {
    /// `init_dict` (`pwqual_dict.c:93-150`): no file or a missing file
    /// leaves the dictionary empty (with the warning `log` gets); any other
    /// read error is fatal.
    pub fn open(dict_file: Option<&Path>, log: &dyn Fn(&str)) -> Result<Self, StoreError> {
        let Some(path) = dict_file else {
            log("No dictionary file specified, continuing without one.");
            return Ok(Self::default());
        };
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                log(&format!(
                    "WARNING!  Cannot find dictionary file {}, continuing without one.",
                    path.display()
                ));
                return Ok(Self::default());
            }
            Err(e) => {
                return Err(StoreError::backend(format!(
                    "{e} while reading dictionary file {}",
                    path.display()
                )))
            }
        };
        Ok(Self::from_bytes(&data))
    }

    /// The words of a dictionary file's contents.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut words: Vec<Vec<u8>> = Vec::new();
        let mut rest = data;
        while let Some(i) = rest.iter().position(|&b| b == b'\n') {
            words.push(fold(c_str(&rest[..i])));
            rest = &rest[i + 1..];
        }
        words.sort();
        Self { words }
    }
}

impl PwQual for DictModule {
    fn name(&self) -> &str {
        "dict"
    }

    fn check(
        &self,
        password: &str,
        policy: Option<&str>,
        _: &PrincipalName,
        _: &str,
    ) -> Result<(), StoreError> {
        if policy.is_none() {
            return Ok(());
        }
        let pw = fold(c_str(password.as_bytes()));
        if self.words.binary_search(&pw).is_ok() {
            return Err(refusal(code::PASS_Q_DICT, PASS_Q_DICT));
        }
        Ok(())
    }
}

/// MIT's `empty` module: an empty password is refused, with or without a
/// policy.
#[derive(Debug, Default, Clone, Copy)]
pub struct EmptyModule;

impl PwQual for EmptyModule {
    fn name(&self) -> &str {
        "empty"
    }

    fn check(
        &self,
        password: &str,
        _: Option<&str>,
        _: &PrincipalName,
        _: &str,
    ) -> Result<(), StoreError> {
        if password.is_empty() {
            return Err(refusal(
                code::PASS_Q_TOOSHORT,
                "Empty passwords are not allowed",
            ));
        }
        Ok(())
    }
}

/// MIT's `hesiod` module as built without Hesiod: it accepts everything.
#[derive(Debug, Default, Clone, Copy)]
pub struct HesiodModule;

impl PwQual for HesiodModule {
    fn name(&self) -> &str {
        "hesiod"
    }

    fn check(
        &self,
        _: &str,
        _: Option<&str>,
        _: &PrincipalName,
        _: &str,
    ) -> Result<(), StoreError> {
        Ok(())
    }
}

/// MIT's `princ` module: with a policy, a password equal, ignoring ASCII
/// case, to the realm or to a component of the principal is refused.
#[derive(Debug, Default, Clone, Copy)]
pub struct PrincModule;

impl PwQual for PrincModule {
    fn name(&self) -> &str {
        "princ"
    }

    fn check(
        &self,
        password: &str,
        policy: Option<&str>,
        princ: &PrincipalName,
        realm: &str,
    ) -> Result<(), StoreError> {
        if policy.is_none() {
            return Ok(());
        }
        let pw = fold(c_str(password.as_bytes()));
        if fold(c_str(realm.as_bytes())) == pw {
            return Err(refusal(code::PASS_Q_DICT, PASS_Q_DICT));
        }
        if princ
            .name_string
            .iter()
            .any(|c| fold(c_str(c.as_bytes())) == pw)
        {
            return Err(refusal(
                code::PASS_Q_DICT,
                "Password may not match principal name",
            ));
        }
        Ok(())
    }
}

/// A built-in module by name, opened with `dict_file`.
pub fn builtin(
    name: &str,
    dict_file: Option<&Path>,
    log: &dyn Fn(&str),
) -> Result<Option<Box<dyn PwQual>>, StoreError> {
    Ok(Some(match name {
        "dict" => Box::new(DictModule::open(dict_file, log)?),
        "empty" => Box::new(EmptyModule),
        "hesiod" => Box::new(HesiodModule),
        "princ" => Box::new(PrincModule),
        _ => return Ok(None),
    }))
}

/// Where module messages go (MIT's `krb5_klog_syslog`).
pub type Logger = Arc<dyn Fn(&str) + Send + Sync>;

/// The default [`Logger`]: standard error.
#[must_use]
pub fn stderr_logger() -> Logger {
    Arc::new(|m| eprintln!("{m}"))
}

/// The enabled password quality modules, in order (`k5_pwqual_load`).
pub struct PwQualModules {
    modules: Vec<Box<dyn PwQual>>,
    log: Logger,
}

impl Default for PwQualModules {
    /// MIT's modules with no configuration: every built-in, no dictionary.
    fn default() -> Self {
        Self::new(
            vec![
                Box::new(DictModule::default()),
                Box::new(EmptyModule),
                Box::new(HesiodModule),
                Box::new(PrincModule),
            ],
            stderr_logger(),
        )
    }
}

impl std::fmt::Debug for PwQualModules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.modules.iter().map(|m| m.name()))
            .finish()
    }
}

impl PwQualModules {
    /// `modules`, in order, logging refusals to `log`.
    #[must_use]
    pub fn new(modules: Vec<Box<dyn PwQual>>, log: Logger) -> Self {
        Self { modules, log }
    }

    /// No modules.
    #[must_use]
    pub fn none() -> Self {
        Self::new(Vec::new(), stderr_logger())
    }

    /// The module names, in order.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.modules.iter().map(|m| m.name()).collect()
    }

    /// Run every module (`passwd_check`, `server_misc.c:117-135`); the first
    /// refusal is logged and returned.
    pub fn check(
        &self,
        password: &str,
        policy: Option<&str>,
        princ: &PrincipalName,
        realm: &str,
    ) -> Result<(), StoreError> {
        for m in &self.modules {
            if let Err(e) = m.check(password, policy, princ, realm) {
                (self.log)(&format!(
                    "password quality module {} rejected password for {}: {}",
                    m.name(),
                    unparse(princ, realm),
                    e.message()
                ));
                return Err(e);
            }
        }
        Ok(())
    }
}

fn unparse(princ: &PrincipalName, realm: &str) -> String {
    String::from_utf8_lossy(&super::mit::unparse_name(princ, realm)).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::KerberosString;

    fn princ(parts: &[&str]) -> PrincipalName {
        PrincipalName {
            name_type: 1,
            name_string: parts
                .iter()
                .map(|p| KerberosString::from_bytes(p.as_bytes()).expect("test"))
                .collect(),
        }
    }

    fn code_of(r: Result<(), StoreError>) -> Option<(u32, String)> {
        r.err()
            .map(|e| (e.code().expect("test"), e.message().to_string()))
    }

    #[test]
    fn dict_matches_newline_terminated_words_ignoring_case_with_a_policy() {
        let d = DictModule::from_bytes(b"birds\nBees\napples\nunterminated");
        let p = princ(&["p"]);
        assert_eq!(
            code_of(d.check("BIRDS", Some("pol"), &p, "R")),
            Some((code::PASS_Q_DICT, PASS_Q_DICT.into()))
        );
        assert!(d.check("bees", Some("pol"), &p, "R").is_err());
        assert!(d.check("unterminated", Some("pol"), &p, "R").is_ok());
        assert!(d.check("birds", None, &p, "R").is_ok());
        assert!(d.check("birdsx", Some("pol"), &p, "R").is_ok());
    }

    #[test]
    fn dict_without_a_file_or_with_a_missing_one_logs_and_continues() {
        let logged = std::sync::Mutex::new(Vec::new());
        let log = |m: &str| logged.lock().expect("test").push(m.to_string());
        let d = DictModule::open(None, &log).expect("test");
        assert!(d.words.is_empty());
        DictModule::open(Some(Path::new("/nonexistent/dict")), &log).expect("test");
        assert!(DictModule::open(Some(Path::new("/")), &log).is_err());
        let logged = logged.lock().expect("test").clone();
        assert_eq!(
            logged[0],
            "No dictionary file specified, continuing without one."
        );
        assert_eq!(
            logged[1],
            "WARNING!  Cannot find dictionary file /nonexistent/dict, continuing without one."
        );
    }

    #[test]
    fn empty_refuses_empty_passwords_without_a_policy() {
        assert_eq!(
            code_of(EmptyModule.check("", None, &princ(&["p"]), "R")),
            Some((
                code::PASS_Q_TOOSHORT,
                "Empty passwords are not allowed".into()
            ))
        );
        assert!(EmptyModule.check("x", None, &princ(&["p"]), "R").is_ok());
    }

    #[test]
    fn princ_refuses_components_and_the_realm_with_a_policy() {
        let p = princ(&["p5", "admin"]);
        assert_eq!(
            code_of(PrincModule.check("P5", Some("pol"), &p, "KRBTEST.COM")),
            Some((
                code::PASS_Q_DICT,
                "Password may not match principal name".into()
            ))
        );
        assert!(PrincModule.check("admin", Some("pol"), &p, "R").is_err());
        assert_eq!(
            code_of(PrincModule.check("krbtest.com", Some("pol"), &p, "KRBTEST.COM")),
            Some((code::PASS_Q_DICT, PASS_Q_DICT.into()))
        );
        assert!(PrincModule.check("p5", None, &p, "R").is_ok());
    }

    #[test]
    fn modules_run_in_order_and_log_the_first_refusal() {
        let logged = Arc::new(std::sync::Mutex::new(Vec::new()));
        let l = logged.clone();
        let mods = PwQualModules::new(
            vec![Box::new(PrincModule), Box::new(EmptyModule)],
            Arc::new(move |m| l.lock().expect("test").push(m.to_string())),
        );
        assert!(mods.check("", None, &princ(&["p"]), "R").is_err());
        assert!(mods.check("p", Some("x"), &princ(&["p"]), "R").is_err());
        assert_eq!(
            *logged.lock().expect("test"),
            [
                "password quality module empty rejected password for p@R: Empty passwords are not allowed",
                "password quality module princ rejected password for p@R: Password may not match principal name",
            ]
        );
        assert_eq!(PwQualModules::default().names(), BUILTIN);
    }
}
