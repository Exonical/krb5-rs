//! The libldap options SASL binds use (`ldap_int_initialize`, init.c:730-800):
//! `SASL_SECPROPS` and `SASL_NOCANON` from `ldap.conf`, `ldaprc` and
//! `LDAP<option>` environment variables, in libldap's order.

use std::path::{Path, PathBuf};

/// Cyrus `SASL_SEC_*` flags.
pub const NOPLAINTEXT: u32 = 0x0001;
pub const NOACTIVE: u32 = 0x0002;
pub const NODICTIONARY: u32 = 0x0004;
pub const FORWARD_SECRECY: u32 = 0x0008;
pub const NOANONYMOUS: u32 = 0x0010;
pub const PASS_CREDENTIALS: u32 = 0x0020;
pub const MUTUAL_AUTH: u32 = 0x0040;

/// `sasl_security_properties_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecProps {
    pub min_ssf: u32,
    pub max_ssf: u32,
    pub maxbufsize: u32,
    pub flags: u32,
}

impl Default for SecProps {
    /// libldap's defaults (init.c:621-627).
    fn default() -> Self {
        SecProps {
            min_ssf: 0,
            max_ssf: i32::MAX as u32,
            maxbufsize: 65536,
            flags: NOPLAINTEXT | NOANONYMOUS,
        }
    }
}

impl SecProps {
    /// `ldap_pvt_sasl_secprops` (cyrus.c:906-985): a comma-separated list;
    /// any unknown property rejects the whole value.
    pub fn apply(&mut self, s: &str) -> Result<(), String> {
        const FLAGS: [(&str, u32); 7] = [
            ("none", 0),
            ("nodict", NODICTIONARY),
            ("noplain", NOPLAINTEXT),
            ("noactive", NOACTIVE),
            ("passcred", PASS_CREDENTIALS),
            ("forwardsec", FORWARD_SECRECY),
            ("noanonymous", NOANONYMOUS),
        ];
        let (mut flags, mut got_flags) = (0, false);
        let (mut min, mut max, mut buf) = (None, None, None);
        for p in s.split(',').filter(|p| !p.is_empty()) {
            let lower = p.to_ascii_lowercase();
            if let Some((_, f)) = FLAGS.iter().find(|(k, _)| *k == lower) {
                flags = if *f == 0 { 0 } else { flags | f };
                got_flags = true;
                continue;
            }
            let num = |key: &str| -> Option<u32> {
                let v = lower.strip_prefix(key)?;
                if !v.starts_with(|c: char| c.is_ascii_digit()) {
                    return None;
                }
                v.parse().ok()
            };
            if let Some(v) = num("minssf=") {
                min = Some(v);
            } else if let Some(v) = num("maxssf=") {
                max = Some(v);
            } else if let Some(v) = num("maxbufsize=") {
                buf = Some(v);
            } else {
                return Err(format!("invalid SASL_SECPROPS option '{p}'"));
            }
        }
        if got_flags {
            self.flags = flags;
        }
        self.min_ssf = min.unwrap_or(self.min_ssf);
        self.max_ssf = max.unwrap_or(self.max_ssf);
        self.maxbufsize = buf.unwrap_or(self.maxbufsize);
        Ok(())
    }
}

/// The SASL options of libldap's global option set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LdapOptions {
    pub secprops: SecProps,
    pub nocanon: bool,
}

impl LdapOptions {
    /// Read the process environment and files as libldap does.
    pub fn load() -> Self {
        let sysconf = ["/etc/ldap/ldap.conf", "/etc/openldap/ldap.conf"]
            .into_iter()
            .map(PathBuf::from)
            .find(|p| p.exists())
            .unwrap_or_else(|| PathBuf::from("/etc/openldap/ldap.conf"));
        Self::load_from(&sysconf, &|k| std::env::var(k).ok())
    }

    /// `ldap_int_initialize` with `sysconf` as `LDAP_CONF_FILE`.
    pub fn load_from(sysconf: &Path, env: &dyn Fn(&str) -> Option<String>) -> Self {
        let mut o = LdapOptions::default();
        if env("LDAPNOINIT").is_some() {
            return o;
        }
        o.read_file(sysconf);
        o.read_userconf("ldaprc", env);
        if let Some(f) = env("LDAPCONF").filter(|f| !f.is_empty()) {
            o.read_file(Path::new(&f));
        }
        if let Some(f) = env("LDAPRC").filter(|f| !f.is_empty()) {
            o.read_userconf(&f, env);
        }
        for (name, _) in OPTIONS {
            if let Some(v) = env(&format!("LDAP{name}")) {
                o.set(name, &v);
            }
        }
        o
    }

    /// `openldap_ldap_init_w_userconf`: `$HOME/file`, `$HOME/.file`, `file`.
    fn read_userconf(&mut self, file: &str, env: &dyn Fn(&str) -> Option<String>) {
        if let Some(home) = env("HOME") {
            self.read_file(&Path::new(&home).join(file));
            self.read_file(&Path::new(&home).join(format!(".{file}")));
        }
        self.read_file(Path::new(file));
    }

    /// `openldap_ldap_init_w_conf`.
    fn read_file(&mut self, path: &Path) {
        let Ok(text) = std::fs::read_to_string(path) else {
            return;
        };
        for line in text.lines() {
            if line.starts_with('#') {
                continue;
            }
            let line = line.trim();
            let Some((cmd, opt)) = line.split_once(|c: char| c.is_ascii_whitespace()) else {
                continue;
            };
            self.set(cmd, opt.trim_start());
        }
    }

    /// `ldap_int_conf_option`, for the options SASL binds read.
    fn set(&mut self, cmd: &str, value: &str) {
        match OPTIONS.iter().find(|(n, _)| n.eq_ignore_ascii_case(cmd)) {
            Some((_, Opt::SecProps)) => {
                let mut p = self.secprops;
                if p.apply(value).is_ok() {
                    self.secprops = p;
                }
            }
            Some((_, Opt::NoCanon)) => {
                self.nocanon = ["on", "true", "yes"]
                    .iter()
                    .any(|t| value.eq_ignore_ascii_case(t));
            }
            None => {}
        }
    }
}

enum Opt {
    SecProps,
    NoCanon,
}

const OPTIONS: [(&str, Opt); 2] = [
    ("SASL_SECPROPS", Opt::SecProps),
    ("SASL_NOCANON", Opt::NoCanon),
];

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn secprops_parse() {
        let mut p = SecProps::default();
        p.apply("noplain,minssf=56,maxssf=128,maxbufsize=1024")
            .unwrap();
        assert_eq!(
            p,
            SecProps {
                min_ssf: 56,
                max_ssf: 128,
                maxbufsize: 1024,
                flags: NOPLAINTEXT
            }
        );
        p.apply("none").unwrap();
        assert_eq!(p.flags, 0);
        let before = p;
        assert!(p.apply("maxssf=1,bogus").is_err());
        assert_eq!(p, before);
        assert!(p.apply("maxssf=x").is_err());
    }

    #[test]
    fn conf_order() {
        let dir = tempfile::tempdir().unwrap();
        let sys = dir.path().join("ldap.conf");
        std::fs::write(&sys, "# c\nSASL_SECPROPS maxssf=0\nsasl_nocanon on\n").unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir(&home).unwrap();
        std::fs::write(home.join(".ldaprc"), "  SASL_SECPROPS minssf=1  \n").unwrap();
        let h = home.to_str().unwrap().to_string();
        let env = move |k: &str| match k {
            "HOME" => Some(h.clone()),
            _ => None,
        };
        let o = LdapOptions::load_from(&sys, &env);
        assert!(o.nocanon);
        assert_eq!(o.secprops.max_ssf, 0);
        assert_eq!(o.secprops.min_ssf, 1);
        let h = home.to_str().unwrap().to_string();
        let env = move |k: &str| match k {
            "HOME" => Some(h.clone()),
            "LDAPSASL_SECPROPS" => Some("maxssf=56".into()),
            "LDAPSASL_NOCANON" => Some("off".into()),
            _ => None,
        };
        let o = LdapOptions::load_from(&sys, &env);
        assert!(!o.nocanon);
        assert_eq!(o.secprops.max_ssf, 56);
        let o = LdapOptions::load_from(&sys, &|k| (k == "LDAPNOINIT").then(String::new));
        assert_eq!(o, LdapOptions::default());
    }
}
