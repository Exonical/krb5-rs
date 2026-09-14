//! krb5.conf-style profile tree and query API (MIT util/profile).

mod deltat;
mod parse;

use std::path::Path;

pub use deltat::string_to_deltat;
use parse::Node;

/// Errors from profile parsing and typed lookups.
#[derive(Debug)]
pub enum ProfileError {
    /// Parse error.
    Syntax {
        /// 1-based source line of the error.
        line: usize,
        /// Error description.
        msg: String,
    },
    /// PROF_BAD_BOOLEAN (prof_get.c:336-369).
    BadBoolean(String),
    /// PROF_BAD_INTEGER (prof_get.c:282-305).
    BadInteger(String),
    /// `krb5_string_to_deltat` parse failure.
    BadDeltat(String),
    /// Filesystem error.
    Io(std::io::Error),
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProfileError::Syntax { line, msg } => {
                write!(f, "profile syntax error line {line}: {msg}")
            }
            ProfileError::BadBoolean(s) => write!(f, "bad boolean value {s:?}"),
            ProfileError::BadInteger(s) => write!(f, "bad integer value {s:?}"),
            ProfileError::BadDeltat(s) => write!(f, "bad delta-time value {s:?}"),
            ProfileError::Io(e) => write!(f, "profile I/O error: {e}"),
        }
    }
}

impl std::error::Error for ProfileError {}

/// A parsed profile (krb5.conf) tree.
pub struct Profile {
    root: Node,
}

impl Profile {
    /// Parse in-memory text.  `include`/`includedir` directives are honored
    /// exactly as MIT does (prof_parse.c:295-306): the named paths are opened
    /// as given (absolute or relative to the process working directory).
    pub fn parse(text: &str) -> Result<Profile, ProfileError> {
        Ok(Profile {
            root: parse::parse_text(text)?,
        })
    }

    /// Load a profile file, recursively processing include/includedir.
    pub fn load(path: &Path) -> Result<Profile, ProfileError> {
        Ok(Profile {
            root: parse::load_file(path)?,
        })
    }

    /// Walk `names[..len-1]` as a subsection path; return the child section.
    fn section<'a>(&'a self, names: &[&str]) -> Option<&'a Node> {
        let mut node = &self.root;
        for name in names {
            node = node
                .children
                .iter()
                .find(|c| c.value.is_none() && c.name == *name)?;
        }
        Some(node)
    }

    /// All values of the relation `names.last()` under the section path
    /// `names[..len-1]`, in file order across merged sections
    /// (profile_get_values, prof_get.c).
    pub fn get_values(&self, names: &[&str]) -> Vec<String> {
        let (key, path) = match names.split_last() {
            Some((k, p)) => (*k, p),
            None => return Vec::new(),
        };
        match self.section(path) {
            Some(sec) => sec
                .children
                .iter()
                .filter(|c| c.name == *key)
                .filter_map(|c| c.value.clone())
                .collect(),
            None => Vec::new(),
        }
    }

    /// First value of the relation (profile_get_value / profile_get_string).
    pub fn get_string(&self, names: &[&str]) -> Option<String> {
        self.get_values(names).into_iter().next()
    }

    /// profile_get_integer (prof_get.c:282-305): strict strtol semantics —
    /// empty, overflow, or trailing garbage all fail.
    pub fn get_integer(&self, names: &[&str], default: i64) -> Result<i64, ProfileError> {
        let s = match self.get_string(names) {
            Some(s) => s,
            None => return Ok(default),
        };
        // strtol: leading whitespace ok, then digits/sign, all consumed.
        let t = s.trim_start();
        if t.is_empty() {
            return Err(ProfileError::BadInteger(s));
        }
        match t.parse::<i64>() {
            Ok(v) => Ok(v),
            Err(_) => Err(ProfileError::BadInteger(s)),
        }
    }

    /// profile_get_boolean (prof_get.c:371-398): conf_yes/conf_no lists,
    /// case-insensitive; anything else -> BadBoolean.
    pub fn get_boolean(&self, names: &[&str], default: bool) -> Result<bool, ProfileError> {
        let s = match self.get_string(names) {
            Some(s) => s,
            None => return Ok(default),
        };
        conf_boolean(&s).ok_or(ProfileError::BadBoolean(s))
    }

    /// profile_get_deltat: parse the first value with
    /// `krb5_string_to_deltat`; absent relation -> `default`.
    pub fn get_deltat(&self, names: &[&str], default: i32) -> Result<i32, ProfileError> {
        match self.get_string(names) {
            Some(s) => string_to_deltat(&s),
            None => Ok(default),
        }
    }

    /// Names of subsections under the path (e.g. realms under `[realms]`).
    /// Order is the MIT child order (sorted by name, deduped by merge).
    pub fn subsection_names(&self, names: &[&str]) -> Vec<String> {
        match self.section(names) {
            Some(sec) => sec
                .children
                .iter()
                .filter(|c| c.value.is_none())
                .map(|c| c.name.clone())
                .collect(),
            None => Vec::new(),
        }
    }
}

/// _krb5_conf_boolean (libdef_parse.c:37-58): MIT's true/false word lists,
/// case-insensitive.  Returns None for unrecognized values.
pub fn conf_boolean(s: &str) -> Option<bool> {
    const YES: [&str; 6] = ["y", "yes", "true", "t", "1", "on"];
    const NO: [&str; 6] = ["n", "no", "false", "nil", "0", "off"];
    if YES.iter().any(|w| s.eq_ignore_ascii_case(w)) {
        Some(true)
    } else if NO.iter().any(|w| s.eq_ignore_ascii_case(w)) {
        Some(false)
    } else {
        None
    }
}
