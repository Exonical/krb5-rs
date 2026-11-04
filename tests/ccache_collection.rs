//! DIR, KEYRING and KCM caches, cache-name resolution and collections, as
//! in MIT's cc_dir.c, cc_keyring.c, cc_kcm.c and ccbase.c.

use std::path::PathBuf;

use krb5_rs::ccache::*;
use krb5_rs::types::*;
use rasn::types::GeneralString;

const REALM: &str = "TEST.REALM";

fn princ(parts: &[&str]) -> PrincipalName {
    PrincipalName {
        name_type: 1,
        name_string: parts
            .iter()
            .map(|p| GeneralString::from_bytes(p.as_bytes()).unwrap())
            .collect(),
    }
}

fn cred(server: &str) -> CcCredential {
    CcCredential {
        client: princ(&["alice"]),
        crealm: REALM.into(),
        server: princ(&[server, REALM]),
        srealm: REALM.into(),
        keyblock: EncryptionKey::new(18, vec![7; 32]),
        authtime: 1,
        starttime: 1,
        endtime: u32::MAX - 1,
        renew_till: 0,
        is_skey: false,
        ticket_flags: 0,
        addresses: vec![],
        authdata: vec![],
        ticket: server.as_bytes().to_vec(),
        second_ticket: vec![],
    }
}

fn server_match(server: &str) -> MatchCred {
    MatchCred {
        server: Some((princ(&[server, REALM]), REALM.into())),
        ..Default::default()
    }
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "krb5rs-cc-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn ctx(default: &str) -> CcContext {
    CcContext {
        default_name: Some(default.into()),
        ..Default::default()
    }
}

#[test]
fn split_name_like_krb5_cc_resolve() {
    assert_eq!(split_name("/tmp/x"), ("FILE", "/tmp/x"));
    assert_eq!(split_name("C:\\x\\cc"), ("FILE", "C:\\x\\cc"));
    assert_eq!(split_name("DIR::/d/tkt"), ("DIR", ":/d/tkt"));
    assert_eq!(
        split_name("KEYRING:persistent:0"),
        ("KEYRING", "persistent:0")
    );
    assert!(matches!(
        resolve(&CcContext::default(), "NOPE:x"),
        Err(CcError::UnknownType)
    ));
}

#[test]
fn default_name_precedence_and_tokens() {
    let mut c = CcContext {
        profile_default: Some("DIR:%{TEMP}/cc_%{uid}%{null}".into()),
        ..Default::default()
    };
    let n = c.default_ccname().unwrap();
    assert!(n.starts_with("DIR:") && !n.contains("%{"), "{n}");
    c.profile_default = None;
    let n = c.default_ccname().unwrap();
    assert!(n.starts_with("FILE:/tmp/krb5cc_") && n[17..].parse::<u32>().is_ok());
    c.default_name = Some("MEMORY:x".into());
    assert_eq!(c.default_ccname().unwrap(), "MEMORY:x");
    assert!(expand_path_tokens("%{bogus}").is_err());
}

#[test]
fn memory_caches_are_shared_by_name() {
    let c = CcContext::default();
    let mut a = resolve(&c, "MEMORY:shared-test").unwrap();
    a.initialize(&princ(&["alice"]), REALM).unwrap();
    a.store(&cred("krbtgt")).unwrap();
    let b = resolve(&c, "MEMORY:shared-test").unwrap();
    assert_eq!(b.creds().unwrap().len(), 1);
    b.destroy().unwrap();
    let a2 = resolve(&c, "MEMORY:shared-test").unwrap();
    assert!(a2.principal().is_err());
}

#[test]
fn dir_primary_subsidiaries_and_switch() {
    let dir = tmpdir("dir");
    let c = ctx(&format!("DIR:{}", dir.display()));
    let mut primary = default_cache(&c).unwrap();
    assert_eq!(
        primary.name(),
        format!("DIR::{}", dir.join("tkt").display())
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("primary")).unwrap(),
        "tkt\n"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }
    primary.initialize(&princ(&["alice"]), REALM).unwrap();
    primary.store(&cred("krbtgt")).unwrap();
    let got = primary
        .retrieve(MatchFlags::empty(), &server_match("krbtgt"), None)
        .unwrap();
    assert_eq!(got.ticket, b"krbtgt");

    let mut second = new_unique(&c, "DIR").unwrap();
    let name = second.name();
    let file = name.rsplit(['/', '\\']).next().unwrap().to_string();
    assert!(file.starts_with("tkt") && file.len() == 9, "{name}");
    second.initialize(&princ(&["bob"]), REALM).unwrap();

    let names: Vec<_> = collection(&c)
        .unwrap()
        .iter()
        .map(AnyCcache::name)
        .collect();
    assert_eq!(names[0], primary.name());
    assert!(names.contains(&name) && names.len() == 2, "{names:?}");

    second.switch_to().unwrap();
    assert_eq!(
        std::fs::read_to_string(dir.join("primary")).unwrap(),
        format!("{file}\n")
    );
    assert_eq!(default_cache(&c).unwrap().name(), name);
    let found = cache_match(&c, &princ(&["alice"]), REALM).unwrap();
    assert_eq!(found.name(), primary.name());
    assert!(cache_match(&c, &princ(&["carol"]), REALM).is_err());
    have_content(&c).unwrap();

    // A subsidiary default names only itself.
    let sub = ctx(&name);
    assert_eq!(collection(&sub).unwrap().len(), 1);
    // gen_new needs a collection default.
    assert!(matches!(
        new_unique(&sub, "DIR"),
        Err(CcError::CannotCreate(_))
    ));

    second.destroy().unwrap();
    assert!(!dir.join(&file).exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn dir_rejects_bad_names_and_primary_files() {
    let c = CcContext::default();
    assert!(matches!(resolve(&c, "DIR::tkt"), Err(CcError::BadName(_))));
    assert!(matches!(
        resolve(&c, "DIR::/tmp/notkt"),
        Err(CcError::BadName(_))
    ));
    let dir = tmpdir("badprimary");
    std::fs::create_dir_all(&dir).unwrap();
    for bad in ["foo\n", "tkt/../x\n", "tkt", ""] {
        std::fs::write(dir.join("primary"), bad).unwrap();
        assert!(
            resolve(&c, &format!("DIR:{}", dir.display())).is_err(),
            "{bad:?}"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn file_collection_yields_only_an_existing_default() {
    let dir = tmpdir("file");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("cc");
    let c = ctx(&format!("FILE:{}", path.display()));
    assert!(collection(&c).unwrap().is_empty());
    assert!(have_content(&c).is_err());
    default_cache(&c)
        .unwrap()
        .initialize(&princ(&["alice"]), REALM)
        .unwrap();
    assert_eq!(collection(&c).unwrap().len(), 1);
    assert!(matches!(
        default_cache(&c).unwrap().switch_to(),
        Err(CcError::Code {
            name: "KRB5_CC_NOSUPP",
            ..
        })
    ));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn keyring_process_collection() {
    let coll = format!("krb5rs{}", std::process::id());
    let c = ctx(&format!("KEYRING:process:{coll}"));
    let mut primary = match default_cache(&c) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("skipping: no keyring access: {e}");
            return;
        }
    };
    assert_eq!(primary.name(), format!("KEYRING:process:{coll}:{coll}"));
    assert!(matches!(primary.principal(), Err(CcError::NoFile(_))));
    primary.initialize(&princ(&["alice"]), REALM).unwrap();
    assert_eq!(primary.principal().unwrap().1, REALM);
    primary.store(&cred("krbtgt")).unwrap();
    primary.store(&cred("host")).unwrap();
    assert_eq!(primary.creds().unwrap().len(), 2);
    primary
        .remove_cred(MatchFlags::empty(), &server_match("host"))
        .unwrap();
    let creds = primary.creds().unwrap();
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].ticket, b"krbtgt");
    primary.set_config(None, "pa_type", Some(b"2")).unwrap();
    assert_eq!(primary.get_config(None, "pa_type").unwrap().unwrap(), b"2");

    let mut second = new_unique(&c, "KEYRING").unwrap();
    let name = second.name();
    assert!(name.starts_with(&format!("KEYRING:process:{coll}:krb_ccache_")));
    assert_eq!(
        name.len(),
        format!("KEYRING:process:{coll}:krb_ccache_").len() + 8
    );
    second.initialize(&princ(&["bob"]), REALM).unwrap();
    let names: Vec<_> = collection(&c)
        .unwrap()
        .iter()
        .map(AnyCcache::name)
        .collect();
    assert_eq!(names, vec![primary.name(), name.clone()]);
    second.switch_to().unwrap();
    assert_eq!(default_cache(&c).unwrap().name(), name);
    assert_eq!(
        cache_match(&c, &princ(&["alice"]), REALM).unwrap().name(),
        primary.name()
    );
    second.destroy().unwrap();
    primary.destroy().unwrap();
    assert!(matches!(
        resolve(&c, "KEYRING:bogus:x"),
        Err(CcError::Code {
            name: "KRB5_KCC_INVALID_ANCHOR",
            ..
        })
    ));
}

#[cfg(unix)]
mod kcm {
    use super::*;
    use krb5_rs::ccache::kcm::op;
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};

    const CC_END: i32 = -1_765_328_242;
    const FCC_NOFILE: i32 = -1_765_328_189;
    const CC_NOSUPP: i32 = -1_765_328_137;

    #[derive(Default)]
    struct Cache {
        princ: Vec<u8>,
        creds: Vec<Vec<u8>>,
        offset: Option<[u8; 4]>,
    }

    #[derive(Default)]
    struct Daemon {
        caches: BTreeMap<String, Cache>,
        default: String,
        next: u32,
        /// Answer GET_CRED_LIST, RETRIEVE and REPLACE with CC_NOSUPP, like
        /// Heimdal's kcm.
        heimdal: bool,
    }

    fn name_arg(b: &[u8]) -> (String, &[u8]) {
        let n = b.iter().position(|&c| c == 0).unwrap();
        (String::from_utf8(b[..n].to_vec()).unwrap(), &b[n + 1..])
    }

    fn uuid(name: &str) -> [u8; 16] {
        let mut u = [0; 16];
        u[..name.len().min(16)].copy_from_slice(&name.as_bytes()[..name.len().min(16)]);
        u
    }

    impl Daemon {
        fn handle(&mut self, req: &[u8]) -> Result<Vec<u8>, i32> {
            assert_eq!(&req[..2], &[2, 0]);
            let opcode = u16::from_be_bytes([req[2], req[3]]);
            let body = &req[4..];
            let named = |n: &str| -> Vec<u8> {
                let mut v = n.as_bytes().to_vec();
                v.push(0);
                v
            };
            match opcode {
                op::GET_DEFAULT_CACHE => return Ok(named(&self.default)),
                op::GEN_NEW => {
                    self.next += 1;
                    let n = format!("1000:{}", self.next);
                    return Ok(named(&n));
                }
                op::GET_CACHE_UUID_LIST => {
                    return Ok(self.caches.keys().flat_map(|n| uuid(n)).collect());
                }
                op::GET_CACHE_BY_UUID => {
                    return self
                        .caches
                        .keys()
                        .find(|n| uuid(n) == body)
                        .map(|n| named(n))
                        .ok_or(CC_END);
                }
                _ => {}
            }
            let (name, args) = name_arg(body);
            if opcode == op::INITIALIZE {
                let c = self.caches.entry(name).or_default();
                c.princ = args.to_vec();
                c.creds.clear();
                return Ok(vec![]);
            }
            let heimdal = self.heimdal;
            if opcode == op::SET_DEFAULT_CACHE {
                self.default = name;
                return Ok(vec![]);
            }
            if opcode == op::REPLACE {
                return Err(CC_NOSUPP);
            }
            let c = self.caches.get_mut(&name).ok_or(FCC_NOFILE)?;
            match opcode {
                op::GET_PRINCIPAL => Ok(c.princ.clone()),
                op::STORE => {
                    c.creds.push(args.to_vec());
                    Ok(vec![])
                }
                op::GET_CRED_LIST if heimdal => Err(CC_NOSUPP),
                op::GET_CRED_LIST => {
                    let mut v = (c.creds.len() as u32).to_be_bytes().to_vec();
                    for cr in &c.creds {
                        v.extend_from_slice(&(cr.len() as u32).to_be_bytes());
                        v.extend_from_slice(cr);
                    }
                    Ok(v)
                }
                op::GET_CRED_UUID_LIST => Ok((0..c.creds.len() as u8)
                    .flat_map(|i| {
                        let mut u = [0; 16];
                        u[0] = i;
                        u
                    })
                    .collect()),
                op::GET_CRED_BY_UUID => c.creds.get(args[0] as usize).cloned().ok_or(CC_END),
                op::RETRIEVE | op::REMOVE_CRED => Err(CC_NOSUPP),
                op::DESTROY => {
                    self.caches.remove(&name);
                    Ok(vec![])
                }
                op::SET_KDC_OFFSET => {
                    c.offset = Some(args.try_into().unwrap());
                    Ok(vec![])
                }
                op::GET_KDC_OFFSET => c.offset.map(|o| o.to_vec()).ok_or(CC_NOSUPP),
                _ => Err(CC_NOSUPP),
            }
        }
    }

    fn serve(mut s: UnixStream, d: &std::sync::Mutex<Daemon>) {
        loop {
            let mut len = [0; 4];
            if s.read_exact(&mut len).is_err() {
                return;
            }
            let mut req = vec![0; u32::from_be_bytes(len) as usize];
            s.read_exact(&mut req).unwrap();
            let (status, payload) = match d.lock().unwrap().handle(&req) {
                Ok(p) => (0, p),
                Err(e) => (e, vec![]),
            };
            let mut body = status.to_be_bytes().to_vec();
            body.extend_from_slice(&payload);
            let mut out = (body.len() as u32).to_be_bytes().to_vec();
            out.extend_from_slice(&0u32.to_be_bytes());
            out.extend_from_slice(&body);
            s.write_all(&out).unwrap();
        }
    }

    fn start(heimdal: bool) -> (PathBuf, CcContext) {
        let dir = tmpdir("kcm");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("kcm.sock");
        let l = UnixListener::bind(&path).unwrap();
        let d: &'static _ = Box::leak(Box::new(std::sync::Mutex::new(Daemon {
            default: "1000".into(),
            heimdal,
            ..Default::default()
        })));
        std::thread::spawn(move || {
            for s in l.incoming() {
                let s = s.unwrap();
                std::thread::spawn(move || serve(s, d));
            }
        });
        let c = CcContext {
            default_name: Some("KCM:".into()),
            kcm_socket: Some(path.display().to_string()),
            ..Default::default()
        };
        (dir, c)
    }

    fn exercise(heimdal: bool) {
        let (dir, c) = start(heimdal);
        let mut primary = default_cache(&c).unwrap();
        assert_eq!(primary.name(), "KCM:1000");
        assert!(matches!(primary.principal(), Err(CcError::NoFile(m)) if m.contains("'KCM:1000'")));
        primary.initialize(&princ(&["alice"]), REALM).unwrap();
        primary.store(&cred("krbtgt")).unwrap();
        primary.store(&cred("host")).unwrap();
        assert_eq!(primary.principal().unwrap().0, princ(&["alice"]));
        assert_eq!(primary.creds().unwrap().len(), 2);
        // RETRIEVE is unsupported here, so it falls back to iteration.
        let got = primary
            .retrieve(MatchFlags::empty(), &server_match("host"), None)
            .unwrap();
        assert_eq!(got.ticket, b"host");

        let mut second = new_unique(&c, "KCM").unwrap();
        assert_eq!(second.name(), "KCM:1000:1");
        second.initialize(&princ(&["bob"]), REALM).unwrap();
        let names: Vec<_> = collection(&c)
            .unwrap()
            .iter()
            .map(AnyCcache::name)
            .collect();
        assert_eq!(names, vec!["KCM:1000", "KCM:1000:1"]);
        second.switch_to().unwrap();
        assert_eq!(default_cache(&c).unwrap().name(), "KCM:1000:1");
        assert_eq!(
            cache_match(&c, &princ(&["alice"]), REALM).unwrap().name(),
            "KCM:1000"
        );
        let single = CcContext {
            default_name: Some("KCM:1000".into()),
            ..c.clone()
        };
        assert_eq!(collection(&single).unwrap().len(), 1);
        second.destroy().unwrap();
        let names: Vec<_> = collection(&c)
            .unwrap()
            .iter()
            .map(AnyCcache::name)
            .collect();
        assert_eq!(names, vec!["KCM:1000"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn kcm_with_mit_extensions() {
        exercise(false);
    }

    #[test]
    fn kcm_heimdal_fallbacks() {
        exercise(true);
    }

    #[test]
    fn kcm_replace_falls_back_and_keeps_offset() {
        let (dir, c) = start(true);
        let AnyCcache::Kcm(mut k) = default_cache(&c).unwrap() else {
            panic!("not KCM");
        };
        k.set_time_offset(-5);
        k.replace(&princ(&["alice"]), REALM, &[cred("a"), cred("b")])
            .unwrap();
        assert_eq!(k.creds().unwrap().len(), 2);
        assert_eq!(k.time_offset(), Some(-5));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn kcm_no_server() {
        let c = CcContext {
            kcm_socket: Some("/nonexistent/kcm.sock".into()),
            ..Default::default()
        };
        assert!(matches!(
            resolve(&c, "KCM:x"),
            Err(CcError::Code {
                name: "KRB5_KCM_NO_SERVER",
                ..
            })
        ));
        let off = CcContext {
            kcm_socket: Some("-".into()),
            ..Default::default()
        };
        assert!(matches!(
            resolve(&off, "KCM:x"),
            Err(CcError::Code {
                name: "KRB5_KCM_NO_SERVER",
                ..
            })
        ));
    }
}
