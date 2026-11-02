//! kadm5_auth modules: MIT's pluggable kadmind authorization
//! (`include/krb5/kadm5_auth_plugin.h`, `kadmin/server/auth.c`).
//!
//! kadmind asks every enabled module about each request. One [`Verdict::Deny`]
//! refuses it; otherwise at least one [`Verdict::Pass`] is needed
//! (`auth.c:182-202`). For `addprinc` and `modprinc`, each module may also
//! return restrictions, which are imposed on the request in module order
//! (`auth.c:268-305`).

use crate::kdc::kdb::kadm5::{PolicyEnt, PrincipalEnt};
use crate::kdc::kdb::restrictions::AclRestrictions;
use crate::types::PrincipalName;

/// A principal and its realm.
#[derive(Debug, Clone, Copy)]
pub struct Princ<'a> {
    /// The principal name.
    pub name: &'a PrincipalName,
    /// The principal's realm.
    pub realm: &'a str,
}

impl Princ<'_> {
    /// `krb5_principal_compare`.
    #[must_use]
    pub fn same(&self, other: &Princ<'_>) -> bool {
        self.realm == other.realm && self.name == other.name
    }
}

/// One kadm5 request, with the arguments MIT passes each module method.
#[derive(Debug, Clone, Copy)]
pub enum Request<'a> {
    /// `addprinc`: the `KADM5_*` mask and the requested policy.
    AddPrinc {
        /// The new principal.
        target: Princ<'a>,
        /// The request's field mask.
        mask: u32,
        /// The requested entry; only fields in `mask` are meaningful.
        ent: &'a PrincipalEnt,
    },
    /// `modprinc`.
    ModPrinc {
        /// The principal being changed.
        target: Princ<'a>,
        /// The request's field mask.
        mask: u32,
        /// The requested entry; only fields in `mask` are meaningful.
        ent: &'a PrincipalEnt,
    },
    /// `setstr` (a `None` value deletes the string).
    SetStr {
        /// The principal being changed.
        target: Princ<'a>,
        /// The string attribute's key.
        key: &'a str,
        /// The new value.
        value: Option<&'a str>,
    },
    /// `cpw` (also kpasswd).
    Cpw {
        /// The principal whose password changes.
        target: Princ<'a>,
    },
    /// `chrand`.
    Chrand {
        /// The principal whose keys are randomized.
        target: Princ<'a>,
    },
    /// `setkey`.
    SetKey {
        /// The principal whose keys are set.
        target: Princ<'a>,
    },
    /// `purgekeys`.
    PurgeKeys {
        /// The principal whose old keys are purged.
        target: Princ<'a>,
    },
    /// `delprinc`.
    DelPrinc {
        /// The principal being deleted.
        target: Princ<'a>,
    },
    /// `renprinc`.
    RenPrinc {
        /// The current name.
        src: Princ<'a>,
        /// The new name.
        dest: Princ<'a>,
    },
    /// `getprinc`.
    GetPrinc {
        /// The principal being read.
        target: Princ<'a>,
    },
    /// `getstrs`.
    GetStrs {
        /// The principal whose strings are read.
        target: Princ<'a>,
    },
    /// `getprinc` with keys (`kadmin.local ktadd -norandkey`).
    Extract {
        /// The principal whose keys are read.
        target: Princ<'a>,
    },
    /// `listprincs`.
    ListPrincs,
    /// `addpol`.
    AddPol {
        /// The new policy's name.
        policy: &'a str,
        /// The request's policy mask.
        mask: u32,
        /// The requested policy; only fields in `mask` are meaningful.
        ent: &'a PolicyEnt,
    },
    /// `modpol`.
    ModPol {
        /// The policy being changed.
        policy: &'a str,
        /// The request's policy mask.
        mask: u32,
        /// The requested policy; only fields in `mask` are meaningful.
        ent: &'a PolicyEnt,
    },
    /// `delpol`.
    DelPol {
        /// The policy being deleted.
        policy: &'a str,
    },
    /// `getpol`.
    GetPol {
        /// The policy being read.
        policy: &'a str,
        /// The client's own policy, if it has one.
        client_policy: Option<&'a str>,
    },
    /// `listpols`.
    ListPols,
    /// An iprop client.
    Iprop,
    /// `addalias`.
    AddAlias {
        /// The new alias.
        alias: Princ<'a>,
        /// The principal it names.
        target: Princ<'a>,
    },
}

/// `KRB5_PLUGIN_NO_HANDLE`.
pub const PLUGIN_NO_HANDLE: i32 = -1_765_328_135;

impl Request<'_> {
    /// MIT's `OP_*` number (`kadmin/server/auth.h`).
    #[must_use]
    pub fn opcode(&self) -> i32 {
        match self {
            Self::AddPrinc { .. } => 1,
            Self::ModPrinc { .. } => 2,
            Self::SetStr { .. } => 3,
            Self::Cpw { .. } => 4,
            Self::Chrand { .. } => 5,
            Self::SetKey { .. } => 6,
            Self::PurgeKeys { .. } => 7,
            Self::DelPrinc { .. } => 8,
            Self::RenPrinc { .. } => 9,
            Self::GetPrinc { .. } => 10,
            Self::GetStrs { .. } => 11,
            Self::Extract { .. } => 12,
            Self::ListPrincs => 13,
            Self::AddPol { .. } => 14,
            Self::ModPol { .. } => 15,
            Self::DelPol { .. } => 16,
            Self::GetPol { .. } => 17,
            Self::ListPols => 18,
            Self::Iprop => 19,
            Self::AddAlias { .. } => 20,
        }
    }
}

/// A module's answer: `0`, `KRB5_PLUGIN_NO_HANDLE`, or another error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The module authorizes the request.
    Pass,
    /// The module has no opinion.
    NoHandle,
    /// The module refuses the request.
    Deny,
}

/// One kadm5_auth module (`kadm5_auth_vtable`).
pub trait Kadm5Auth: Send + Sync {
    /// The module name used by `enable_only` and `disable`.
    fn name(&self) -> &str;

    /// Decide `req` for `client`. For `addprinc`/`modprinc` the module may
    /// also return restrictions, which are imposed whatever the verdict.
    fn authorize(&self, client: Princ<'_>, req: &Request<'_>)
        -> (Verdict, Option<AclRestrictions>);

    /// `end`: called once the request has been handled.
    fn end(&self) {}
}

/// MIT's built-in `self` module (`auth_self.c`): a principal may change its
/// own password or keys, purge its old keys, and read its own entry, strings
/// and policy.
#[derive(Debug, Default, Clone, Copy)]
pub struct SelfModule;

impl Kadm5Auth for SelfModule {
    fn name(&self) -> &str {
        "self"
    }

    fn authorize(
        &self,
        client: Princ<'_>,
        req: &Request<'_>,
    ) -> (Verdict, Option<AclRestrictions>) {
        let pass = match req {
            Request::Cpw { target }
            | Request::Chrand { target }
            | Request::PurgeKeys { target }
            | Request::GetPrinc { target }
            | Request::GetStrs { target } => client.same(target),
            Request::GetPol {
                policy,
                client_policy,
            } => *client_policy == Some(*policy),
            _ => false,
        };
        (
            if pass {
                Verdict::Pass
            } else {
                Verdict::NoHandle
            },
            None,
        )
    }
}

/// The enabled modules, in the order kadmind asks them.
#[derive(Default)]
pub struct Kadm5AuthModules {
    modules: Vec<Box<dyn Kadm5Auth>>,
}

impl std::fmt::Debug for Kadm5AuthModules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.modules.iter().map(|m| m.name()))
            .finish()
    }
}

impl Kadm5AuthModules {
    /// Modules in the order they are asked.
    #[must_use]
    pub fn new(modules: Vec<Box<dyn Kadm5Auth>>) -> Self {
        Self { modules }
    }

    /// The module names, in order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.modules.iter().map(|m| m.name())
    }

    /// `auth`/`auth_restrict`: `Some` with the restrictions to impose when
    /// the request is authorized, `None` when it is refused.
    #[must_use]
    pub fn authorize(&self, client: Princ<'_>, req: &Request<'_>) -> Option<Vec<AclRestrictions>> {
        let mut authorized = false;
        let mut restrictions = Vec::new();
        for m in &self.modules {
            let (verdict, rs) = m.authorize(client, req);
            if let Some(rs) = rs {
                restrictions.push(rs);
            }
            match verdict {
                Verdict::Pass => authorized = true,
                Verdict::Deny => return None,
                Verdict::NoHandle => {}
            }
        }
        authorized.then_some(restrictions)
    }

    /// `auth_end`.
    pub fn end(&self) {
        for m in &self.modules {
            m.end();
        }
    }
}

/// The module order of MIT's plugin framework (`plugin.c`
/// `configure_interface`): dynamic `module` entries in profile order, then
/// the built-in modules, dropping later duplicates; then `disable` removes
/// modules, and `enable_only`, if set, keeps only the modules it names, in
/// its order.
#[must_use]
pub fn module_order(
    dynamic: &[String],
    builtin: &[&str],
    enable_only: &[String],
    disable: &[String],
) -> Vec<String> {
    let mut list: Vec<String> = Vec::new();
    for name in dynamic
        .iter()
        .map(String::as_str)
        .chain(builtin.iter().copied())
    {
        if !list.iter().any(|n| n == name) {
            list.push(name.to_string());
        }
    }
    list.retain(|n| !disable.contains(n));
    if enable_only.is_empty() {
        return list;
    }
    enable_only
        .iter()
        .filter(|n| list.contains(n))
        .fold(Vec::new(), |mut out, n| {
            if !out.contains(n) {
                out.push(n.clone());
            }
            out
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_string()).collect()
    }

    #[test]
    fn module_order_matches_mit_plugin_framework() {
        let b = ["acl", "self"];
        assert_eq!(module_order(&[], &b, &[], &[]), s(&["acl", "self"]));
        assert_eq!(
            module_order(&s(&["x", "acl"]), &b, &[], &[]),
            s(&["x", "acl", "self"])
        );
        assert_eq!(
            module_order(&s(&["x"]), &b, &[], &s(&["acl"])),
            s(&["x", "self"])
        );
        assert_eq!(
            module_order(&s(&["w", "b"]), &b, &s(&["b", "w", "nope"]), &[]),
            s(&["b", "w"])
        );
    }

    struct Fixed(&'static str, Verdict);
    impl Kadm5Auth for Fixed {
        fn name(&self) -> &str {
            self.0
        }
        fn authorize(&self, _: Princ<'_>, _: &Request<'_>) -> (Verdict, Option<AclRestrictions>) {
            (self.1, None)
        }
    }

    #[test]
    fn one_deny_refuses_and_one_pass_is_needed() {
        let name = PrincipalName::new_principal("u");
        let c = Princ {
            name: &name,
            realm: "R",
        };
        let m = |v: Vec<Verdict>| {
            Kadm5AuthModules::new(
                v.into_iter()
                    .map(|v| Box::new(Fixed("f", v)) as Box<dyn Kadm5Auth>)
                    .collect(),
            )
            .authorize(c, &Request::ListPols)
            .is_some()
        };
        assert!(!m(vec![]));
        assert!(!m(vec![Verdict::NoHandle]));
        assert!(m(vec![Verdict::NoHandle, Verdict::Pass]));
        assert!(!m(vec![Verdict::Pass, Verdict::Deny]));
    }

    #[test]
    fn self_module_matches_auth_self() {
        let u = PrincipalName::new_principal("u");
        let v = PrincipalName::new_principal("v");
        let me = Princ {
            name: &u,
            realm: "R",
        };
        let other = Princ {
            name: &v,
            realm: "R",
        };
        let pass = |r: Request<'_>| SelfModule.authorize(me, &r).0 == Verdict::Pass;
        assert!(pass(Request::Cpw { target: me }));
        assert!(pass(Request::GetStrs { target: me }));
        assert!(!pass(Request::Cpw { target: other }));
        assert!(!pass(Request::SetKey { target: me }));
        assert!(pass(Request::GetPol {
            policy: "p",
            client_policy: Some("p")
        }));
        assert!(!pass(Request::GetPol {
            policy: "p",
            client_policy: None
        }));
    }
}
