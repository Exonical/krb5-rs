//! `kadm5.acl` restrictions: the fourth field of an ACL line, which
//! constrains the principals a matching administrator may create or modify
//! (`auth_acl.c:155-238` `parse_restrictions`, `auth.c:206-266`
//! `impose_restrictions`).

use super::admin::AttrChange;

/// `KADM5_PRINC_EXPIRE_TIME` (`kadm5/admin.h:89`).
pub const KADM5_PRINC_EXPIRE_TIME: u32 = 0x00_0002;
/// `KADM5_PW_EXPIRATION`.
pub const KADM5_PW_EXPIRATION: u32 = 0x00_0004;
/// `KADM5_ATTRIBUTES`.
pub const KADM5_ATTRIBUTES: u32 = 0x00_0010;
/// `KADM5_MAX_LIFE`.
pub const KADM5_MAX_LIFE: u32 = 0x00_0020;
/// `KADM5_POLICY`.
pub const KADM5_POLICY: u32 = 0x00_0800;
/// `KADM5_POLICY_CLR`.
pub const KADM5_POLICY_CLR: u32 = 0x00_1000;
/// `KADM5_MAX_RLIFE`.
pub const KADM5_MAX_RLIFE: u32 = 0x00_2000;

/// Parsed restrictions (`struct kadm5_auth_restrictions`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclRestrictions {
    /// `KADM5_*` fields the restrictions cover.
    pub mask: u32,
    /// Attribute bits forced on.
    pub require_attrs: u32,
    /// Attribute bits kept (cleared bits are forced off).
    pub forbid_attrs: u32,
    /// `-policy`.
    pub policy: Option<String>,
    /// `-expire` delta.
    pub princ_lifetime: i32,
    /// `-pwexpire` delta.
    pub pw_lifetime: i32,
    /// `-maxlife`.
    pub max_life: i32,
    /// `-maxrenewlife`.
    pub max_renewable_life: i32,
}

/// The `kadm5_principal_ent_rec` fields restrictions act on. Timestamps are
/// `krb5_timestamp`s, compared as unsigned like MIT's `ts_after`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestrictedEntry {
    /// `attributes`.
    pub attributes: u32,
    /// `policy`.
    pub policy: Option<String>,
    /// `princ_expire_time`.
    pub princ_expire_time: i32,
    /// `pw_expiration`.
    pub pw_expiration: i32,
    /// `max_life`.
    pub max_life: i32,
    /// `max_renewable_life`.
    pub max_renewable_life: i32,
}

fn ts_after(a: i32, b: i32) -> bool {
    a as u32 > b as u32
}

impl AclRestrictions {
    /// `parse_restrictions`: `[+-]flag`, `-clearpolicy`, `-policy POL`,
    /// `-expire`, `-pwexpire`, `-maxlife` and `-maxrenewlife` with a delta
    /// time. `None` for anything else, a missing argument or a second
    /// `-policy`.
    pub fn parse(s: &str) -> Option<Self> {
        let mut rs = AclRestrictions {
            mask: 0,
            require_attrs: 0,
            forbid_attrs: !0,
            policy: None,
            princ_lifetime: 0,
            pw_lifetime: 0,
            max_life: 0,
            max_renewable_life: 0,
        };
        let delim = |c: char| matches!(c, '\t' | '\n' | '\x0c' | '\x0b' | '\r' | ' ' | ',');
        let mut tokens = s.split(delim).filter(|t| !t.is_empty());
        while let Some(token) = tokens.next() {
            let mut flag = AttrChange::default();
            if flag.add_spec(token).is_ok() {
                rs.require_attrs |= flag.set;
                rs.forbid_attrs &= !flag.clear;
                rs.mask |= KADM5_ATTRIBUTES;
                continue;
            }
            if token == "-clearpolicy" {
                rs.mask |= KADM5_POLICY_CLR;
                continue;
            }
            let arg = tokens.next()?;
            if token == "-policy" {
                if rs.policy.is_some() {
                    return None;
                }
                rs.policy = Some(arg.to_string());
                rs.mask |= KADM5_POLICY;
                continue;
            }
            let delta = crate::profile::string_to_deltat(arg).ok()?;
            match token {
                "-expire" => {
                    rs.princ_lifetime = delta;
                    rs.mask |= KADM5_PRINC_EXPIRE_TIME;
                }
                "-pwexpire" => {
                    rs.pw_lifetime = delta;
                    rs.mask |= KADM5_PW_EXPIRATION;
                }
                "-maxlife" => {
                    rs.max_life = delta;
                    rs.mask |= KADM5_MAX_LIFE;
                }
                "-maxrenewlife" => {
                    rs.max_renewable_life = delta;
                    rs.mask |= KADM5_MAX_RLIFE;
                }
                _ => return None,
            }
        }
        Some(rs)
    }

    /// `impose_restrictions`: force the restricted fields of an add or
    /// modify request, given its `KADM5_*` mask and the current time.
    pub fn impose(&self, ent: &mut RestrictedEntry, mask: &mut u32, now: i32) {
        if self.mask & KADM5_ATTRIBUTES != 0 {
            ent.attributes |= self.require_attrs;
            ent.attributes &= self.forbid_attrs;
            *mask |= KADM5_ATTRIBUTES;
        }
        if self.mask & KADM5_POLICY_CLR != 0 {
            *mask &= !KADM5_POLICY;
            *mask |= KADM5_POLICY_CLR;
        } else if self.mask & KADM5_POLICY != 0 {
            if ent.policy != self.policy {
                ent.policy.clone_from(&self.policy);
            }
            *mask |= KADM5_POLICY;
        }
        if self.mask & KADM5_PRINC_EXPIRE_TIME != 0 {
            let limit = now.wrapping_add(self.princ_lifetime);
            if *mask & KADM5_PRINC_EXPIRE_TIME == 0 || ts_after(ent.princ_expire_time, limit) {
                ent.princ_expire_time = limit;
            }
            *mask |= KADM5_PRINC_EXPIRE_TIME;
        }
        if self.mask & KADM5_PW_EXPIRATION != 0 {
            let limit = now.wrapping_add(self.pw_lifetime);
            if *mask & KADM5_PW_EXPIRATION == 0 || ts_after(ent.pw_expiration, limit) {
                ent.pw_expiration = limit;
            }
            *mask |= KADM5_PW_EXPIRATION;
        }
        if self.mask & KADM5_MAX_LIFE != 0 {
            if *mask & KADM5_MAX_LIFE == 0 || ent.max_life > self.max_life {
                ent.max_life = self.max_life;
            }
            *mask |= KADM5_MAX_LIFE;
        }
        if self.mask & KADM5_MAX_RLIFE != 0 {
            if *mask & KADM5_MAX_RLIFE == 0 || ent.max_renewable_life > self.max_renewable_life {
                ent.max_renewable_life = self.max_renewable_life;
            }
            *mask |= KADM5_MAX_RLIFE;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_restriction_kind() {
        let rs = AclRestrictions::parse(
            "+requires_preauth,-allow_tix -policy std -expire 1d -pwexpire 2h \
             -maxlife 10h -maxrenewlife 7d",
        )
        .expect("valid");
        assert_eq!(
            rs.mask,
            KADM5_ATTRIBUTES
                | KADM5_POLICY
                | KADM5_PRINC_EXPIRE_TIME
                | KADM5_PW_EXPIRATION
                | KADM5_MAX_LIFE
                | KADM5_MAX_RLIFE
        );
        assert_eq!(rs.require_attrs, 0x80 | 0x40);
        assert_eq!(rs.forbid_attrs, !0);
        assert_eq!(rs.policy.as_deref(), Some("std"));
        assert_eq!(
            (
                rs.princ_lifetime,
                rs.pw_lifetime,
                rs.max_life,
                rs.max_renewable_life
            ),
            (86_400, 7_200, 36_000, 604_800)
        );
        let rs =
            AclRestrictions::parse("-requires_preauth +allow_tix -clearpolicy").expect("valid");
        assert_eq!(rs.require_attrs, 0);
        assert_eq!(rs.forbid_attrs, !0x80 & !0x40);
        assert_eq!(rs.mask, KADM5_ATTRIBUTES | KADM5_POLICY_CLR);
    }

    #[test]
    fn rejects_what_mit_rejects() {
        for bad in [
            "-policy",
            "-policy a -policy b",
            "-expire",
            "-expire soon",
            "-bogus 1d",
            "frobnicate 1d",
        ] {
            assert!(AclRestrictions::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn imposes_like_mit() {
        let rs = AclRestrictions::parse(
            "+requires_preauth +allow_svr -policy std -expire 1d -maxlife 1h",
        )
        .expect("valid");
        let now = 1_000_000;
        // Fields absent from the request are forced to the restriction.
        let mut ent = RestrictedEntry {
            attributes: 0x1000 | 0x1,
            ..Default::default()
        };
        let mut mask = 0;
        rs.impose(&mut ent, &mut mask, now);
        assert_eq!(ent.attributes, 0x80 | 0x1);
        assert_eq!(ent.policy.as_deref(), Some("std"));
        assert_eq!(ent.princ_expire_time, now + 86_400);
        assert_eq!(ent.max_life, 3_600);
        assert_eq!(
            mask,
            KADM5_ATTRIBUTES | KADM5_POLICY | KADM5_PRINC_EXPIRE_TIME | KADM5_MAX_LIFE
        );
        // Requested values within the limit are kept; larger ones capped.
        let mut ent = RestrictedEntry {
            policy: Some("other".into()),
            princ_expire_time: now + 60,
            max_life: 7_200,
            ..Default::default()
        };
        let mut mask = KADM5_PRINC_EXPIRE_TIME | KADM5_MAX_LIFE | KADM5_POLICY;
        rs.impose(&mut ent, &mut mask, now);
        assert_eq!(ent.princ_expire_time, now + 60);
        assert_eq!(ent.max_life, 3_600);
        assert_eq!(ent.policy.as_deref(), Some("std"));
        // "Never" (0) is after nothing, so it is kept, as in MIT.
        let mut ent = RestrictedEntry::default();
        let mut mask = KADM5_PRINC_EXPIRE_TIME;
        rs.impose(&mut ent, &mut mask, now);
        assert_eq!(ent.princ_expire_time, 0);
    }

    #[test]
    fn clearpolicy_wins_over_a_requested_policy() {
        let rs = AclRestrictions::parse("-clearpolicy").expect("valid");
        let mut ent = RestrictedEntry {
            policy: Some("p".into()),
            ..Default::default()
        };
        let mut mask = KADM5_POLICY;
        rs.impose(&mut ent, &mut mask, 0);
        assert_eq!(mask, KADM5_POLICY_CLR);
    }
}
