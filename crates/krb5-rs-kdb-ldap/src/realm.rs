//! The realm container (`krb5_ldap_read_realm_params`, ldap_realm.c:740-860)
//! and the subtrees principals are searched in (`krb5_get_subtree_info`,
//! ldap_misc.c:520-570).

/// `LDAP_SCOPE_ONELEVEL`.
pub const SCOPE_ONE: i32 = 1;
/// `LDAP_SCOPE_SUBTREE`, the default.
pub const SCOPE_SUB: i32 = 2;

/// The realm object's parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealmParams {
    /// `cn=<REALM>,<container>`.
    pub realm_dn: String,
    /// `krbSubTrees`.
    pub subtrees: Vec<String>,
    /// `krbPrincContainerRef`.
    pub container_ref: Option<String>,
    /// `krbSearchScope` (1 or 2, else 2).
    pub search_scope: i32,
    /// `krbMaxTicketLife` (0 when absent).
    pub max_life: i32,
    /// `krbMaxRenewableAge` (0 when absent).
    pub max_renewable_life: i32,
    /// `krbTicketFlags` (0 when absent).
    pub tkt_flags: i32,
}

impl RealmParams {
    /// Read the realm object's attributes.
    pub fn from_attrs(realm_dn: String, a: &crate::entry::Attrs) -> Self {
        let int = |n: &str| a.first(n).and_then(|v| v.trim().parse().ok()).unwrap_or(0);
        let scope = int("krbsearchscope");
        RealmParams {
            realm_dn,
            subtrees: a.text.get("krbsubtrees").cloned().unwrap_or_default(),
            container_ref: a.first("krbprinccontainerref").map(str::to_string),
            search_scope: if scope == SCOPE_ONE || scope == SCOPE_SUB {
                scope
            } else {
                SCOPE_SUB
            },
            max_life: int("krbmaxticketlife"),
            max_renewable_life: int("krbmaxrenewableage"),
            tkt_flags: int("krbticketflags"),
        }
    }

    /// `krb5_get_subtree_info`: the subtrees, then the realm DN and the
    /// container reference, without repeats or (for subtree scope) nested
    /// entries.
    pub fn search_bases(&self) -> Vec<String> {
        let mut list = self.subtrees.clone();
        list.push(self.realm_dn.clone());
        list.extend(self.container_ref.clone());
        remove_overlapping_subtrees(&mut list, self.search_scope);
        list
    }
}

/// Whether `dn1` is strictly below `dn2`.
fn is_subtree(dn1: &str, dn2: &str) -> bool {
    let (l1, l2) = (dn1.len(), dn2.len());
    l1 > l2
        && dn1.as_bytes()[l1 - l2 - 1] == b','
        && dn1.is_char_boundary(l1 - l2)
        && dn1[l1 - l2..].eq_ignore_ascii_case(dn2)
}

/// `remove_overlapping_subtrees` (ldap_misc.c:1318-1347), including its
/// swap-with-last removal order.
pub fn remove_overlapping_subtrees(list: &mut Vec<String>, scope: i32) {
    let mut i = 0;
    'outer: while i < list.len() {
        let mut j = i + 1;
        while j < list.len() {
            let same = list[j].len() == list[i].len() && list[j].eq_ignore_ascii_case(&list[i]);
            if same || (scope == SCOPE_SUB && is_subtree(&list[j], &list[i])) {
                list.swap_remove(j);
            } else if scope == SCOPE_SUB && is_subtree(&list[i], &list[j]) {
                list.swap_remove(i);
                continue 'outer;
            } else {
                j += 1;
            }
        }
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlapping_subtrees() {
        let mut l = vec![
            "ou=a,dc=x".to_string(),
            "dc=x".to_string(),
            "OU=A,DC=X".to_string(),
            "ou=b,dc=y".to_string(),
        ];
        remove_overlapping_subtrees(&mut l, SCOPE_SUB);
        assert_eq!(l, ["ou=b,dc=y", "dc=x"]);
        let mut l = vec![
            "ou=a,dc=x".to_string(),
            "dc=x".to_string(),
            "OU=A,DC=X".to_string(),
        ];
        remove_overlapping_subtrees(&mut l, SCOPE_ONE);
        assert_eq!(l, ["ou=a,dc=x", "dc=x"]);
    }
}
