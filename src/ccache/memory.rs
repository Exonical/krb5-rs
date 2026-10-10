//! MEMORY ccache (cc_memory.c): in-memory list semantics.

use super::retrieve::retrieve_in;
use super::{
    config_cred, config_matches, CcCredential, CcError, Ccache, MatchCred, MatchFlags, CONFIG_REALM,
};
use crate::types::PrincipalName;

/// An in-memory credential cache.
#[derive(Default)]
pub struct MemoryCcache {
    principal: Option<(PrincipalName, String)>,
    creds: Vec<CcCredential>,
}

impl MemoryCcache {
    /// An uninitialized cache.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Ccache for MemoryCcache {
    fn initialize(&mut self, client: &PrincipalName, realm: &str) -> Result<(), CcError> {
        self.principal = Some((client.clone(), realm.to_string()));
        self.creds.clear();
        Ok(())
    }

    fn principal(&self) -> Result<(PrincipalName, String), CcError> {
        self.principal.clone().ok_or(CcError::NotFound)
    }

    fn store(&mut self, cred: &CcCredential) -> Result<(), CcError> {
        self.creds.push(cred.clone());
        Ok(())
    }

    fn creds(&self) -> Result<Vec<CcCredential>, CcError> {
        Ok(self.creds.clone())
    }

    fn remove_cred(&mut self, flags: MatchFlags, m: &MatchCred) -> Result<(), CcError> {
        // cc_memory.c: matching entries are deleted outright.
        match self
            .creds
            .iter()
            .position(|c| super::creds_match_request(flags, m, c))
        {
            Some(i) => {
                self.creds.remove(i);
                Ok(())
            }
            None => Err(CcError::NotFound),
        }
    }

    fn retrieve(
        &self,
        flags: MatchFlags,
        m: &MatchCred,
        ktypes: Option<&[i32]>,
    ) -> Result<CcCredential, CcError> {
        retrieve_in(&self.creds, flags, m, ktypes)
    }

    fn set_config(
        &mut self,
        principal: Option<(&PrincipalName, &str)>,
        key: &str,
        data: Option<&[u8]>,
    ) -> Result<(), CcError> {
        let target = super::config_principal(principal, key);
        let m = MatchCred {
            server: Some((target, CONFIG_REALM.to_string())),
            ..Default::default()
        };
        let _ = self.remove_cred(MatchFlags::empty(), &m);
        if let Some(data) = data {
            let (client, realm) = self.principal()?;
            self.creds
                .push(config_cred(&client, &realm, principal, key, data));
        }
        Ok(())
    }

    fn get_config(
        &self,
        principal: Option<(&PrincipalName, &str)>,
        key: &str,
    ) -> Result<Option<Vec<u8>>, CcError> {
        Ok(self
            .creds
            .iter()
            .find(|c| config_matches(c, principal, key))
            .map(|c| c.ticket.clone()))
    }
}
