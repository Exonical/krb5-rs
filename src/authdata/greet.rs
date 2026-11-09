//! MIT's sample client authdata module, `greet_client`
//! (plugins/authdata/greet_client/greet.c): the `urn:greet:greeting` name
//! attribute from the KDC's [`AD_GREET`] authdata.

use super::{
    AuthdataModule, AuthdataRequestContext, NameAttrValue, Principal, AD_INFORMATIONAL,
    AD_USAGE_AP_REQ, AD_USAGE_KDC_ISSUED, EEXIST, EINVAL, ENOENT,
};
use crate::types::AuthorizationDataElement;

/// The greet authdata type.
pub const AD_GREET: i32 = -42;
/// The greeting attribute.
pub const GREET_ATTR: &str = "urn:greet:greeting";

/// The `greet` client module.
pub struct GreetClient;

impl AuthdataModule for GreetClient {
    fn name(&self) -> &str {
        "greet"
    }
    fn ad_types(&self) -> &[i32] {
        &[AD_GREET]
    }
    fn flags(&self, _ad_type: i32) -> u32 {
        AD_USAGE_AP_REQ | AD_USAGE_KDC_ISSUED | AD_INFORMATIONAL
    }
    fn request_init(&self) -> Result<Box<dyn AuthdataRequestContext>, i32> {
        Ok(Box::new(GreetContext::default()))
    }
}

/// `struct greet_context`.
#[derive(Debug, Clone, Default)]
struct GreetContext {
    greeting: Vec<u8>,
    verified: bool,
}

impl AuthdataRequestContext for GreetContext {
    fn import_authdata(
        &mut self,
        authdata: &[AuthorizationDataElement],
        kdc_issued: bool,
        _issuer: Option<&Principal>,
    ) -> Result<(), i32> {
        self.greeting = authdata
            .first()
            .map(|a| a.ad_data.to_vec())
            .unwrap_or_default();
        self.verified = kdc_issued;
        Ok(())
    }

    fn get_attribute_types(&self) -> Result<Vec<String>, i32> {
        if self.greeting.is_empty() {
            return Err(ENOENT);
        }
        Ok(vec![GREET_ATTR.to_string()])
    }

    fn get_attribute(&self, attribute: &str) -> Result<Vec<NameAttrValue>, i32> {
        if attribute.as_bytes() != GREET_ATTR.as_bytes() || self.greeting.is_empty() {
            return Err(ENOENT);
        }
        Ok(vec![NameAttrValue {
            value: self.greeting.clone(),
            display_value: self.greeting.clone(),
            authenticated: self.verified,
            complete: true,
        }])
    }

    fn set_attribute(&mut self, _complete: bool, attribute: &str, value: &[u8]) -> Result<(), i32> {
        if attribute.as_bytes() != GREET_ATTR.as_bytes() {
            return Err(ENOENT);
        }
        if !self.greeting.is_empty() {
            return Err(EEXIST);
        }
        self.greeting = value.to_vec();
        self.verified = false;
        Ok(())
    }

    fn delete_attribute(&mut self, _attribute: &str) -> Result<(), i32> {
        self.greeting.clear();
        self.verified = false;
        Ok(())
    }

    fn export_authdata(&self, _usage: u32) -> Option<Result<Vec<AuthorizationDataElement>, i32>> {
        Some(Ok(vec![AuthorizationDataElement {
            ad_type: AD_GREET,
            ad_data: self.greeting.clone().into(),
        }]))
    }

    /// Greeting length, greeting, verified.
    fn externalize(&self) -> Option<Vec<u8>> {
        let mut out = (self.greeting.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(&self.greeting);
        out.extend_from_slice(&u32::from(self.verified).to_be_bytes());
        Some(out)
    }

    fn internalize(&mut self, buf: &mut &[u8]) -> Result<(), i32> {
        let take = |b: &mut &[u8], n: usize| -> Result<Vec<u8>, i32> {
            if b.len() < n {
                return Err(EINVAL);
            }
            let (head, rest) = b.split_at(n);
            *b = rest;
            Ok(head.to_vec())
        };
        let mut b = *buf;
        let len = u32::from_be_bytes(take(&mut b, 4)?.try_into().map_err(|_| EINVAL)?);
        let greeting = take(&mut b, len as usize)?;
        let verified = u32::from_be_bytes(take(&mut b, 4)?.try_into().map_err(|_| EINVAL)?);
        self.greeting = greeting;
        self.verified = verified != 0;
        *buf = b;
        Ok(())
    }
}
