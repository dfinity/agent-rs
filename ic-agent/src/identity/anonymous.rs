use crate::{agent::EnvelopeContent, export::Principal, identity::Identity, Signature};

/// The anonymous identity.
///
/// The caller will be represented as [`Principal::anonymous`], or `2vxsx-fae`.
#[derive(Debug, Copy, Clone)]
pub struct AnonymousIdentity;

impl Identity for AnonymousIdentity {
    fn sender(&self) -> Result<Principal, String> {
        Ok(Principal::anonymous())
    }

    fn sign(&self, _: &EnvelopeContent) -> Result<Signature, String> {
        Ok(Signature {
            signature: None,
            public_key: None,
        })
    }
}
