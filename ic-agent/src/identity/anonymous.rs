use crate::{
    export::{Principal, SignedDelegation},
    identity::Identity,
    Signature,
};

/// The anonymous identity.
///
/// The caller will be represented as [`Principal::anonymous`], or `2vxsx-fae`.
#[derive(Debug, Copy, Clone)]
pub struct AnonymousIdentity;

impl Identity for AnonymousIdentity {
    fn sender(&self) -> Result<Principal, String> {
        Ok(Principal::anonymous())
    }

    fn sign(&self, _blob: &[u8]) -> Result<Signature, String> {
        Ok(Signature {
            signature: None,
            public_key: None,
        })
    }

    fn delegation(&self) -> Option<Vec<SignedDelegation>> {
        None
    }
}
