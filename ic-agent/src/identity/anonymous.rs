use crate::{export::Principal, identity::Identity, Signature};

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
}
