use crate::identity::Identity;
use crate::{Blob, Principal, Signature};

pub(crate) struct DummyIdentity {}

impl Identity for DummyIdentity {
    fn sender(&self) -> Result<Principal, String> {
        Ok(Principal::anonymous())
    }

    fn sign(&self, _blob: &[u8], _principal: &Principal) -> Result<Signature, String> {
        Ok(Signature {
            signature: Blob::from(vec![1; 32]),
            public_key: Blob::from(vec![2; 32]),
        })
    }
}
