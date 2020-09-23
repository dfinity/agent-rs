use crate::identity::Identity;
use crate::Signature;
use ic_types::Principal;

pub(crate) struct DummyIdentity {}

impl Identity for DummyIdentity {
    fn sender(&self) -> Result<Principal, String> {
        Ok(Principal::anonymous())
    }

    fn sign(&self, _blob: &[u8], _principal: &Principal) -> Result<Signature, String> {
        Ok(Signature {
            signature: vec![1; 32],
            public_key: vec![2; 32],
        })
    }
}
