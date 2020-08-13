use crate::{Blob, Identity, Principal, Signature};
use ring::signature::{Ed25519KeyPair, KeyPair};

pub struct BasicIdentity {
    key_pair: Ed25519KeyPair,
}

impl BasicIdentity {
    pub fn from_key_pair(key_pair: Ed25519KeyPair) -> Self {
        Self { key_pair }
    }
}

impl Identity for BasicIdentity {
    fn sender(&self) -> Result<Principal, String> {
        Ok(Principal::self_authenticating(&self.key_pair.public_key()))
    }
    fn sign(&self, msg: &[u8], _principal: &Principal) -> Result<Signature, String> {
        let signature = self.key_pair.sign(msg.as_ref());
        // At this point we shall validate the signature in this first
        // skeleton version.
        let public_key_bytes = self.key_pair.public_key().as_ref();

        Ok(Signature {
            signature: Blob::from(signature.as_ref()),
            public_key: Blob::from(public_key_bytes),
        })
    }
}
