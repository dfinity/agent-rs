use async_trait::async_trait;
use candid::Principal;

use crate::{agent::EnvelopeContent, Signature};

use super::{Delegation, Identity, SignedDelegation};

/// An identity that has been delegated the authority to authenticate as a different principal.
pub struct DelegatedIdentity {
    to: Box<dyn Identity>,
    chain: Vec<SignedDelegation>,
    from_key: Vec<u8>,
}

impl DelegatedIdentity {
    /// Creates a delegated identity that signs using `to`, for the principal corresponding to the public key `from_key`.
    ///
    /// `chain` must be a list of delegations connecting `from_key` to `to.public_key()`, and in that order.
    pub fn new(from_key: Vec<u8>, to: Box<dyn Identity>, chain: Vec<SignedDelegation>) -> Self {
        Self {
            to,
            from_key,
            chain,
        }
    }

    fn chain_signature(&self, mut sig: Signature) -> Signature {
        sig.public_key = self.public_key();
        sig.delegations
            .get_or_insert(vec![])
            .extend(self.chain.iter().cloned());
        sig
    }
}

#[async_trait]
impl Identity for DelegatedIdentity {
    fn sender(&self) -> Result<Principal, String> {
        Ok(Principal::self_authenticating(&self.from_key))
    }
    fn public_key(&self) -> Option<Vec<u8>> {
        Some(self.from_key.clone())
    }
    async fn sign(&self, content: &EnvelopeContent) -> Result<Signature, String> {
        self.to
            .sign(content)
            .await
            .map(|sig| self.chain_signature(sig))
    }
    fn sign_delegation(&self, content: &Delegation) -> Result<Signature, String> {
        self.to
            .sign_delegation(content)
            .map(|sig| self.chain_signature(sig))
    }
    fn sign_arbitrary(&self, content: &[u8]) -> Result<Signature, String> {
        self.to
            .sign_arbitrary(content)
            .map(|sig| self.chain_signature(sig))
    }
    fn delegation_chain(&self) -> Vec<SignedDelegation> {
        let mut chain = self.to.delegation_chain();
        chain.extend(self.chain.iter().cloned());
        chain
    }
}
