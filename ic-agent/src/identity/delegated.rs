use candid::Principal;

use crate::{agent::EnvelopeContent, Signature};

use super::{Delegation, Identity, SignedDelegation};

/// An identity that has been delegated the authority to authenticate as a different principal.
pub struct DelegatedIdentity {
    to: Box<dyn Identity>,
    chain: Vec<SignedDelegation>,
    principal: Principal,
}

impl DelegatedIdentity {
    /// Creates a delegated identity that signs using `identity`, for the principal derived from `from.pubkey`.
    ///
    /// `from` must be a delegation to `to.public_key()`. For more than one delegation in the chain, use [`for_principal`](Self::for_principal).
    pub fn new(to: Box<dyn Identity>, from: Delegation, signature: Vec<u8>) -> Self {
        let public_key = from.pubkey.clone();
        Self::for_principal(
            Principal::self_authenticating(public_key),
            to,
            vec![SignedDelegation {
                delegation: from,
                signature,
            }],
        )
    }
    /// Creates a delegated identity that signs using `identity`, for `principal`.
    ///
    /// `chain` must be a list of delegations connecting `principal` to `to.public_key()`, and in that order.
    pub fn for_principal(
        principal: Principal,
        to: Box<dyn Identity>,
        chain: Vec<SignedDelegation>,
    ) -> Self {
        Self {
            to,
            principal,
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

impl Identity for DelegatedIdentity {
    fn sender(&self) -> Result<Principal, String> {
        Ok(self.principal)
    }
    fn public_key(&self) -> Option<Vec<u8>> {
        Some(self.chain[0].delegation.pubkey.clone())
    }
    fn sign(&self, content: &EnvelopeContent) -> Result<Signature, String> {
        self.to.sign(content).map(|sig| self.chain_signature(sig))
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
