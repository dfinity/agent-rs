use candid::Principal;
use der::{Decode, SliceReader};
use ecdsa::signature::Verifier;
use k256::Secp256k1;
use p256::NistP256;
use pkcs8::{spki::SubjectPublicKeyInfoRef, AssociatedOid, ObjectIdentifier};
use sec1::{EcParameters, EncodedPoint};

use crate::{agent::EnvelopeContent, Signature};

use super::{error::DelegationError, Delegation, Identity, SignedDelegation};

/// An identity that has been delegated the authority to authenticate as a different principal.
pub struct DelegatedIdentity {
    to: Box<dyn Identity>,
    chain: Vec<SignedDelegation>,
    from_key: Vec<u8>,
}

impl DelegatedIdentity {
    /// Creates a delegated identity that signs using `to`, for the principal corresponding to the public key `from_key`.
    ///
    /// `chain` must be a list of delegations connecting `from_key` to `to.public_key()`, and in that order;
    /// otherwise, this function will return an error.
    pub fn new(
        from_key: Vec<u8>,
        to: Box<dyn Identity>,
        chain: Vec<SignedDelegation>,
    ) -> Result<Self, DelegationError> {
        let mut last_verified = &from_key;
        for delegation in &chain {
            let spki = SubjectPublicKeyInfoRef::decode(
                &mut SliceReader::new(&last_verified[..]).map_err(|_| DelegationError::Parse)?,
            )
            .map_err(|_| DelegationError::Parse)?;
            if spki.algorithm.oid == elliptic_curve::ALGORITHM_OID {
                let Some(params) = spki.algorithm.parameters else {
                    return Err(DelegationError::UnknownAlgorithm);
                };
                let params = params
                    .decode_as::<EcParameters>()
                    .map_err(|_| DelegationError::Parse)?;
                let curve = params
                    .named_curve()
                    .ok_or(DelegationError::UnknownAlgorithm)?;
                if curve == Secp256k1::OID {
                    let pt = EncodedPoint::from_bytes(spki.subject_public_key.raw_bytes())
                        .map_err(|_| DelegationError::Parse)?;
                    let vk = k256::ecdsa::VerifyingKey::from_encoded_point(&pt)
                        .map_err(|_| DelegationError::Parse)?;
                    let sig = k256::ecdsa::Signature::try_from(&delegation.signature[..])
                        .map_err(|_| DelegationError::Parse)?;
                    vk.verify(&delegation.delegation.signable(), &sig)
                        .map_err(|_| DelegationError::BrokenChain {
                            from: last_verified.clone(),
                            to: Some(delegation.delegation.clone()),
                        })?;
                } else if curve == NistP256::OID {
                    let pt = EncodedPoint::from_bytes(spki.subject_public_key.raw_bytes())
                        .map_err(|_| DelegationError::Parse)?;
                    let vk = p256::ecdsa::VerifyingKey::from_encoded_point(&pt)
                        .map_err(|_| DelegationError::Parse)?;
                    let sig = p256::ecdsa::Signature::try_from(&delegation.signature[..])
                        .map_err(|_| DelegationError::Parse)?;
                    vk.verify(&delegation.delegation.signable(), &sig)
                        .map_err(|_| DelegationError::BrokenChain {
                            from: last_verified.clone(),
                            to: Some(delegation.delegation.clone()),
                        })?;
                } else {
                    return Err(DelegationError::UnknownAlgorithm);
                }
            } else if spki.algorithm.oid == ObjectIdentifier::new_unwrap("1.3.101.112") {
                let vk =
                    ic_ed25519::PublicKey::deserialize_raw(spki.subject_public_key.raw_bytes())
                        .map_err(|_| DelegationError::Parse)?;
                vk.verify_signature(&delegation.delegation.signable(), &delegation.signature[..])
                    .map_err(|_| DelegationError::BrokenChain {
                        from: last_verified.clone(),
                        to: Some(delegation.delegation.clone()),
                    })?;
            } else {
                return Err(DelegationError::UnknownAlgorithm);
            }
            last_verified = &delegation.delegation.pubkey;
        }
        let delegated_principal = Principal::self_authenticating(last_verified);
        if delegated_principal != to.sender().map_err(DelegationError::IdentityError)? {
            return Err(DelegationError::BrokenChain {
                from: last_verified.clone(),
                to: None,
            });
        }

        Ok(Self::new_unchecked(from_key, to, chain))
    }

    /// Creates a delegated identity that signs using `to`, for the principal corresponding to the public key `from_key`.
    ///
    /// `chain` must be a list of delegations connecting `from_key` to `to.public_key()`, and in that order;
    /// otherwise, the replica will reject this delegation when used as an identity.
    pub fn new_unchecked(
        from_key: Vec<u8>,
        to: Box<dyn Identity>,
        chain: Vec<SignedDelegation>,
    ) -> Self {
        Self {
            to,
            chain,
            from_key,
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
        Ok(Principal::self_authenticating(&self.from_key))
    }
    fn public_key(&self) -> Option<Vec<u8>> {
        Some(self.from_key.clone())
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
