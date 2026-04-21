use candid::Principal;
use pkcs8::{
    der::{Decode, SliceReader},
    spki::SubjectPublicKeyInfoRef,
};

use ic_transport_types::SenderInfo;

use crate::{
    agent::{EnvelopeContent, IC_ROOT_KEY},
    Signature,
};

use super::{
    delegated::{parse_canister_sig_pubkey, verify_canister_sig, CANISTER_SIG_OID},
    error::DelegationError,
    Delegation, Identity, SignedDelegation,
};

// Domain separator per IC interface spec §Identity attributes: \x0E (14) + "ic-sender-info"
const SENDER_INFO_DOMAIN_SEP: &[u8; 15] = b"\x0Eic-sender-info";

/// An identity wrapper that attaches canister-certified sender information to every request.
///
/// The inner identity's public key must be a canister signature key (OID 1.3.6.1.4.1.56387.1.2).
/// `sig` must be a canister signature over `\x0Eic-sender-info || info` using that same key.
pub struct InfoAwareIdentity<I: Identity> {
    inner: I,
    info: Vec<u8>,
    signer: Principal,
    sig: Vec<u8>,
}

impl<I: Identity> InfoAwareIdentity<I> {
    /// Wraps `inner` and attaches `info`/`sig` as certified sender information.
    ///
    /// Verifies the canister signature against the IC mainnet root key.
    /// `inner` must have a canister signature public key.
    pub fn new(inner: I, info: Vec<u8>, sig: Vec<u8>) -> Result<Self, DelegationError> {
        Self::new_impl(inner, info, sig, IC_ROOT_KEY)
    }

    /// Like [`new`](Self::new), but verifies against a custom root key (e.g. local replica or testnet).
    pub fn new_with_root_key(
        inner: I,
        info: Vec<u8>,
        sig: Vec<u8>,
        root_key: &[u8],
    ) -> Result<Self, DelegationError> {
        Self::new_impl(inner, info, sig, root_key)
    }

    /// Like [`new`](Self::new), but skips cryptographic verification of the canister signature.
    ///
    /// The replica will still reject an invalid signature. The signer principal is still parsed
    /// from the inner identity's public key.
    pub fn new_unchecked(inner: I, info: Vec<u8>, sig: Vec<u8>) -> Result<Self, DelegationError> {
        let (signer, _seed) = parse_canister_pubkey(&inner)?;
        Ok(Self {
            inner,
            info,
            signer,
            sig,
        })
    }

    fn new_impl(
        inner: I,
        info: Vec<u8>,
        sig: Vec<u8>,
        root_key: &[u8],
    ) -> Result<Self, DelegationError> {
        let (signer, seed) = parse_canister_pubkey(&inner)?;
        let mut payload = Vec::with_capacity(SENDER_INFO_DOMAIN_SEP.len() + info.len());
        payload.extend_from_slice(SENDER_INFO_DOMAIN_SEP);
        payload.extend_from_slice(&info);
        verify_canister_sig(&payload, &sig, signer, &seed, root_key)?;
        Ok(Self {
            inner,
            info,
            signer,
            sig,
        })
    }
}

/// Parse the inner identity's public key as a canister sig SPKI, returning (canister_id, seed).
fn parse_canister_pubkey<I: Identity>(inner: &I) -> Result<(Principal, Vec<u8>), DelegationError> {
    let pubkey = inner.public_key().ok_or(DelegationError::Parse)?;
    let spki = SubjectPublicKeyInfoRef::decode(
        &mut SliceReader::new(&pubkey).map_err(|_| DelegationError::Parse)?,
    )
    .map_err(|_| DelegationError::Parse)?;
    if spki.algorithm.oid != CANISTER_SIG_OID {
        return Err(DelegationError::UnknownAlgorithm);
    }
    parse_canister_sig_pubkey(spki.subject_public_key.raw_bytes())
}

impl<I: Identity> Identity for InfoAwareIdentity<I> {
    fn sender(&self) -> Result<Principal, String> {
        self.inner.sender()
    }

    fn public_key(&self) -> Option<Vec<u8>> {
        self.inner.public_key()
    }

    fn sign(&self, content: &EnvelopeContent) -> Result<Signature, String> {
        self.inner.sign(content)
    }

    fn sign_delegation(&self, content: &Delegation) -> Result<Signature, String> {
        self.inner.sign_delegation(content)
    }

    fn sign_arbitrary(&self, content: &[u8]) -> Result<Signature, String> {
        self.inner.sign_arbitrary(content)
    }

    fn delegation_chain(&self) -> Vec<SignedDelegation> {
        self.inner.delegation_chain()
    }

    fn sender_info(&self) -> Option<SenderInfo> {
        Some(SenderInfo {
            info: self.info.clone(),
            signer: self.signer.as_slice().to_vec(),
            sig: self.sig.clone(),
        })
    }
}
