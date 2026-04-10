use candid::Principal;
use ecdsa::signature::Verifier;
use ic_certification::{Certificate, LookupResult};
use k256::Secp256k1;
use p256::NistP256;
use pkcs8::der::{Decode, SliceReader};
use pkcs8::{spki::SubjectPublicKeyInfoRef, AssociatedOid, ObjectIdentifier};
use sec1::{EcParameters, EncodedPoint};
use sha2::{Digest, Sha256};

use crate::{
    agent::{
        response_authentication::{lookup_canister_ranges, DER_PREFIX, KEY_LENGTH},
        EnvelopeContent, IC_ROOT_KEY, IC_STATE_ROOT_DOMAIN_SEPARATOR,
    },
    Signature,
};

use super::{error::DelegationError, Delegation, Identity, SignedDelegation};

// OID for canister signatures per IC interface spec §Canister signatures: 1.3.6.1.4.1.56387.1.2
const CANISTER_SIG_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.56387.1.2");

/// CBOR body of a canister signature per the IC interface spec.
///
/// The wire encoding is `tag(55799, {"certificate": bytes, "tree": hash-tree})`.
/// `serde_cbor` transparently strips CBOR tags, so no special handling is needed.
#[derive(serde::Deserialize)]
struct CanisterSig {
    #[serde(with = "serde_bytes")]
    certificate: Vec<u8>,
    tree: ic_certification::HashTree,
}

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
    ///
    /// Canister signature keys in the chain are verified against the IC mainnet root key.
    /// Use [`new_with_root_key`](Self::new_with_root_key) to verify against a different root key
    /// (e.g. for a local replica or testnet).
    pub fn new(
        from_key: Vec<u8>,
        to: Box<dyn Identity>,
        chain: Vec<SignedDelegation>,
    ) -> Result<Self, DelegationError> {
        Self::new_impl(from_key, to, chain, IC_ROOT_KEY)
    }

    /// Creates a delegated identity that signs using `to`, for the principal corresponding to the public key `from_key`.
    ///
    /// `chain` must be a list of delegations connecting `from_key` to `to.public_key()`, and in that order;
    /// otherwise, this function will return an error.
    ///
    /// `root_key` is the DER-encoded BLS public key of the IC root (or whichever trust anchor is
    /// appropriate for the network), required to verify canister signature keys in the chain.
    pub fn new_with_root_key(
        from_key: Vec<u8>,
        to: Box<dyn Identity>,
        chain: Vec<SignedDelegation>,
        root_key: &[u8],
    ) -> Result<Self, DelegationError> {
        Self::new_impl(from_key, to, chain, root_key)
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

    fn new_impl(
        from_key: Vec<u8>,
        to: Box<dyn Identity>,
        chain: Vec<SignedDelegation>,
        root_key: &[u8],
    ) -> Result<Self, DelegationError> {
        let mut last_verified = &from_key;
        for delegation in &chain {
            verify_delegation_link(
                last_verified,
                &delegation.delegation,
                &delegation.signature,
                root_key,
            )?;
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

/// Verify one link in the delegation chain: that `delegation` was signed by the key `from_key`.
fn verify_delegation_link(
    from_key: &[u8],
    delegation: &ic_transport_types::Delegation,
    signature: &[u8],
    root_key: &[u8],
) -> Result<(), DelegationError> {
    let spki = SubjectPublicKeyInfoRef::decode(
        &mut SliceReader::new(from_key).map_err(|_| DelegationError::Parse)?,
    )
    .map_err(|_| DelegationError::Parse)?;

    let payload = delegation.signable();

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
            let sig =
                k256::ecdsa::Signature::try_from(signature).map_err(|_| DelegationError::Parse)?;
            vk.verify(&payload, &sig)
                .map_err(|_| DelegationError::BrokenChain {
                    from: from_key.to_vec(),
                    to: Some(delegation.clone()),
                })?;
        } else if curve == NistP256::OID {
            let pt = EncodedPoint::from_bytes(spki.subject_public_key.raw_bytes())
                .map_err(|_| DelegationError::Parse)?;
            let vk = p256::ecdsa::VerifyingKey::from_encoded_point(&pt)
                .map_err(|_| DelegationError::Parse)?;
            let sig =
                p256::ecdsa::Signature::try_from(signature).map_err(|_| DelegationError::Parse)?;
            vk.verify(&payload, &sig)
                .map_err(|_| DelegationError::BrokenChain {
                    from: from_key.to_vec(),
                    to: Some(delegation.clone()),
                })?;
        } else {
            return Err(DelegationError::UnknownAlgorithm);
        }
    } else if spki.algorithm.oid == ObjectIdentifier::new_unwrap("1.3.101.112") {
        let vk = ic_ed25519::PublicKey::deserialize_raw(spki.subject_public_key.raw_bytes())
            .map_err(|_| DelegationError::Parse)?;
        vk.verify_signature(&payload, signature)
            .map_err(|_| DelegationError::BrokenChain {
                from: from_key.to_vec(),
                to: Some(delegation.clone()),
            })?;
    } else if spki.algorithm.oid == CANISTER_SIG_OID {
        let (signing_canister_id, seed) =
            parse_canister_sig_pubkey(spki.subject_public_key.raw_bytes())?;
        verify_canister_sig(&payload, signature, signing_canister_id, &seed, root_key)?;
    } else {
        return Err(DelegationError::UnknownAlgorithm);
    }

    Ok(())
}

/// Parse the raw BIT STRING bytes of a canister signature public key into (canister_id, seed).
///
/// Format per the IC interface spec:
///   `| canister_id_length (1 byte) | canister_id_bytes | seed_bytes |`
fn parse_canister_sig_pubkey(raw: &[u8]) -> Result<(Principal, Vec<u8>), DelegationError> {
    if raw.is_empty() {
        return Err(DelegationError::Parse);
    }
    let id_len = raw[0] as usize;
    if raw.len() < 1 + id_len {
        return Err(DelegationError::Parse);
    }
    let canister_id =
        Principal::try_from_slice(&raw[1..1 + id_len]).map_err(|_| DelegationError::Parse)?;
    let seed = raw[1 + id_len..].to_vec();
    Ok((canister_id, seed))
}

/// Strip the DER prefix from a DER-encoded BLS12-381 public key, validating both length and prefix.
fn extract_bls_key(der: &[u8]) -> Result<&[u8], DelegationError> {
    if der.len() != DER_PREFIX.len() + KEY_LENGTH {
        return Err(DelegationError::InvalidCanisterSignature(
            "invalid BLS public key DER encoding: wrong length".into(),
        ));
    }
    if &der[..DER_PREFIX.len()] != DER_PREFIX.as_ref() {
        return Err(DelegationError::InvalidCanisterSignature(
            "invalid BLS public key DER encoding: wrong prefix".into(),
        ));
    }
    Ok(&der[DER_PREFIX.len()..])
}

/// BLS-verify an IC certificate's signature.
fn verify_cert_bls(cert: &Certificate, raw_bls_key: &[u8]) -> Result<(), DelegationError> {
    let root_hash = cert.tree.digest();
    let mut msg = Vec::with_capacity(IC_STATE_ROOT_DOMAIN_SEPARATOR.len() + 32);
    msg.extend_from_slice(IC_STATE_ROOT_DOMAIN_SEPARATOR);
    msg.extend_from_slice(&root_hash);
    ic_verify_bls_signature::verify_bls_signature(&cert.signature, &msg, raw_bls_key)
        .map_err(|_| DelegationError::InvalidCanisterSignature("BLS verification failed".into()))
}

/// Determine the DER-encoded BLS key to use when verifying `cert`, following at most one level of
/// subnet delegation and checking that `signing_canister_id` is within the delegated ranges.
fn resolve_cert_key(
    cert: &Certificate,
    signing_canister_id: Principal,
    root_key_der: &[u8],
) -> Result<Vec<u8>, DelegationError> {
    let delegation = match &cert.delegation {
        None => return Ok(root_key_der.to_vec()),
        Some(d) => d,
    };

    // Parse the inner delegation certificate (nesting not allowed).
    let delegation_cert: Certificate =
        serde_cbor::from_slice(&delegation.certificate).map_err(|e| {
            DelegationError::InvalidCanisterSignature(format!(
                "invalid delegation certificate CBOR: {e}"
            ))
        })?;
    if delegation_cert.delegation.is_some() {
        return Err(DelegationError::InvalidCanisterSignature(
            "nested delegations in certificate are not allowed".into(),
        ));
    }

    // BLS-verify the inner cert against the root key.
    let raw_root_key = extract_bls_key(root_key_der)?;
    verify_cert_bls(&delegation_cert, raw_root_key)?;

    // Verify the signing canister is within the subnet's authorised ranges.
    let subnet_id = Principal::try_from_slice(&delegation.subnet_id).map_err(|_| {
        DelegationError::InvalidCanisterSignature("invalid subnet_id in delegation".into())
    })?;
    let ranges = lookup_canister_ranges(&subnet_id, &delegation_cert).map_err(|e| {
        DelegationError::InvalidCanisterSignature(format!("canister range lookup failed: {e}"))
    })?;
    if !ranges.contains(&signing_canister_id) {
        return Err(DelegationError::InvalidCanisterSignature(
            "signing canister is not within the delegation's authorised canister ranges".into(),
        ));
    }

    // Return the subnet's public key (DER-encoded) from the inner cert.
    let pk_path: [&[u8]; 3] = [b"subnet", &delegation.subnet_id, b"public_key"];
    match delegation_cert.tree.lookup_path(pk_path) {
        LookupResult::Found(pk) => Ok(pk.to_vec()),
        _ => Err(DelegationError::InvalidCanisterSignature(
            "subnet public key not found in delegation certificate".into(),
        )),
    }
}

/// Verify a canister signature over `payload`.
///
/// Implements the verification procedure from the IC interface spec §Canister signatures:
/// 1. The certificate must be valid.
/// 2. `lookup_path(["canister", canister_id, "certified_data"], cert.tree) == reconstruct(sig.tree)`.
/// 3. `lookup_path(["sig", sha256(seed), sha256(payload)], sig.tree) == Found("")`.
fn verify_canister_sig(
    payload: &[u8],
    sig_bytes: &[u8],
    signing_canister_id: Principal,
    seed: &[u8],
    root_key_der: &[u8],
) -> Result<(), DelegationError> {
    // 1. Decode the CBOR signature envelope.
    //    CBOR tag 55799 (Self-Described CBOR) is transparently stripped by serde_cbor.
    let canister_sig: CanisterSig = serde_cbor::from_slice(sig_bytes).map_err(|e| {
        DelegationError::InvalidCanisterSignature(format!("invalid canister signature CBOR: {e}"))
    })?;

    // 2. Parse the IC certificate.
    let cert: Certificate = serde_cbor::from_slice(&canister_sig.certificate).map_err(|e| {
        DelegationError::InvalidCanisterSignature(format!("invalid certificate CBOR: {e}"))
    })?;

    // 3. Verify the certificate's BLS signature (following delegation if present).
    let verification_key_der = resolve_cert_key(&cert, signing_canister_id, root_key_der)?;
    let raw_bls_key = extract_bls_key(&verification_key_der)?;
    verify_cert_bls(&cert, raw_bls_key)?;

    // 4. Verify certified_data == reconstruct(sig.tree).
    //    reconstruct(tree) is the tree's root digest per the IC spec.
    let tree_root_hash = canister_sig.tree.digest();
    let certified_data_path: [&[u8]; 3] = [
        b"canister",
        signing_canister_id.as_slice(),
        b"certified_data",
    ];
    let certified_data = match cert.tree.lookup_path(certified_data_path) {
        LookupResult::Found(v) => v,
        LookupResult::Absent => {
            return Err(DelegationError::InvalidCanisterSignature(
                "certified_data is absent from the certificate tree".into(),
            ))
        }
        _ => {
            return Err(DelegationError::InvalidCanisterSignature(
                "certified_data lookup returned Unknown or Error".into(),
            ))
        }
    };
    if certified_data != tree_root_hash.as_ref() {
        return Err(DelegationError::InvalidCanisterSignature(
            "certified_data does not match the signature tree root hash".into(),
        ));
    }

    // 5. Verify lookup_path(["sig", sha256(seed), sha256(payload)], sig.tree) == Found("").
    let seed_hash: [u8; 32] = Sha256::digest(seed).into();
    let payload_hash: [u8; 32] = Sha256::digest(payload).into();
    let sig_path: [&[u8]; 3] = [b"sig", &seed_hash, &payload_hash];
    match canister_sig.tree.lookup_path(sig_path) {
        LookupResult::Found([]) => Ok(()),
        LookupResult::Found(_) => Err(DelegationError::InvalidCanisterSignature(
            "sig leaf in the signature tree is not empty".into(),
        )),
        _ => Err(DelegationError::InvalidCanisterSignature(
            "sig not found in the signature tree".into(),
        )),
    }
}
