use crate::{agent::EnvelopeContent, export::Principal, Identity, Signature};

#[cfg(feature = "pem")]
use crate::identity::error::PemError;

use ring::signature::{Ed25519KeyPair, KeyPair};
use simple_asn1::{
    oid, to_der,
    ASN1Block::{BitString, ObjectIdentifier, Sequence},
};

use std::fmt;

use super::Delegation;

/// A Basic Identity which sign using an ED25519 key pair.
pub struct BasicIdentity {
    key_pair: Ed25519KeyPair,
    der_encoded_public_key: Vec<u8>,
}

impl fmt::Debug for BasicIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BasicIdentity")
            .field("der_encoded_public_key", &self.der_encoded_public_key)
            .finish_non_exhaustive()
    }
}

impl BasicIdentity {
    /// Create a BasicIdentity from reading a PEM file at the path.
    #[cfg(feature = "pem")]
    pub fn from_pem_file<P: AsRef<std::path::Path>>(file_path: P) -> Result<Self, PemError> {
        Self::from_pem(std::fs::File::open(file_path)?)
    }

    /// Create a BasicIdentity from reading a PEM File from a Reader.
    #[cfg(feature = "pem")]
    pub fn from_pem<R: std::io::Read>(pem_reader: R) -> Result<Self, PemError> {
        let bytes: Vec<u8> = pem_reader
            .bytes()
            .collect::<Result<Vec<u8>, std::io::Error>>()?;

        Ok(BasicIdentity::from_key_pair(Ed25519KeyPair::from_pkcs8(
            pem::parse(bytes)?.contents(),
        )?))
    }

    /// Create a BasicIdentity from a KeyPair from the ring crate.
    pub fn from_key_pair(key_pair: Ed25519KeyPair) -> Self {
        let der_encoded_public_key = der_encode_public_key(key_pair.public_key().as_ref().to_vec());

        Self {
            key_pair,
            der_encoded_public_key,
        }
    }
}

impl Identity for BasicIdentity {
    fn sender(&self) -> Result<Principal, String> {
        Ok(Principal::self_authenticating(&self.der_encoded_public_key))
    }

    fn public_key(&self) -> Option<Vec<u8>> {
        Some(self.der_encoded_public_key.clone())
    }

    fn sign(&self, content: &EnvelopeContent) -> Result<Signature, String> {
        self.sign_arbitrary(&content.to_request_id().signable())
    }

    fn sign_delegation(&self, content: &Delegation) -> Result<Signature, String> {
        self.sign_arbitrary(&content.signable())
    }

    fn sign_arbitrary(&self, content: &[u8]) -> Result<Signature, String> {
        let signature = self.key_pair.sign(content);
        Ok(Signature {
            signature: Some(signature.as_ref().to_vec()),
            public_key: self.public_key(),
        })
    }
}

fn der_encode_public_key(public_key: Vec<u8>) -> Vec<u8> {
    // see Section 4 "SubjectPublicKeyInfo" in https://tools.ietf.org/html/rfc8410

    let id_ed25519 = oid!(1, 3, 101, 112);
    let algorithm = Sequence(0, vec![ObjectIdentifier(0, id_ed25519)]);
    let subject_public_key = BitString(0, public_key.len() * 8, public_key);
    let subject_public_key_info = Sequence(0, vec![algorithm, subject_public_key]);
    to_der(&subject_public_key_info).unwrap()
}
