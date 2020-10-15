use crate::export::Principal;
use crate::{Identity, Signature};
use num_bigint::BigUint;
use ring::signature::{Ed25519KeyPair, KeyPair};
use simple_asn1::ASN1Block::{BitString, ObjectIdentifier, Sequence};
use simple_asn1::{to_der, ASN1EncodeErr, OID};
use thiserror::Error;

/// An error happened while reading a PEM file to create a BasicIdentity.
#[derive(Error, Debug)]
pub enum PemError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[cfg(feature = "pem")]
    #[error("An error occurred while reading the file: {0}")]
    PemError(#[from] pem::PemError),

    #[error("A key was rejected by Ring: {0}")]
    KeyRejected(#[from] ring::error::KeyRejected),
}

/// A Basic Identity which sign using an ED25519 key pair.
pub struct BasicIdentity {
    key_pair: Ed25519KeyPair,
    der_encoded_public_key: Vec<u8>,
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
            pem::parse(&bytes)?.contents.as_slice(),
        )?))
    }

    /// Create a BasicIdentity from a KeyPair from the ring crate.
    pub fn from_key_pair(key_pair: Ed25519KeyPair) -> Self {
        let der_encoded_public_key = der_encode_public_key(key_pair.public_key().as_ref().to_vec())
            .expect("DER encoding error");
        // eprintln!(
        //     "key bytes: {:?}",
        //     &der_encoded_public_key.clone()
        //         .unwrap()
        //         .iter()
        //         .map(|x| format!("{:02X}", x))
        //         .collect::<Vec<String>>()
        // );

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
    fn sign(&self, msg: &[u8], _principal: &Principal) -> Result<Signature, String> {
        let signature = self.key_pair.sign(msg.as_ref());
        // At this point we shall validate the signature in this first
        // skeleton version.
        let public_key_bytes = self.key_pair.public_key();

        Ok(Signature {
            signature: signature.as_ref().to_vec(),
            public_key: public_key_bytes.as_ref().to_vec(),
            der_encoded_public_key: self.der_encoded_public_key.clone(),
        })
    }
}

fn der_encode_public_key(public_key: Vec<u8>) -> Result<Vec<u8>, ASN1EncodeErr> {
    // see Section 4 "SubjectPublicKeyInfo" in https://tools.ietf.org/html/rfc8410

    let id_ed25519 = OID::new(vec![
        BigUint::from(1u32),
        BigUint::from(3u32),
        BigUint::from(101u32),
        BigUint::from(112u32),
    ]);
    let algorithm = Sequence(0, vec![ObjectIdentifier(0, id_ed25519)]);
    let subject_public_key = BitString(0, public_key.len() * 8, public_key);
    let subject_public_key_info = Sequence(0, vec![algorithm, subject_public_key]);
    to_der(&subject_public_key_info)
}
