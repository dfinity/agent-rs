use crate::export::Principal;
use crate::{Identity, Signature};
use num_bigint::BigUint;
use openssl::ec::EcKey;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::Signer;
use ring::signature::{Ed25519KeyPair, KeyPair};
use simple_asn1::ASN1Block::{BitString, ObjectIdentifier, Sequence};
use simple_asn1::{oid, to_der, OID};
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

    #[error("A key was rejected by OpenSSL: {0}")]
    ErrorStack(#[from] ErrorStack),
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
        let der_encoded_public_key =
            der_encode_ed25519_public_key(key_pair.public_key().as_ref().to_vec());

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
    fn sign(&self, msg: &[u8]) -> Result<Signature, String> {
        let signature = self.key_pair.sign(msg.as_ref());
        // At this point we shall validate the signature in this first
        // skeleton version.

        Ok(Signature {
            signature: Some(signature.as_ref().to_vec()),
            public_key: Some(self.der_encoded_public_key.clone()),
        })
    }
}

pub struct Secp256k1Identity {
    private_key: EcKey<Private>,
    public_key: EcKey<Public>,
    der_encoded_public_key: Vec<u8>,
}

impl Secp256k1Identity {
    #[cfg(feature = "pem")]
    pub fn from_pem_file<P: AsRef<std::path::Path>>(file_path: P) -> Result<Self, PemError> {
        Self::from_pem(std::fs::File::open(file_path)?)
    }

    #[cfg(feature = "pem")]
    pub fn from_pem<R: std::io::Read>(pem_reader: R) -> Result<Self, PemError> {
        let contents = pem_reader
            .bytes()
            .collect::<Result<Vec<u8>, std::io::Error>>()?;
        let private_key = EcKey::private_key_from_pem(&contents)?;
        Ok(Self::from_private_key(private_key))
    }

    pub fn from_private_key(private_key: EcKey<Private>) -> Self {
        // TODO: Investegate why the OpenSSL library returns Result type;
        let public_key = EcKey::from_public_key(private_key.group(), private_key.public_key())
            .expect("Cannot secp256k1 public key from secp256k1 private key.");
        let der_encoded_public_key = public_key
            .public_key_to_der()
            .expect("Cannot DER encode secp256k1 public key.");
        Self {
            private_key,
            public_key,
            der_encoded_public_key,
        }
    }
}

impl Identity for Secp256k1Identity {
    fn sender(&self) -> Result<Principal, String> {
        Ok(Principal::self_authenticating(&self.der_encoded_public_key))
    }
    fn sign(&self, msg: &[u8]) -> Result<Signature, String> {
        let md_type =
            MessageDigest::from_nid(Nid::SECP256K1).expect("Cannot construct message digest type.");
        let pkey = PKey::from_ec_key(self.private_key.clone()).map_err(|err| err.to_string())?;
        let signer = Signer::new(md_type, &pkey);
        // signer.update()

        //let signature = self.key_pair.sign(msg.as_ref());

        Err(":(".to_string())

        /*
            let message = beneficiary.to_text();
            let envelope = format!("\x19Ethereum Signed Message:\n{}{}", message.len(), message);
            let mut hasher = sha3::Keccak256::new();
            hasher.update(envelope);
            let digest_bin = &hasher.finalize()[..];
            let digest = Message::parse_slice(&digest_bin)?;
        */

        /*
                Ok(Signature {
                    signature: Some(signature.as_ref().to_vec()),
                    public_key: Some(self.der_encoded_public_key.clone()),
                })
        */
    }
}

fn der_encode_public_key(oid: OID, public_key: Vec<u8>) -> Vec<u8> {
    // see Section 4 "SubjectPublicKeyInfo" in https://tools.ietf.org/html/rfc8410
    let algorithm = Sequence(0, vec![ObjectIdentifier(0, oid)]);
    let subject_public_key = BitString(0, public_key.len() * 8, public_key);
    let subject_public_key_info = Sequence(0, vec![algorithm, subject_public_key]);
    to_der(&subject_public_key_info).unwrap()
}

fn der_encode_ed25519_public_key(public_key: Vec<u8>) -> Vec<u8> {
    let oid = oid!(1, 3, 101, 112);
    der_encode_public_key(oid, public_key)
}

/*
fn der_encode_secp256k1_public_key(public_key: Vec<u8>) -> Vec<u8> {
    let oid = oid!(1, 3, 132, 0, 10);
    der_encode_public_key(oid, public_key)
}
*/
