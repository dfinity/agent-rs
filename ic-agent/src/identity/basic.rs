use crate::{Blob, Identity, Principal, Signature};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PemError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("An error occured while reading the file: {0}")]
    PemError(#[from] pem::PemError),

    #[error("A key was rejected by Ring: {0}")]
    KeyRejected(#[from] ring::error::KeyRejected),
}

pub struct BasicIdentity {
    key_pair: Ed25519KeyPair,
}

impl BasicIdentity {
    pub fn from_pem_file<P: AsRef<Path>>(file_path: P) -> Result<Self, PemError> {
        Self::from_pem(std::fs::File::open(file_path)?)
    }

    pub fn from_pem<R: std::io::Read>(pem_reader: R) -> Result<Self, PemError> {
        let bytes: Vec<u8> = pem_reader
            .bytes()
            .collect::<Result<Vec<u8>, std::io::Error>>()?;

        Ok(Self {
            key_pair: Ed25519KeyPair::from_pkcs8(pem::parse(&bytes)?.contents.as_slice())?,
        })
    }

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
