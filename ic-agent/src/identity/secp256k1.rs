use crate::export::Principal;
use crate::identity::error::PemError;
use crate::{Identity, Signature};

use openssl::ec::EcKey;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::Signer;
use sha2::{Digest, Sha256};

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
        // TODO: Investegate why the OpenSSL library returns Result type here.
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
        // TODO: Investegate why the OpenSSL library returns Result type here.
        let type_ =
            MessageDigest::from_nid(Nid::SECP256K1).expect("Cannot construct message digest type.");
        let private_key =
            PKey::from_ec_key(self.private_key.clone()).map_err(|err| err.to_string())?;
        let public_key = Some(self.der_encoded_public_key.clone());
        let mut signer = Signer::new(type_, &private_key).map_err(|err| err.to_string())?;
        let mut hasher = Sha256::new();
        hasher.update(msg);
        signer.update(&hasher.finalize()[..]);
        let signature = signer
            .sign_to_vec()
            .map(Some)
            .map_err(|err| err.to_string())?;
        Ok(Signature {
            signature,
            public_key,
        })
    }
}
