use crate::{export::Principal, Identity, Signature};

#[cfg(feature = "pem")]
use crate::identity::error::PemError;

use ed25519_dalek::{Keypair as Ed25519KeyPair, PublicKey, Signer};
#[cfg(feature = "pem")]
use pkcs8::PrivateKeyDocument;
use simple_asn1::{
    oid, to_der,
    ASN1Block::{BitString, ObjectIdentifier, Sequence},
};

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
        let file = std::str::from_utf8(&bytes).unwrap();
        let pem_file: PrivateKeyDocument = file.parse().map_err(|_| PemError::PemError)?;
        let key_info = pem_file.private_key_info();

        // Check OID
        if key_info.algorithm.oid != "1.3.101.112".parse().unwrap() {
            return Err(PemError::WrongOid(
                "1.3.101.112".to_string(),
                format!("{}", key_info.algorithm.oid),
            ));
        }

        // Check that there are no parameters on the key
        if key_info.algorithm.parameters.is_some() {
            return Err(PemError::KeyRejected(
                "Parameters on the key are not allowed".to_string(),
            ));
        }

        // Retrieve the secret key and check that we have a string of 32 byte length
        let sk = key_info.private_key;
        if sk[0] != 4 || sk[1] != 32 || sk.len() != 34 {
            return Err(PemError::KeyRejected(
                "Key is not a Ed25519 private key".to_string(),
            ));
        }

        // Retrieve the public key, error if it was not provided
        let pk = match key_info.public_key {
            Some(pk) => pk,
            None => {
                return Err(PemError::KeyRejected(
                    "Public key must be included in the file".to_string(),
                ))
            }
        };

        let mut key = [0; 64];
        key[..32].copy_from_slice(&sk[2..]);
        key[32..].copy_from_slice(pk);

        let key_pair = Ed25519KeyPair::from_bytes(&key)
            .map_err(|err| PemError::KeyRejected(format!("Key invalid: {}", err)))?;

        // Check that the provided public key matches the secret key
        // by regenerating and comparing the public key.
        let pk2 = PublicKey::from(&key_pair.secret);
        if pk2 != key_pair.public {
            return Err(PemError::KeyRejected("Invalid public key".to_string()));
        }

        Ok(BasicIdentity::from_key_pair(key_pair))
    }

    /// Create a BasicIdentity from a KeyPair from the ring crate.
    pub fn from_key_pair(key_pair: Ed25519KeyPair) -> Self {
        let der_encoded_public_key = der_encode_public_key(key_pair.public.as_ref().to_vec());

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

fn der_encode_public_key(public_key: Vec<u8>) -> Vec<u8> {
    // see Section 4 "SubjectPublicKeyInfo" in https://tools.ietf.org/html/rfc8410

    let id_ed25519 = oid!(1, 3, 101, 112);
    let algorithm = Sequence(0, vec![ObjectIdentifier(0, id_ed25519)]);
    let subject_public_key = BitString(0, public_key.len() * 8, public_key);
    let subject_public_key_info = Sequence(0, vec![algorithm, subject_public_key]);
    to_der(&subject_public_key_info).unwrap()
}

#[cfg(feature = "pem")]
#[cfg(test)]
mod test {
    use super::*;

    // Generated with `dfx identity new`
    const IDENTITY_FILE: &str = "-----BEGIN PRIVATE KEY-----
MFMCAQEwBQYDK2VwBCIEILcugDIk2LHOj/6MUerC94QkWswslgjuiEYKqoJw/rx+
oSMDIQC0pDnxK4FLbD03g2a4BdZxYX4w+RQvwSestgNDEwzHHA==
-----END PRIVATE KEY-----";

    const WRONG_OID: &str = "-----BEGIN PRIVATE KEY-----
MFMCAQEwBQYDK2RwBCIEILcugDIk2LHOj/6MUerC94QkWswslgjuiEYKqoJw/rx+
oSMDIQC0pDnxK4FLbD03g2a4BdZxYX4w+RQvwSestgNDEwzHHA==
-----END PRIVATE KEY-----";

    // Generated with `dfx identity get-principal`
    const PRICIPAL: &str = "egnpc-ce26d-7fywe-lnoor-gu2r2-ogz7w-ls2yd-q7uee-wfpfn-oien7-3qe";

    // Tests that identities generate with `dfx identity new` are parsable
    #[test]
    fn identity_from_pem() {
        let identity =
            BasicIdentity::from_pem(IDENTITY_FILE.as_bytes()).expect("Failed to parse PEM file");
        let principal = identity.sender().expect("Failed to get principal");
        assert_eq!(principal.to_text(), PRICIPAL);
    }

    // Tests that identities generate with `dfx identity new` are parsable
    #[test]
    fn wrong_oid_in_pem() {
        match BasicIdentity::from_pem(WRONG_OID.as_bytes()) {
            Err(PemError::WrongOid(exp, got)) if exp == "1.3.101.112" && got == "1.3.100.112" => (),
            Ok(_) => panic!("Expected wrong OID error but got success"),
            Err(err) => panic!("Expected wrong OID error but got error {:?}", err),
        }
    }
}
