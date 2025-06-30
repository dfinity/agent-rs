use crate::{agent::EnvelopeContent, export::Principal, Identity, Signature};

#[cfg(feature = "pem")]
use crate::identity::error::PemError;

use ic_ed25519::PrivateKey;

use std::fmt;

use super::Delegation;

/// A cryptographic identity which signs using an Ed25519 key pair.
///
/// The caller will be represented via [`Principal::self_authenticating`], which contains the SHA-224 hash of the public key.
pub struct BasicIdentity {
    private_key: KeyCompat,
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
    /// Create a `BasicIdentity` from reading a PEM file at the path.
    #[cfg(feature = "pem")]
    pub fn from_pem_file<P: AsRef<std::path::Path>>(file_path: P) -> Result<Self, PemError> {
        Self::from_pem(std::fs::File::open(file_path)?)
    }

    /// Create a `BasicIdentity` from reading a PEM File from a Reader.
    #[cfg(feature = "pem")]
    pub fn from_pem<R: std::io::Read>(pem_reader: R) -> Result<Self, PemError> {
        use der::{asn1::OctetString, Decode, ErrorKind, SliceReader, Tag, TagNumber};
        use pkcs8::PrivateKeyInfo;

        let bytes: Vec<u8> = pem_reader.bytes().collect::<Result<_, _>>()?;
        let pem = pem::parse(bytes)?;
        let pki_res = PrivateKeyInfo::decode(&mut SliceReader::new(pem.contents())?);
        let mut truncated;
        let pki = match pki_res {
            Ok(pki) => pki,
            Err(e) => {
                if e.kind()
                    == (ErrorKind::Noncanonical {
                        tag: Tag::ContextSpecific {
                            constructed: true,
                            number: TagNumber::new(1),
                        },
                    })
                {
                    // Very old versions of dfx generated nonconforming containers. They can only be imported if the extra data is removed.
                    truncated = pem.into_contents();
                    if truncated[48..52] != *b"\xA1\x23\x03\x21" {
                        return Err(e.into());
                    }
                    // hatchet surgery
                    truncated.truncate(48);
                    truncated[1] = 46;
                    truncated[4] = 0;
                    PrivateKeyInfo::decode(&mut SliceReader::new(&truncated)?).map_err(|_| e)?
                } else {
                    return Err(e.into());
                }
            }
        };
        let decoded_key = OctetString::from_der(pki.private_key)?; // ed25519 uses an octet string within another octet string
        let key_len = decoded_key.as_bytes().len();
        if key_len != 32 {
            Err(PemError::InvalidPrivateKey(format!(
                "Ed25519 expects a 32 octets PRivate Key, but got {key_len} octets",
            )))
        } else {
            let raw_key: [u8; 32] = decoded_key.as_bytes().try_into().unwrap();
            Ok(Self::from_raw_key(&raw_key))
        }
    }

    /// Create a `BasicIdentity` from a raw 32-byte Private Key as described in RFC 8032 5.1.5.
    pub fn from_raw_key(key: &[u8; 32]) -> Self {
        let private_key = PrivateKey::deserialize_raw_32(key);
        let public_key = private_key.public_key();
        let der_encoded_public_key = public_key.serialize_rfc8410_der();
        Self {
            private_key: KeyCompat::Standard(private_key),
            der_encoded_public_key,
        }
    }

    /// Create a `BasicIdentity` from a `SigningKey` from `ed25519-consensus`.
    ///
    /// # Note
    ///
    /// This constructor is kept for backwards compatibility.
    /// The signing won't use `ed25519-consensus` anymore.
    #[deprecated(since = "0.41.0", note = "use BasicIdentity::from_raw_key instead")]
    pub fn from_signing_key(key: ed25519_consensus::SigningKey) -> Self {
        let raw_key = key.to_bytes();
        Self::from_raw_key(&raw_key)
    }

    /// Create a `BasicIdentity` from an `Ed25519KeyPair` from `ring`.
    #[cfg(feature = "ring")]
    pub fn from_key_pair(key_pair: ring::signature::Ed25519KeyPair) -> Self {
        use ic_ed25519::PublicKey;
        use ring::signature::KeyPair;
        let raw_public_key = key_pair.public_key().as_ref().to_vec();
        // Unwrap safe: we trust that the public key is valid, as it comes from a valid key pair.
        let public_key = PublicKey::deserialize_raw(&raw_public_key).unwrap();
        let der_encoded_public_key = public_key.serialize_rfc8410_der();
        Self {
            private_key: KeyCompat::Ring(key_pair),
            der_encoded_public_key,
        }
    }
}

enum KeyCompat {
    /// ic_ed25519::PrivateKey
    Standard(PrivateKey),
    #[cfg(feature = "ring")]
    Ring(ring::signature::Ed25519KeyPair),
}

impl KeyCompat {
    fn sign(&self, payload: &[u8]) -> Vec<u8> {
        match self {
            Self::Standard(k) => k.sign_message(payload).to_vec(),
            #[cfg(feature = "ring")]
            Self::Ring(k) => k.sign(payload).as_ref().to_vec(),
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
        let signature = self.private_key.sign(content);
        Ok(Signature {
            signature: Some(signature),
            public_key: self.public_key(),
            delegations: None,
        })
    }
}
