use crate::{
    export::{Delegation, Principal, SignedDelegation},
    identity::{BasicIdentity, Secp256k1Identity},
    Identity, Signature,
};
use ic_crypto_sha::Sha256;
use std::{collections::BTreeMap, string::String};
use types::{
    messages::RawHttpRequestVal::{self, *},
    CanisterId, Time,
};

#[cfg(feature = "pem")]
use crate::identity::error::PemError;
#[cfg(feature = "pem")]
use std::path::Path;

#[derive(Debug)]
enum SecondIdentity {
    BasicIdentity(BasicIdentity),
    Secp256k1Identity(Secp256k1Identity),
}

/// A Delegation Identity which sign using an ED25519 key pair.
#[derive(Debug)]
pub struct DelegationIdentity {
    second_identity: SecondIdentity,
    delegation: Option<Vec<SignedDelegation>>,
    main_identity_pubkey: Option<Vec<u8>>,
}

impl DelegationIdentity {
    /// Creates an identity from a PEM file. Shorthand for calling `from_pem` with `std::fs::read`.
    #[cfg(feature = "pem")]
    pub fn from_pem_file<P: AsRef<Path>>(file_path: P, base: bool) -> Result<Self, PemError> {
        if base {
            Ok(Self {
                second_identity: SecondIdentity::BasicIdentity(BasicIdentity::from_pem_file(
                    file_path,
                )?),
                delegation: None,
                main_identity_pubkey: None,
            })
        } else {
            Ok(Self {
                second_identity: SecondIdentity::Secp256k1Identity(
                    Secp256k1Identity::from_pem_file(file_path)?,
                ),
                delegation: None,
                main_identity_pubkey: None,
            })
        }
    }

    /// Creates an identity from a PEM file. Shorthand for calling `from_pem` with `std::fs::read`.
    #[cfg(feature = "pem")]
    pub fn set_delegation_from_pem_file<P: AsRef<Path>>(
        &mut self,
        file_path: P,
        base: bool,
        delegation_expiry: Option<u64>,
        delegation_targets: Option<Vec<Principal>>,
    ) -> Result<(), PemError> {
        let mut origin = self.delegation.clone().unwrap_or_default();
        let second_pubkey = if origin.is_empty() {
            match &self.second_identity {
                SecondIdentity::BasicIdentity(b) => b.der_encoded_public_key.clone(),
                SecondIdentity::Secp256k1Identity(s) => s.der_encoded_public_key.as_ref().to_vec(),
            }
        } else {
            self.main_identity_pubkey.clone().unwrap()
        };

        let delegation = match delegation_targets {
            Some(targets) => {
                Delegation::new_with_targets(
                    second_pubkey, // public key of identity2
                    Time::from_nanos_since_unix_epoch(delegation_expiry.unwrap()),
                    targets
                        .into_iter()
                        .map(|principal| CanisterId::try_from(principal.as_slice()).unwrap())
                        .collect(),
                )
            }
            None => {
                Delegation::new(
                    second_pubkey, // public key of identity2
                    Time::from_nanos_since_unix_epoch(delegation_expiry.unwrap()),
                )
            }
        };

        let result = if base {
            let main_identity = BasicIdentity::from_pem_file(file_path)?;
            let signed_delegation = sign_delegation(delegation, &main_identity);
            (signed_delegation, main_identity.der_encoded_public_key)
        } else {
            let main_identity = Secp256k1Identity::from_pem_file(file_path)?;
            let signed_delegation = sign_delegation(delegation, &main_identity);
            (
                signed_delegation,
                main_identity.der_encoded_public_key.as_ref().to_vec(),
            )
        };
        origin.push(result.0);
        self.delegation = Some(origin);
        self.main_identity_pubkey = Some(result.1);
        Ok(())
    }
}

impl Identity for DelegationIdentity {
    fn sender(&self) -> Result<Principal, String> {
        match &self.delegation {
            None => match &self.second_identity {
                SecondIdentity::BasicIdentity(b) => b.sender(),
                SecondIdentity::Secp256k1Identity(s) => s.sender(),
            },
            Some(_) => Ok(Principal::self_authenticating(
                self.main_identity_pubkey.as_ref().unwrap(),
            )),
        }
    }

    fn sign(&self, msg: &[u8]) -> Result<Signature, String> {
        match &self.delegation {
            None => match &self.second_identity {
                SecondIdentity::BasicIdentity(b) => b.sign(msg),
                SecondIdentity::Secp256k1Identity(s) => s.sign(msg),
            },
            Some(_) => {
                let sign = match &self.second_identity {
                    SecondIdentity::BasicIdentity(b) => b.sign(msg)?,
                    SecondIdentity::Secp256k1Identity(s) => s.sign(msg)?,
                };
                Ok(Signature {
                    public_key: self.main_identity_pubkey.clone(),
                    signature: sign.signature,
                })
            }
        }
    }

    fn delegation(&self) -> Option<Vec<SignedDelegation>> {
        self.delegation.clone()
    }
}

fn sign_delegation(delegation: Delegation, identity: &impl Identity) -> SignedDelegation {
    let mut msg = b"\x1Aic-request-auth-delegation".to_vec();
    msg.extend(as_signed_bytes_without_domain_separator(&delegation));
    let signature = identity.sign(&msg).unwrap();

    SignedDelegation::new(delegation, signature.signature.unwrap())
}

fn as_signed_bytes_without_domain_separator(delegation: &Delegation) -> Vec<u8> {
    use maplit::btreemap;

    let mut map = btreemap! {
        "pubkey" => Bytes(delegation.pubkey().clone()),
        "expiration" => U64(delegation.expiration().as_nanos_since_unix_epoch()),
    };
    if let Some(targets) = delegation.targets().unwrap() {
        map.insert(
            "targets",
            Array(
                targets
                    .iter()
                    .map(|t| Bytes(t.get_ref().as_slice().to_vec()))
                    .collect(),
            ),
        );
    }

    hash_of_map(&map).to_vec()
}

// Describes `hash_of_map` as specified in the public spec.

fn hash_string(value: String) -> Vec<u8> {
    Sha256::hash(&value.into_bytes()).to_vec()
}

fn hash_bytes(value: Vec<u8>) -> Vec<u8> {
    Sha256::hash(&value).to_vec()
}

fn hash_u64(value: u64) -> Vec<u8> {
    // We need at most ⌈ 64 / 7 ⌉ = 10 bytes to encode a 64 bit
    // integer in LEB128.
    let mut buf = [0u8; 10];
    let mut n = value;
    let mut i = 0;

    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;

        if n == 0 {
            buf[i] = byte;
            break;
        } else {
            buf[i] = byte | 0x80;
            i += 1;
        }
    }

    hash_bytes(buf[..=i].to_vec())
}

// arrays, encoded as the concatenation of the hashes of the encodings of the
// array elements.
fn hash_array(elements: Vec<RawHttpRequestVal>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    elements
        .into_iter()
        // Hash the encoding of all the array elements.
        .for_each(|e| hasher.write(hash_val(e).as_slice()));
    hasher.finish().to_vec() // hash the concatenation of the hashes.
}

fn hash_val(val: RawHttpRequestVal) -> Vec<u8> {
    match val {
        RawHttpRequestVal::String(string) => hash_string(string),
        RawHttpRequestVal::Bytes(bytes) => hash_bytes(bytes),
        RawHttpRequestVal::U64(integer) => hash_u64(integer),
        RawHttpRequestVal::Array(elements) => hash_array(elements),
    }
}

fn hash_key_val(key: String, val: RawHttpRequestVal) -> Vec<u8> {
    let mut key_hash = hash_string(key);
    let mut val_hash = hash_val(val);
    key_hash.append(&mut val_hash);
    key_hash
}

/// Describes `hash_of_map` as specified in the public spec.
pub(crate) fn hash_of_map<S: ToString>(map: &BTreeMap<S, RawHttpRequestVal>) -> [u8; 32] {
    let mut hashes: Vec<Vec<u8>> = Vec::new();
    for (key, val) in map.iter() {
        hashes.push(hash_key_val(key.to_string(), val.clone()));
    }

    // Computes hash by first sorting by "field name" hash, which is the
    // same as sorting by concatenation of H(field name) · H(field value)
    // (although in practice it's actually more stable in the presence of
    // duplicated field names).  Then concatenate all the hashes.
    hashes.sort();

    let mut hasher = Sha256::new();
    for hash in hashes {
        hasher.write(&hash);
    }

    hasher.finish()
}
