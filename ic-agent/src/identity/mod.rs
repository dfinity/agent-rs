//! Types and traits dealing with identity across the Internet Computer.
use crate::{agent::EnvelopeContent, export::Principal, to_request_id};

use serde::{Deserialize, Serialize};

pub(crate) mod anonymous;
pub(crate) mod basic;
pub(crate) mod delegated;
pub(crate) mod secp256k1;

#[cfg(feature = "pem")]
pub(crate) mod error;

pub use anonymous::AnonymousIdentity;
pub use basic::BasicIdentity;
pub use delegated::DelegatedIdentity;
pub use secp256k1::Secp256k1Identity;

#[cfg(feature = "pem")]
pub use error::PemError;

/// A cryptographic signature, signed by an [Identity].
#[derive(Clone, Debug)]
pub struct Signature {
    /// This is the DER-encoded public key.
    pub public_key: Option<Vec<u8>>,
    /// The signature bytes.
    pub signature: Option<Vec<u8>>,
    /// A list of delegations connecting `public_key` to the key that signed `signature`, and in that order.
    pub delegations: Option<Vec<SignedDelegation>>,
}

/// An `Identity` produces [`Signatures`](Signature) for requests or delegations. It knows or
/// represents the [`Principal`] of the sender.
///
/// [`Agents`](crate::Agent) are assigned a single `Identity` object, but there can be multiple
/// identities used.
pub trait Identity: Send + Sync {
    /// Returns a sender, ie. the Principal ID that is used to sign a request.
    ///
    /// Only one sender can be used per request.
    fn sender(&self) -> Result<Principal, String>;

    /// Sign a request ID derived from a content map.
    ///
    /// Implementors should call `content.to_request_id().signable()` for the actual bytes that need to be signed.
    fn sign(&self, content: &EnvelopeContent) -> Result<Signature, String>;

    /// Sign a delegation to let another key be used to authenticate [`sender`](Identity::sender).
    ///
    /// Implementors should call `content.signable()` for the actual bytes that need to be signed.
    fn sign_delegation(&self, content: &Delegation) -> Result<Signature, String> {
        let _ = content; // silence unused warning
        Err(String::from("unsupported"))
    }

    /// Sign arbitrary bytes.
    ///
    /// Not all `Identity` implementations support this operation.
    fn sign_arbitrary(&self, content: &[u8]) -> Result<Signature, String> {
        let _ = content; // silence unused warning
        Err(String::from("unsupported"))
    }

    /// Produce the public key commonly returned in [`Signature`].
    ///
    /// May return `None` when [`sign`](Identity::sign) would return `Some`.
    fn public_key(&self) -> Option<Vec<u8>>;

    /// A list of signed delegations connecting [`sender`](Identity::sender)
    /// to [`public_key`](Identity::public_key), and in that order.
    fn delegation_chain(&self) -> Vec<SignedDelegation> {
        vec![]
    }
}

/// A delegation from one key to another.
///
/// If key A signs a delegation containing key B, then key B may be used to
/// authenticate as key A's corresponding principal(s).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delegation {
    /// The delegated-to key.
    #[serde(with = "serde_bytes")]
    pub pubkey: Vec<u8>,
    /// A nanosecond timestamp after which this delegation is no longer valid.
    pub expiration: u64,
    /// If present, this delegation only applies to requests sent to one of these canisters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub targets: Option<Vec<Principal>>,
    /// If present, this delegation only applies to requests originating from one of these principals.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub senders: Option<Vec<Principal>>,
}

impl Delegation {
    /// Returns the signable form of the delegation, by running it through [`to_request_id`]
    /// and prepending `\x1Aic-request-auth-delegation` to the result.
    pub fn signable(&self) -> Vec<u8> {
        let hash = to_request_id(self).unwrap();
        let mut bytes = Vec::with_capacity(59);
        bytes.extend_from_slice(b"\x1Aic-request-auth-delegation");
        bytes.extend_from_slice(hash.as_slice());
        bytes
    }
}

/// A [`Delegation`] that has been signed by an [`Identity`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedDelegation {
    /// The signed delegation.
    pub delegation: Delegation,
    /// The signature for the delegation.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}
