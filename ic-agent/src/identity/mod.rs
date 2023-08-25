//! Types and traits dealing with identity across the Internet Computer.
use crate::{agent::EnvelopeContent, export::Principal, to_request_id};

use serde::{Deserialize, Serialize};

pub(crate) mod anonymous;
pub(crate) mod basic;
pub(crate) mod secp256k1;

#[cfg(feature = "pem")]
pub(crate) mod error;

pub use anonymous::AnonymousIdentity;
pub use basic::BasicIdentity;
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

    /// Produce the public key commonly returned in [`Signature`].
    ///
    /// Should only return `None` if `sign` would do the same.
    fn public_key(&self) -> Option<Vec<u8>>;

    /// Sign a request ID derived from a content map.
    ///
    /// Implementors should call `content.to_request_id().signable()` for the actual bytes that need to be signed.
    fn sign(&self, content: &EnvelopeContent) -> Result<Signature, String>;

    /// Sign a delegation to let another key be used to authenticate [`sender`](Identity::sender).
    ///
    /// Not all `Identity` implementations support this operation, though all `ic-agent` implementations other than `AnonymousIdentity` do.
    ///
    /// Implementors should call `content.signable()` for the actual bytes that need to be signed.
    fn sign_delegation(&self, content: &Delegation) -> Result<Signature, String> {
        let _ = content; // silence unused warning
        Err(String::from("unsupported"))
    }

    /// Sign arbitrary bytes.
    ///
    /// Not all `Identity` implementations support this operation, though all `ic-agent` implementations do.
    fn sign_arbitrary(&self, content: &[u8]) -> Result<Signature, String> {
        let _ = content; // silence unused warning
        Err(String::from("unsupported"))
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

const IC_REQUEST_DELEGATION_DOMAIN_SEPARATOR: &[u8] = b"\x1Aic-request-auth-delegation";

impl Delegation {
    /// Returns the signable form of the delegation, by running it through [`to_request_id`]
    /// and prepending `\x1Aic-request-auth-delegation` to the result.
    pub fn signable(&self) -> Vec<u8> {
        let hash = to_request_id(self).unwrap();
        let mut bytes = Vec::with_capacity(59);
        bytes.extend_from_slice(IC_REQUEST_DELEGATION_DOMAIN_SEPARATOR);
        bytes.extend_from_slice(hash.as_slice());
        bytes
    }
}
