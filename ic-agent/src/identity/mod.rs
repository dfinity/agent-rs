//! Types and traits dealing with identity across the Internet Computer.
use crate::{agent::EnvelopeContent, export::Principal};

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

/// An Identity takes a request id and returns the [Signature]. It knows or
/// represents the Principal of the sender.
///
/// Agents are assigned a single Identity object, but there can be multiple
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
}
