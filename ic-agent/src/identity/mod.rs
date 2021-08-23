//! Types and traits dealing with identity across the Internet Computer.
use crate::export::Principal;
use std::sync::Arc;

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

#[derive(Clone, Debug)]
pub struct Signature {
    /// This is the DER-encoded public key.
    pub public_key: Option<Vec<u8>>,
    pub signature: Option<Vec<u8>>,
}

/// An Identity takes a request id and returns the [Signature]. Since it
/// also knows about the Principal of the sender.
///
/// Agents are assigned a single Identity object, but there can be multiple
/// identities used
pub trait Identity: Send + Sync {
    /// Returns a sender, ie. the Principal ID that is used to sign a request.
    /// Only one sender can be used per request.
    fn sender(&self) -> Result<Principal, String>;

    /// Sign a blob, the concatenation of the domain separator & request ID,
    /// creating the sender signature.
    fn sign(&self, blob: &[u8]) -> Result<Signature, String>;
}

impl<I: Identity + ?Sized> Identity for Box<I> {
    fn sender(&self) -> Result<Principal, String> {
        (**self).sender()
    }
    fn sign(&self, blob: &[u8]) -> Result<Signature, String> {
        (**self).sign(blob)
    }
}
impl<I: Identity + ?Sized> Identity for Arc<I> {
    fn sender(&self) -> Result<Principal, String> {
        (**self).sender()
    }
    fn sign(&self, blob: &[u8]) -> Result<Signature, String> {
        (**self).sign(blob)
    }
}
