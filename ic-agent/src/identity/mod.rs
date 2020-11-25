//! Types and traits dealing with identity across the Internet Computer.
use crate::export::Principal;

pub(crate) mod basic;
pub(crate) mod dummy;
pub(crate) mod hardware;
pub use basic::{BasicIdentity, PemError};
pub use hardware::HardwareIdentity;

#[derive(Clone, Debug)]
pub struct Signature {
    /// This is the DER-encoded public key.
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
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
    /// creating the sender signature, with the principal passed in.
    /// The principal should be
    /// the same returned by the call to `sender()`.
    fn sign(&self, blob: &[u8], principal: &Principal) -> Result<Signature, String>;
}
