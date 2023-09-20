//! Types and traits dealing with identity across the Internet Computer.
use std::sync::Arc;

use crate::{agent::EnvelopeContent, export::Principal};

pub(crate) mod anonymous;
pub(crate) mod basic;
pub(crate) mod delegated;
pub(crate) mod secp256k1;

#[cfg(feature = "pem")]
pub(crate) mod error;

#[doc(inline)]
pub use anonymous::AnonymousIdentity;
#[doc(inline)]
pub use basic::BasicIdentity;
#[doc(inline)]
pub use delegated::DelegatedIdentity;
#[doc(inline)]
pub use ic_transport_types::{Delegation, SignedDelegation};
#[doc(inline)]
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

    /// A list of signed delegations connecting [`sender`](Identity::sender)
    /// to [`public_key`](Identity::public_key), and in that order.
    fn delegation_chain(&self) -> Vec<SignedDelegation> {
        vec![]
    }
}

macro_rules! delegating_impl {
    ($implementor:ty, $name:ident => $self_expr:expr) => {
        impl Identity for $implementor {
            fn sender(&$name) -> Result<Principal, String> {
                $self_expr.sender()
            }

            fn public_key(&$name) -> Option<Vec<u8>> {
                $self_expr.public_key()
            }

            fn sign(&$name, content: &EnvelopeContent) -> Result<Signature, String> {
                $self_expr.sign(content)
            }

            fn sign_delegation(&$name, content: &Delegation) -> Result<Signature, String> {
                $self_expr.sign_delegation(content)
            }

            fn sign_arbitrary(&$name, content: &[u8]) -> Result<Signature, String> {
                $self_expr.sign_arbitrary(content)
            }

            fn delegation_chain(&$name) -> Vec<SignedDelegation> {
                $self_expr.delegation_chain()
            }
        }
    };
}

delegating_impl!(Box<dyn Identity>, self => **self);
delegating_impl!(Arc<dyn Identity>, self => **self);
delegating_impl!(&dyn Identity, self => *self);
