//! Types and traits dealing with identity across the Internet Computer.
use std::sync::Arc;

use crate::{agent::EnvelopeContent, export::Principal};

pub(crate) mod anonymous;
pub(crate) mod basic;
pub(crate) mod delegated;
pub(crate) mod error;
pub(crate) mod prime256v1;
pub(crate) mod secp256k1;

#[doc(inline)]
pub use anonymous::AnonymousIdentity;
#[doc(inline)]
pub use basic::BasicIdentity;
#[doc(inline)]
pub use delegated::DelegatedIdentity;
#[doc(inline)]
pub use error::DelegationError;
#[doc(inline)]
pub use ic_transport_types::{Delegation, SignedDelegation};
#[doc(inline)]
pub use prime256v1::Prime256v1Identity;
#[doc(inline)]
pub use secp256k1::Secp256k1Identity;

#[cfg(feature = "pem")]
#[doc(inline)]
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

/// Parses a PKCS#8 ("PRIVATE KEY") EC private key from raw DER bytes.
///
/// Validates that the algorithm OID is EC and that the curve OID matches `expected_curve`,
/// then returns the inner SEC1 private key bytes. Applies the dfx legacy hatchet surgery for
/// nonconforming containers if needed.
#[cfg(feature = "pem")]
fn parse_ec_pkcs8_key_bytes(
    der_bytes: &[u8],
    expected_curve: pkcs8::der::asn1::ObjectIdentifier,
    curve_name: &str,
) -> Result<Vec<u8>, error::PemError> {
    use pkcs8::{
        der::{Decode, Encode},
        PrivateKeyInfo,
    };

    let mut truncated: Vec<u8>;
    let pki = match PrivateKeyInfo::from_der(der_bytes) {
        Ok(pki) => pki,
        Err(e) => {
            // Very old versions of dfx generated nonconforming PKCS#8 containers.
            // This code was copied from agent-rs@1e67be03 via icp-cli.
            truncated = der_bytes.to_vec();
            if truncated.len() >= 52 && truncated[48..52] == *b"\xA1\x23\x03\x21" {
                truncated.truncate(48);
                truncated[1] = 46;
                truncated[4] = 0;
                PrivateKeyInfo::from_der(&truncated).map_err(|_| e)?
            } else {
                return Err(e.into());
            }
        }
    };
    if pki.algorithm.oid != elliptic_curve::ALGORITHM_OID {
        return Err(error::PemError::InvalidPrivateKey(format!(
            "expected EC algorithm OID {}, found {}",
            elliptic_curve::ALGORITHM_OID,
            pki.algorithm.oid,
        )));
    }
    let curve_oid = pki
        .algorithm
        .parameters_oid()
        .map_err(|_| pkcs8::Error::KeyMalformed)?;
    if curve_oid != expected_curve {
        return Err(error::PemError::UnsupportedKeyCurve(
            curve_name.to_string(),
            curve_oid.to_der().unwrap_or_default(),
        ));
    }
    Ok(pki.private_key.to_vec())
}
