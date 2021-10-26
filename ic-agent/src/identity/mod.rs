//! Types and traits dealing with identity across the Internet Computer.

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

pub use crate::ic_agent_ifaces::identity::Identity;
pub use crate::ic_agent_ifaces::signature::Signature;
