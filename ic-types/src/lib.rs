//! A collection of types related to the Internet Computer Protocol.
//!
//! If you need support for the serde library, you will need to use the `serde` feature
//! (available by default).

pub type Sha256Digest = [u8; 32];

/// Principal related types and traits.
pub mod principal;
pub use principal::{Principal, PrincipalError};

/// Hash Tree types and traits.
pub mod hash_tree;
pub use hash_tree::HashTree;
