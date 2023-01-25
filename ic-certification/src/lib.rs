//! A collection of types related to the Internet Computer Protocol.
//!
//! If you need support for the serde library, you will need to use the `serde` feature
//! (available by default).

pub mod hash_tree;
#[doc(inline)]
pub use hash_tree::{HashTree, Label, LookupResult, SubtreeLookupResult};

pub mod certificate;
#[doc(inline)]
pub use certificate::{Certificate, Delegation};
