//! A collection of types related to the Internet Computer Protocol.
//!
//! If you need support for the serde library, you will need to use the `serde` feature
//! (available by default).
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use hash_tree::Sha256Digest;
use hex::FromHexError;

pub mod certificate;
pub mod hash_tree;

#[doc(inline)]
pub use hash_tree::LookupResult;

/// A HashTree representing a full tree.
pub type HashTree = hash_tree::HashTree<Vec<u8>>;
/// For labeled [`HashTreeNode`](hash_tree::HashTreeNode)
pub type Label = hash_tree::Label<Vec<u8>>;
/// A result of looking up for a subtree.
pub type SubtreeLookupResult = hash_tree::SubtreeLookupResult<Vec<u8>>;

/// A `Delegation` as defined in <https://internetcomputer.org/docs/current/references/ic-interface-spec/#certification-delegation>
pub type Delegation = certificate::Delegation<Vec<u8>>;
/// A `Certificate` as defined in <https://internetcomputer.org/docs/current/references/ic-interface-spec/#certificate>
pub type Certificate = certificate::Certificate<Vec<u8>>;

/// Create an empty hash tree.
#[inline]
pub fn empty() -> HashTree {
    hash_tree::empty()
}

/// Create a forked tree from two trees or node.
#[inline]
pub fn fork(left: HashTree, right: HashTree) -> HashTree {
    hash_tree::fork(left, right)
}

/// Create a labeled hash tree.
#[inline]
pub fn label<L: Into<Label>, N: Into<HashTree>>(label: L, node: N) -> HashTree {
    hash_tree::label(label, node)
}

/// Create a leaf in the tree.
#[inline]
pub fn leaf<L: Into<Vec<u8>>>(leaf: L) -> HashTree {
    hash_tree::leaf(leaf)
}

/// Create a pruned tree node.
#[inline]
pub fn pruned<C: Into<Sha256Digest>>(content: C) -> HashTree {
    hash_tree::pruned(content)
}

/// Create a pruned tree node, from a hex representation of the data. Useful for
/// testing or hard coded values.
#[inline]
pub fn pruned_from_hex<C: AsRef<str>>(content: C) -> Result<HashTree, FromHexError> {
    hash_tree::pruned_from_hex(content)
}

#[cfg(feature = "serde")]
mod serde_impl {
    use std::borrow::Cow;

    use serde::Deserialize;
    use serde_bytes::{ByteBuf, Bytes};

    /// A trait to genericize deserializing owned or borrowed bytes
    pub trait Storage {
        type Temp<'a>: Deserialize<'a>;
        type Value<'a>: AsRef<[u8]>;
        fn convert(t: Self::Temp<'_>) -> Self::Value<'_>;
    }

    /// `Vec<u8>`
    pub struct VecStorage;
    /// `&[u8]`
    pub struct SliceStorage;
    /// `Cow<[u8]>`
    pub struct CowStorage;

    impl Storage for VecStorage {
        type Temp<'a> = ByteBuf;
        type Value<'a> = Vec<u8>;
        fn convert(t: Self::Temp<'_>) -> Self::Value<'_> {
            t.into_vec()
        }
    }

    impl Storage for SliceStorage {
        type Temp<'a> = &'a Bytes;
        type Value<'a> = &'a [u8];
        fn convert(t: Self::Temp<'_>) -> Self::Value<'_> {
            t.as_ref()
        }
    }

    impl Storage for CowStorage {
        type Temp<'a> = &'a Bytes;
        type Value<'a> = Cow<'a, [u8]>;
        fn convert(t: Self::Temp<'_>) -> Self::Value<'_> {
            Cow::Borrowed(t.as_ref())
        }
    }
}
