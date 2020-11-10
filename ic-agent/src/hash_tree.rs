//! Types used to manage the Hash Tree. This type is currently private and should be improved
//! and reviewed before being moved to ic-types (where it should ultimately live).
//!
//! TODO: clean this file and move it to ic-types. When this is done, consider generalizing
//!       the Sha256Digest and use the same type in RequestId (they're interchangeable).
//!
//! cf https://docs.dfinity.systems/public/v/0.13.1/#_encoding_of_certificates
use openssl::sha::Sha256;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

/// Type alias for a sha256 result (ie. a u256).
pub type Sha256Digest = [u8; 32];

#[derive(Clone, Hash, Ord, PartialOrd, Eq, PartialEq, Deserialize)]
#[serde(from = "&serde_bytes::Bytes")]
#[serde(into = "serde_bytes::ByteBuf")]
pub struct Label(Vec<u8>);

impl Label {
    /// Returns this label as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl Into<serde_bytes::ByteBuf> for Label {
    fn into(self) -> serde_bytes::ByteBuf {
        serde_bytes::ByteBuf::from(self.as_bytes().to_vec())
    }
}

impl<T> From<T> for Label
where
    T: AsRef<[u8]>,
{
    fn from(s: T) -> Self {
        Self(s.as_ref().to_vec())
    }
}

impl std::fmt::Display for Label {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Try to print it as an UTF-8 string. If an error happens, print the bytes
        // as hexadecimal.
        match std::str::from_utf8(self.as_bytes()) {
            Ok(s) => f.write_str(s),
            Err(_) => {
                write!(f, "0x")?;
                std::fmt::Debug::fmt(self, f)
            }
        }
    }
}

impl std::fmt::Debug for Label {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_bytes()
            .iter()
            .try_for_each(|b| write!(f, "{:02X}", b))
    }
}

impl Serialize for Label {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            format!("{:?}", self).serialize(serializer)
        } else {
            serializer.serialize_bytes(self.0.as_ref())
        }
    }
}

/// A result of looking up for a certificate.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LookupResult<'tree> {
    /// The value is guaranteed to be absent in the original state tree.
    Absent,

    /// This partial view does not include information about this path, and the original
    /// tree may or may note include this value.
    Unknown,

    /// The value was found at the referenced node.
    Found(&'tree [u8]),

    /// The path does not make sense for this certificate.
    Error,
}

/// A HashTree representing a full tree.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HashTree {
    root: HashTreeNode,
}

impl HashTree {
    /// Recomputes root hash of the full tree that this hash tree was constructed from.
    #[inline]
    pub fn digest(&self) -> Sha256Digest {
        self.root.digest()
    }

    /// Given a (verified) tree, the client can fetch the value at a given path, which is a
    /// sequence of labels (blobs).
    pub fn lookup_path<P>(&self, path: P) -> LookupResult
    where
        P: AsRef<[Label]>,
    {
        self.root.lookup_path(path.as_ref())
    }
}

impl<'de> serde::Deserialize<'de> for HashTree {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(HashTree {
            root: HashTreeNode::deserialize(deserializer)?,
        })
    }
}

impl<'de> serde::Deserialize<'de> for HashTreeNode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de;

        struct SeqVisitor;

        impl<'de> de::Visitor<'de> for SeqVisitor {
            type Value = HashTreeNode;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str(
                    "HashTree encoded as a sequence of the form \
                     hash-tree ::= [0] | [1 hash-tree hash-tree] | [2 bytes hash-tree] | [3 bytes] | [4 hash]",
                )
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: de::SeqAccess<'de>,
            {
                let tag: u8 = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;

                match tag {
                    0 => {
                        if let Some(de::IgnoredAny) = seq.next_element()? {
                            return Err(de::Error::invalid_length(2, &self));
                        }

                        Ok(HashTreeNode::Empty())
                    }
                    1 => {
                        let left: HashTreeNode = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                        let right: HashTreeNode = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(2, &self))?;

                        if let Some(de::IgnoredAny) = seq.next_element()? {
                            return Err(de::Error::invalid_length(4, &self));
                        }

                        Ok(HashTreeNode::Fork(Box::new((left, right))))
                    }
                    2 => {
                        let label: Label = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                        let subtree: HashTreeNode = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(2, &self))?;

                        if let Some(de::IgnoredAny) = seq.next_element()? {
                            return Err(de::Error::invalid_length(4, &self));
                        }

                        Ok(HashTreeNode::Labeled(label, Box::new(subtree)))
                    }
                    3 => {
                        let bytes: serde_bytes::ByteBuf = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?;

                        if let Some(de::IgnoredAny) = seq.next_element()? {
                            return Err(de::Error::invalid_length(3, &self));
                        }

                        Ok(HashTreeNode::Leaf(bytes.into_vec()))
                    }
                    4 => {
                        let digest_bytes: serde_bytes::ByteBuf = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?;

                        if let Some(de::IgnoredAny) = seq.next_element()? {
                            return Err(de::Error::invalid_length(3, &self));
                        }

                        let digest =
                            Sha256Digest::try_from(digest_bytes.as_ref()).map_err(|_| {
                                de::Error::invalid_length(
                                    digest_bytes.len(),
                                    &"Expected digest blob",
                                )
                            })?;

                        Ok(HashTreeNode::Pruned(digest))
                    }
                    _ => Err(de::Error::custom(format!(
                        "Unknown tag: {}, expected the tag to be one of {{0, 1, 2, 3, 4}}",
                        tag
                    ))),
                }
            }
        }

        deserializer.deserialize_seq(SeqVisitor)
    }
}

/// Private type for label lookup result.
enum LookupLabelResult<'node> {
    /// The label is not part of this node's tree.
    Absent,

    /// The label was not found, but could still be somewhere else.
    Continue,

    /// The label was found. Contains a reference to the [HashTreeNode].
    Found(&'node HashTreeNode),
}

/// A Node in the HashTree.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum HashTreeNode {
    Empty(),
    Fork(Box<(HashTreeNode, HashTreeNode)>),
    Labeled(Label, Box<HashTreeNode>),
    Leaf(Vec<u8>),
    Pruned(Sha256Digest),
}

impl HashTreeNode {
    /// Get the domain separator (byte(|s|) . s).
    #[inline]
    pub fn domain_sep(&self, hasher: &mut Sha256) {
        let domain_sep = match self {
            HashTreeNode::Empty() => "ic-hashtree-empty",
            HashTreeNode::Fork(_) => "ic-hashtree-fork",
            HashTreeNode::Labeled(_, _) => "ic-hashtree-labeled",
            HashTreeNode::Leaf(_) => "ic-hashtree-leaf",
            HashTreeNode::Pruned(_) => return,
        };
        hasher.update(&domain_sep.len().to_ne_bytes());
        hasher.update(domain_sep.as_bytes());
    }

    /// Calculate the digest of this node only.
    #[inline]
    pub fn digest(&self) -> Sha256Digest {
        let mut hasher = Sha256::new();
        self.domain_sep(&mut hasher);

        match self {
            HashTreeNode::Empty() => {}
            HashTreeNode::Fork(nodes) => {
                hasher.update(&nodes.0.digest());
                hasher.update(&nodes.1.digest());
            }
            HashTreeNode::Labeled(label, node) => {
                hasher.update(&label.as_bytes());
                hasher.update(&node.digest());
            }
            HashTreeNode::Leaf(bytes) => {
                hasher.update(bytes);
            }
            HashTreeNode::Pruned(digest) => {
                return *digest;
            }
        }

        hasher.finish()
    }

    /// Lookup a single label, returning a reference to the labeled [HashTreeNode] node if found.
    ///
    /// This assumes a sorted hash tree, which is what the spec says the system should
    /// return. It will stop when it finds a label that's greater than the one being looked
    /// for.
    ///
    /// This function is implemented with flattening in mind, ie. flattening the forks
    /// is not necessary.
    fn lookup_label(&self, label: &Label) -> LookupLabelResult {
        match self {
            // If this node is a labeled node, check for the name. This assume a
            HashTreeNode::Labeled(l, node) => match label.cmp(l) {
                std::cmp::Ordering::Greater => LookupLabelResult::Continue,
                std::cmp::Ordering::Equal => LookupLabelResult::Found(node.as_ref()),
                // If this node has a smaller label than the one we're looking for, shortcut
                // out of this search (sorted tree), we looked too far.
                std::cmp::Ordering::Less => LookupLabelResult::Absent,
            },
            HashTreeNode::Fork(nodes) => match nodes.0.lookup_label(label) {
                // On continue, look on the right side of the fork.
                LookupLabelResult::Continue => nodes.1.lookup_label(label),
                result @ LookupLabelResult::Absent => result,
                result @ LookupLabelResult::Found(_) => result,
            },
            // Any other type of node and we need to look for more forks.
            _ => LookupLabelResult::Continue,
        }
    }

    /// Lookup the path for the current node only. If the node does not contain the label,
    /// this will return [None], signifying that whatever process is recursively walking the
    /// tree should continue with siblings of this node (if possible). If it returns
    /// [Some] value, then it found an actual result and this may be propagated to the
    /// original process doing the lookup.
    ///
    /// This assumes a sorted hash tree, which is what the spec says the system should return.
    /// It will stop when it finds a label that's greater than the one being looked for.
    fn lookup_path(&self, path: &[Label]) -> LookupResult {
        match self {
            HashTreeNode::Leaf(v) => {
                if path.is_empty() {
                    LookupResult::Found(v)
                } else {
                    LookupResult::Error
                }
            }
            HashTreeNode::Empty() => LookupResult::Absent,
            HashTreeNode::Pruned(_) => LookupResult::Unknown,
            _ => match self.lookup_label(&path[0]) {
                LookupLabelResult::Absent | LookupLabelResult::Continue => {
                    if path.is_empty() {
                        LookupResult::Absent
                    } else {
                        LookupResult::Error
                    }
                }
                LookupLabelResult::Found(node) => node.lookup_path(&path[1..]),
            },
        }
    }
}

#[cfg(test)]
mod hash_tree_tests;
