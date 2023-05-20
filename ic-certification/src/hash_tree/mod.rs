//! cf <https://internetcomputer.org/docs/current/references/ic-interface-spec/#certification-encoding>

use hex::FromHexError;
use sha2::Digest;
use std::{
    borrow::{Borrow, Cow},
    fmt,
};

/// Sha256 Digest: 32 bytes
pub type Sha256Digest = [u8; 32];

#[derive(Clone, Hash, Ord, PartialOrd, Eq, PartialEq)]
/// For labeled [HashTreeNode]
pub struct Label<Storage: AsRef<[u8]>>(Storage);

impl<Storage: AsRef<[u8]>> Label<Storage> {
    /// Create a label from bytes.
    pub fn from_bytes<'a>(v: &'a [u8]) -> Self
    where
        &'a [u8]: Into<Storage>,
    {
        Self(v.into())
    }

    /// Convert labels
    pub fn from_label<StorageB: AsRef<[u8]> + Into<Storage>>(s: Label<StorageB>) -> Self {
        Self(s.0.into())
    }

    /// Returns this label as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// The length of the output of [`Self::write_hex`]
    fn hex_len(&self) -> usize {
        self.as_bytes().len() * 2
    }

    /// Write out the hex
    fn write_hex(&self, f: &mut impl fmt::Write) -> fmt::Result {
        self.as_bytes()
            .iter()
            .try_for_each(|b| write!(f, "{:02X}", b))
    }
}

impl<Storage: AsRef<[u8]>> From<Storage> for Label<Storage> {
    fn from(s: Storage) -> Self {
        Self(s)
    }
}

impl<const N: usize> From<[u8; N]> for Label<Vec<u8>> {
    fn from(s: [u8; N]) -> Self {
        Self(s.into())
    }
}
impl<'a, const N: usize> From<&'a [u8; N]> for Label<Vec<u8>> {
    fn from(s: &'a [u8; N]) -> Self {
        Self(s.as_slice().into())
    }
}
impl<'a> From<&'a [u8]> for Label<Vec<u8>> {
    fn from(s: &'a [u8]) -> Self {
        Self(s.into())
    }
}
impl<'a> From<&'a str> for Label<Vec<u8>> {
    fn from(s: &'a str) -> Self {
        Self(s.as_bytes().into())
    }
}
impl From<String> for Label<Vec<u8>> {
    fn from(s: String) -> Self {
        Self(s.into())
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for Label<&'a [u8]> {
    fn from(s: &'a [u8; N]) -> Self {
        Self(s.as_slice())
    }
}
impl<'a> From<&'a str> for Label<&'a [u8]> {
    fn from(s: &'a str) -> Self {
        Self(s.as_bytes())
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for Label<Cow<'a, [u8]>> {
    fn from(s: &'a [u8; N]) -> Self {
        Self(s.as_slice().into())
    }
}
impl<'a> From<&'a [u8]> for Label<Cow<'a, [u8]>> {
    fn from(s: &'a [u8]) -> Self {
        Self(s.into())
    }
}
impl<'a> From<&'a str> for Label<Cow<'a, [u8]>> {
    fn from(s: &'a str) -> Self {
        Self(s.as_bytes().into())
    }
}

impl<Storage: AsRef<[u8]>> fmt::Display for Label<Storage> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use fmt::Write;

        // Try to print it as an UTF-8 string. If an error happens, print the bytes
        // as hexadecimal.
        match std::str::from_utf8(self.as_bytes()) {
            Ok(s) if s.chars().all(|c| c.is_ascii_graphic()) => {
                f.write_char('"')?;
                f.write_str(s)?;
                f.write_char('"')
            }
            _ => {
                write!(f, "0x")?;
                fmt::Debug::fmt(self, f)
            }
        }
    }
}

impl<Storage: AsRef<[u8]>> fmt::Debug for Label<Storage> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_hex(f)
    }
}

impl<Storage: AsRef<[u8]>> AsRef<[u8]> for Label<Storage> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
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

/// A result of looking up for a subtree.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SubtreeLookupResult<Storage: AsRef<[u8]>> {
    /// The subtree at the provided path is guaranteed to be absent in the original state tree.
    Absent,

    /// This partial view does not include information about this path, and the original
    /// tree may or may note include a subtree at this path.
    Unknown,

    /// The subtree was found at the provided path.
    Found(HashTree<Storage>),
}

/// A HashTree representing a full tree.
#[derive(Clone, PartialEq, Eq)]
pub struct HashTree<Storage: AsRef<[u8]>> {
    root: HashTreeNode<Storage>,
}

impl<Storage: AsRef<[u8]>> fmt::Debug for HashTree<Storage> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HashTree")
            .field("root", &self.root)
            .finish()
    }
}

#[allow(dead_code)]
impl<Storage: AsRef<[u8]>> HashTree<Storage> {
    /// Recomputes root hash of the full tree that this hash tree was constructed from.
    #[inline]
    pub fn digest(&self) -> Sha256Digest {
        self.root.digest()
    }

    /// Given a (verified) tree, the client can fetch the value at a given path, which is a
    /// sequence of labels (blobs).
    pub fn lookup_path<P>(&self, path: P) -> LookupResult<'_>
    where
        P: IntoIterator,
        P::Item: AsRef<[u8]>,
    {
        self.root.lookup_path(&mut path.into_iter())
    }
}

impl<Storage: Clone + AsRef<[u8]>> HashTree<Storage> {
    /// Given a (verified) tree, the client can fetch the subtree at a given path, which is a
    /// sequence of labels (blobs).
    pub fn lookup_subtree<'p, P, I>(&self, path: P) -> SubtreeLookupResult<Storage>
    where
        P: IntoIterator<Item = &'p I>,
        I: ?Sized + AsRef<[u8]> + 'p,
    {
        self.root
            .lookup_subtree(&mut path.into_iter().map(|v| v.borrow()))
    }

    /// List all paths in the [HashTree]
    pub fn list_paths(&self) -> Vec<Vec<Label<Storage>>> {
        self.root.list_paths(&vec![])
    }
}

impl<Storage: AsRef<[u8]>> AsRef<HashTreeNode<Storage>> for HashTree<Storage> {
    fn as_ref(&self) -> &HashTreeNode<Storage> {
        &self.root
    }
}

impl<Storage: AsRef<[u8]>> From<HashTree<Storage>> for HashTreeNode<Storage> {
    fn from(tree: HashTree<Storage>) -> HashTreeNode<Storage> {
        tree.root
    }
}

/// Create an empty hash tree.
#[inline]
pub fn empty<Storage: AsRef<[u8]>>() -> HashTree<Storage> {
    HashTree {
        root: HashTreeNode::Empty(),
    }
}

/// Create a forked tree from two trees or node.
#[inline]
pub fn fork<Storage: AsRef<[u8]>>(
    left: HashTree<Storage>,
    right: HashTree<Storage>,
) -> HashTree<Storage> {
    HashTree {
        root: HashTreeNode::Fork(Box::new((left.root, right.root))),
    }
}

/// Create a labeled hash tree.
#[inline]
pub fn label<Storage: AsRef<[u8]>, L: Into<Label<Storage>>, N: Into<HashTree<Storage>>>(
    label: L,
    node: N,
) -> HashTree<Storage> {
    HashTree {
        root: HashTreeNode::Labeled(label.into(), Box::new(node.into().root)),
    }
}

/// Create a leaf in the tree.
#[inline]
pub fn leaf<Storage: AsRef<[u8]>, L: Into<Storage>>(leaf: L) -> HashTree<Storage> {
    HashTree {
        root: HashTreeNode::Leaf(leaf.into()),
    }
}

/// Create a pruned tree node.
#[inline]
pub fn pruned<Storage: AsRef<[u8]>, C: Into<Sha256Digest>>(content: C) -> HashTree<Storage> {
    HashTree {
        root: HashTreeNode::Pruned(content.into()),
    }
}

/// Create a pruned tree node, from a hex representation of the data. Useful for
/// testing or hard coded values.
#[inline]
pub fn pruned_from_hex<Storage: AsRef<[u8]>, C: AsRef<str>>(
    content: C,
) -> Result<HashTree<Storage>, FromHexError> {
    let mut decode: Sha256Digest = [0; 32];
    hex::decode_to_slice(content.as_ref(), &mut decode)?;

    Ok(pruned(decode))
}

/// Private type for label lookup result.
#[derive(Debug)]
enum LookupLabelResult<'node, Storage: AsRef<[u8]>> {
    /// The label is not part of this node's tree.
    Absent,

    /// Same as absent, but some leaves were pruned and so it's impossible to know.
    Unknown,

    /// The label was not found, but could still be to the left.
    Less,

    /// The label was not found, but could still be to the right.
    Greater,

    /// The label was found. Contains a reference to the [HashTreeNode].
    Found(&'node HashTreeNode<Storage>),
}

/// A Node in the HashTree.
#[derive(Clone, PartialEq, Eq)]
pub enum HashTreeNode<Storage: AsRef<[u8]>> {
    Empty(),
    Fork(Box<(Self, Self)>),
    Labeled(Label<Storage>, Box<Self>),
    Leaf(Storage),
    Pruned(Sha256Digest),
}

impl<Storage: AsRef<[u8]>> fmt::Debug for HashTreeNode<Storage> {
    // Shows a nicer view to debug than the default debugger.
    // Example:
    //
    // ```
    // HashTree {
    //     root: Fork(
    //         Fork(
    //             Label("a", Fork(
    //                 Pruned(1b4feff9bef8131788b0c9dc6dbad6e81e524249c879e9f10f71ce3749f5a638),
    //                 Label("y", Leaf("world")),
    //             )),
    //             Label("b", Pruned(7b32ac0c6ba8ce35ac82c255fc7906f7fc130dab2a090f80fe12f9c2cae83ba6)),
    //         ),
    //         Fork(
    //             Pruned(ec8324b8a1f1ac16bd2e806edba78006479c9877fed4eb464a25485465af601d),
    //             Label("d", Leaf("morning")),
    //         ),
    //     ),
    // }
    // ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn readable_print(f: &mut fmt::Formatter<'_>, v: &[u8]) -> fmt::Result {
            // If it's UTF-8 and all the characters are graphic ASCII, then show as a string.
            // If it's short, show hex.
            // Otherwise, show length.
            match std::str::from_utf8(v) {
                Ok(s) if s.chars().all(|c| c.is_ascii_graphic()) => {
                    f.write_str("\"")?;
                    f.write_str(s)?;
                    f.write_str("\"")
                }
                _ if v.len() <= 32 => {
                    f.write_str("0x")?;
                    f.write_str(&hex::encode(v))
                }
                _ => {
                    write!(f, "{} bytes", v.len())
                }
            }
        }

        match self {
            HashTreeNode::Empty() => f.write_str("Empty"),
            HashTreeNode::Fork(nodes) => f
                .debug_tuple("Fork")
                .field(&nodes.0)
                .field(&nodes.1)
                .finish(),
            HashTreeNode::Leaf(v) => {
                f.write_str("Leaf(")?;
                readable_print(f, v.as_ref())?;
                f.write_str(")")
            }
            HashTreeNode::Labeled(l, node) => {
                f.write_str("Label(")?;
                readable_print(f, l.as_bytes())?;
                f.write_str(", ")?;
                node.fmt(f)?;
                f.write_str(")")
            }
            HashTreeNode::Pruned(digest) => write!(f, "Pruned({})", hex::encode(digest.as_ref())),
        }
    }
}

impl<Storage: AsRef<[u8]>> HashTreeNode<Storage> {
    /// Update a hasher with the domain separator (byte(|s|) . s).
    #[inline]
    fn domain_sep(&self, hasher: &mut sha2::Sha256) {
        let domain_sep = match self {
            HashTreeNode::Empty() => "ic-hashtree-empty",
            HashTreeNode::Fork(_) => "ic-hashtree-fork",
            HashTreeNode::Labeled(_, _) => "ic-hashtree-labeled",
            HashTreeNode::Leaf(_) => "ic-hashtree-leaf",
            HashTreeNode::Pruned(_) => return,
        };
        hasher.update([domain_sep.len() as u8]);
        hasher.update(domain_sep.as_bytes());
    }

    /// Calculate the digest of this node only.
    #[inline]
    pub fn digest(&self) -> Sha256Digest {
        let mut hasher = sha2::Sha256::new();
        self.domain_sep(&mut hasher);

        match self {
            HashTreeNode::Empty() => {}
            HashTreeNode::Fork(nodes) => {
                hasher.update(nodes.0.digest());
                hasher.update(nodes.1.digest());
            }
            HashTreeNode::Labeled(label, node) => {
                hasher.update(label.as_bytes());
                hasher.update(node.digest());
            }
            HashTreeNode::Leaf(bytes) => {
                hasher.update(bytes.as_ref());
            }
            HashTreeNode::Pruned(digest) => {
                return *digest;
            }
        }

        hasher.finalize().into()
    }

    /// Lookup a single label, returning a reference to the labeled [HashTreeNode] node if found.
    ///
    /// This assumes a sorted hash tree, which is what the spec says the system should
    /// return. It will stop when it finds a label that's greater than the one being looked
    /// for.
    ///
    /// This function is implemented with flattening in mind, ie. flattening the forks
    /// is not necessary.
    fn lookup_label(&self, label: &[u8]) -> LookupLabelResult<Storage> {
        match self {
            // If this node is a labeled node, check for the name.
            HashTreeNode::Labeled(l, node) => match label.cmp(l.as_bytes()) {
                std::cmp::Ordering::Greater => LookupLabelResult::Greater,
                std::cmp::Ordering::Equal => LookupLabelResult::Found(node.as_ref()),
                // If this node has a smaller label than the one we're looking for, shortcut
                // out of this search (sorted tree), we looked too far.
                std::cmp::Ordering::Less => LookupLabelResult::Less,
            },
            HashTreeNode::Fork(nodes) => {
                let left_label = nodes.0.lookup_label(label);
                match left_label {
                    // On greater or unknown, look on the right side of the fork.
                    LookupLabelResult::Greater => {
                        let right_label = nodes.1.lookup_label(label);
                        match right_label {
                            LookupLabelResult::Less => LookupLabelResult::Absent,
                            result => result,
                        }
                    }
                    LookupLabelResult::Unknown => {
                        let right_label = nodes.1.lookup_label(label);
                        match right_label {
                            LookupLabelResult::Less => LookupLabelResult::Unknown,
                            result => result,
                        }
                    }
                    result => result,
                }
            }
            HashTreeNode::Pruned(_) => LookupLabelResult::Unknown,
            // Any other type of node and we need to look for more forks.
            _ => LookupLabelResult::Absent,
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
    fn lookup_path(&self, path: &mut dyn Iterator<Item = impl AsRef<[u8]>>) -> LookupResult<'_> {
        use HashTreeNode::*;
        use LookupLabelResult as LLR;
        use LookupResult::*;

        match (
            path.next()
                .map(|segment| self.lookup_label(segment.as_ref())),
            self,
        ) {
            (Some(LLR::Found(node)), _) => node.lookup_path(path),
            (None, Leaf(v)) => Found(v.as_ref()),

            (None, Empty()) => Absent,
            (None, Pruned(_)) => Unknown,
            (None, Labeled(_, _) | Fork(_)) => Error,

            (Some(LLR::Unknown), _) => Unknown,
            (Some(LLR::Absent | LLR::Greater | LLR::Less), _) => Absent,
        }
    }
}

impl<Storage: Clone + AsRef<[u8]>> HashTreeNode<Storage> {
    /// Lookup a subtree at the provided path.
    /// If the tree definitely does not contain the label, this will return [SubtreeLookupResult::Absent].
    /// If the tree has pruned sections that might contain the path, this will return [SubtreeLookupResult::Unknown].
    /// If the provided path is found, this will return [SubtreeLookupResult::Found] with the node that was found at that path.
    ///
    /// This assumes a sorted hash tree, which is what the spec says the system should return.
    /// It will stop when it finds a label that's greater than the one being looked for.
    fn lookup_subtree(
        &self,
        path: &mut dyn Iterator<Item = impl AsRef<[u8]>>,
    ) -> SubtreeLookupResult<Storage> {
        use LookupLabelResult as LLR;
        use SubtreeLookupResult::*;

        match path
            .next()
            .map(|segment| self.lookup_label(segment.as_ref()))
        {
            Some(LLR::Found(node)) => node.lookup_subtree(path),
            Some(LLR::Unknown) => Unknown,
            Some(LLR::Absent | LLR::Greater | LLR::Less) => Absent,
            None => Found(HashTree {
                root: self.to_owned(),
            }),
        }
    }

    fn list_paths(&self, path: &Vec<Label<Storage>>) -> Vec<Vec<Label<Storage>>> {
        match self {
            HashTreeNode::Empty() => vec![],
            HashTreeNode::Fork(nodes) => {
                [nodes.0.list_paths(path), nodes.1.list_paths(path)].concat()
            }
            HashTreeNode::Leaf(_) => vec![path.clone()],
            HashTreeNode::Labeled(l, node) => {
                let mut path = path.clone();
                path.push(l.clone());
                node.list_paths(&path)
            }
            HashTreeNode::Pruned(_) => vec![],
        }
    }
}
#[cfg(feature = "serde")]
mod serde_impl {
    use std::{borrow::Cow, fmt, marker::PhantomData};

    use crate::serde_impl::{CowStorage, SliceStorage, Storage, VecStorage};

    use super::{HashTree, HashTreeNode, Label};

    use serde::{
        de::{self, SeqAccess, Visitor},
        ser::SerializeSeq,
        Deserialize, Deserializer, Serialize, Serializer,
    };
    use serde_bytes::Bytes;

    impl<Storage: AsRef<[u8]>> Serialize for Label<Storage> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            if serializer.is_human_readable() {
                let mut s = String::with_capacity(self.hex_len());
                self.write_hex(&mut s).unwrap();
                s.serialize(serializer)
            } else {
                serializer.serialize_bytes(self.0.as_ref())
            }
        }
    }
    impl<'de, Storage: AsRef<[u8]>> Deserialize<'de> for Label<Storage>
    where
        Storage: serde_bytes::Deserialize<'de>,
    {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            serde_bytes::deserialize(deserializer).map(Self)
        }
    }

    impl<Storage: AsRef<[u8]>> Serialize for HashTreeNode<Storage> {
        // Serialize a `MixedHashTree` per the CDDL of the public spec.
        // See https://docs.dfinity.systems/public/certificates.cddl
        fn serialize<S>(
            &self,
            serializer: S,
        ) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
        where
            S: Serializer,
        {
            match self {
                HashTreeNode::Empty() => {
                    let mut seq = serializer.serialize_seq(Some(1))?;
                    seq.serialize_element(&0u8)?;
                    seq.end()
                }
                HashTreeNode::Fork(tree) => {
                    let mut seq = serializer.serialize_seq(Some(3))?;
                    seq.serialize_element(&1u8)?;
                    seq.serialize_element(&tree.0)?;
                    seq.serialize_element(&tree.1)?;
                    seq.end()
                }
                HashTreeNode::Labeled(label, tree) => {
                    let mut seq = serializer.serialize_seq(Some(3))?;
                    seq.serialize_element(&2u8)?;
                    seq.serialize_element(Bytes::new(label.as_bytes()))?;
                    seq.serialize_element(&tree)?;
                    seq.end()
                }
                HashTreeNode::Leaf(leaf_bytes) => {
                    let mut seq = serializer.serialize_seq(Some(2))?;
                    seq.serialize_element(&3u8)?;
                    seq.serialize_element(Bytes::new(leaf_bytes.as_ref()))?;
                    seq.end()
                }
                HashTreeNode::Pruned(digest) => {
                    let mut seq = serializer.serialize_seq(Some(2))?;
                    seq.serialize_element(&4u8)?;
                    seq.serialize_element(Bytes::new(digest))?;
                    seq.end()
                }
            }
        }
    }

    struct HashTreeNodeVisitor<S>(PhantomData<S>);

    impl<'de, S: Storage> Visitor<'de> for HashTreeNodeVisitor<S>
    where
        HashTreeNode<S::Value<'de>>: Deserialize<'de>,
    {
        type Value = HashTreeNode<S::Value<'de>>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str(
                "HashTree encoded as a sequence of the form \
                 hash-tree ::= [0] | [1 hash-tree hash-tree] | [2 bytes hash-tree] | [3 bytes] | [4 hash]",
            )
        }

        fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
        where
            V: SeqAccess<'de>,
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
                    let left = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                    let right = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(2, &self))?;

                    if let Some(de::IgnoredAny) = seq.next_element()? {
                        return Err(de::Error::invalid_length(4, &self));
                    }

                    Ok(HashTreeNode::Fork(Box::new((left, right))))
                }
                2 => {
                    let label = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                    let subtree = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(2, &self))?;

                    if let Some(de::IgnoredAny) = seq.next_element()? {
                        return Err(de::Error::invalid_length(4, &self));
                    }

                    Ok(HashTreeNode::Labeled(
                        Label(S::convert(label)),
                        Box::new(subtree),
                    ))
                }
                3 => {
                    let bytes = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(1, &self))?;

                    if let Some(de::IgnoredAny) = seq.next_element()? {
                        return Err(de::Error::invalid_length(3, &self));
                    }

                    Ok(HashTreeNode::Leaf(S::convert(bytes)))
                }
                4 => {
                    let digest_bytes: &serde_bytes::Bytes = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(1, &self))?;

                    if let Some(de::IgnoredAny) = seq.next_element()? {
                        return Err(de::Error::invalid_length(3, &self));
                    }

                    let digest =
                        std::convert::TryFrom::try_from(digest_bytes.as_ref()).map_err(|_| {
                            de::Error::invalid_length(digest_bytes.len(), &"Expected digest blob")
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

    impl<'de> Deserialize<'de> for HashTreeNode<Vec<u8>> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_seq(HashTreeNodeVisitor::<VecStorage>(PhantomData))
        }
    }

    impl<'de> Deserialize<'de> for HashTreeNode<&'de [u8]> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_seq(HashTreeNodeVisitor::<SliceStorage>(PhantomData))
        }
    }

    impl<'de> Deserialize<'de> for HashTreeNode<Cow<'de, [u8]>> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_seq(HashTreeNodeVisitor::<CowStorage>(PhantomData))
        }
    }

    impl<Storage: AsRef<[u8]>> serde::Serialize for HashTree<Storage> {
        fn serialize<S>(
            &self,
            serializer: S,
        ) -> Result<<S as serde::Serializer>::Ok, <S as serde::Serializer>::Error>
        where
            S: serde::Serializer,
        {
            self.root.serialize(serializer)
        }
    }

    impl<'de, Storage: AsRef<[u8]>> serde::Deserialize<'de> for HashTree<Storage>
    where
        HashTreeNode<Storage>: Deserialize<'de>,
    {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            Ok(HashTree {
                root: HashTreeNode::deserialize(deserializer)?,
            })
        }
    }
}

#[cfg(test)]
mod tests;
