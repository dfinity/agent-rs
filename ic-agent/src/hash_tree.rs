/** Hash-tree

#### Resources:

- [Public spec link](https://hydra.dfinity.systems/latest/dfinity-ci-build/ic-ref.pr-218/public-spec/1/index.html#_encoding_of_certificates)

- [Reference implementation in the replica](https://github.com/dfinity-lab/dfinity/tree/master/rs/crypto/tree_hash)

*/
use serde::{export::Formatter, Deserialize, Serialize};

use openssl::sha::Sha256;

use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt;
use std::fmt::Debug;

const DOMAIN_HASHTREE_LEAF: &str = "ic-hashtree-leaf";
const DOMAIN_HASHTREE_EMPTY_SUBTREE: &str = "ic-hashtree-empty";
const DOMAIN_HASHTREE_NODE: &str = "ic-hashtree-labeled";
const DOMAIN_HASHTREE_FORK: &str = "ic-hashtree-fork";

/// A blob used as a label in the tree.
///
/// Most labels are expected to be printable ASCII strings, but some
/// are just short sequences of arbitrary bytes (e.g., CanisterIds).
#[derive(Clone, Serialize, Deserialize)]
#[serde(from = "&serde_bytes::Bytes")]
#[serde(into = "serde_bytes::ByteBuf")]
pub struct Label(LabelRepr);

/// Represents a path in a hash tree.
pub type Path = Vec<Label>;

/// Vec<u8> is typically 3 machine words long (pointer + size + capacity) which
/// is 24 bytes on amd64.  It's a good practice to keep enum variants of
/// approximately the same size. We want to optimize for labels of at most 32
/// bytes (as we will have many labels that are SHA256 hashes).
const SMALL_LABEL_SIZE: usize = 32;

/// This type hides the implementation of Label.
#[derive(Clone)]
enum LabelRepr {
    /// A label small enough to fit into this representation "by value". The
    /// first byte of the array indicates the number of bytes that should be
    /// used as label value, so we can fit up to SMALL_LABEL_SIZE bytes.
    Value([u8; SMALL_LABEL_SIZE + 1]),
    /// Label of size SMALL_LABEL_SIZE or longer.
    Ref(Vec<u8>),
}

impl PartialEq for Label {
    fn eq(&self, rhs: &Self) -> bool {
        self.as_bytes() == rhs.as_bytes()
    }
}

impl Eq for Label {}

impl Ord for Label {
    fn cmp(&self, rhs: &Self) -> std::cmp::Ordering {
        self.as_bytes().cmp(rhs.as_bytes())
    }
}

impl PartialOrd for Label {
    fn partial_cmp(&self, rhs: &Self) -> Option<std::cmp::Ordering> {
        self.as_bytes().partial_cmp(rhs.as_bytes())
    }
}

impl Label {
    pub fn as_bytes(&self) -> &[u8] {
        match &self.0 {
            LabelRepr::Value(bytes) => &bytes[1..=bytes[0] as usize],
            LabelRepr::Ref(v) => &v[..],
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl fmt::Debug for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn printable(byte: u8) -> bool {
            byte >= 32 && byte < 127
        }
        let bytes = self.as_bytes();
        if bytes.iter().all(|b| printable(*b)) {
            write!(f, "{}", std::str::from_utf8(bytes).unwrap())
        } else {
            write!(f, "0x")?;
            bytes.iter().try_for_each(|b| write!(f, "{:02X}", b))
        }
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Into<String> for Label {
    fn into(self) -> String {
        format!("{}", self)
    }
}

impl Into<serde_bytes::ByteBuf> for Label {
    fn into(self) -> serde_bytes::ByteBuf {
        serde_bytes::ByteBuf::from(self.to_vec())
    }
}

impl<T> From<T> for Label
where
    T: std::convert::AsRef<[u8]>,
{
    fn from(bytes: T) -> Label {
        let slice = bytes.as_ref();
        let n = slice.len();
        if n <= SMALL_LABEL_SIZE {
            let mut buf = [0u8; SMALL_LABEL_SIZE + 1];
            buf[0] = n as u8;
            buf[1..=n].copy_from_slice(slice);
            Self(LabelRepr::Value(buf))
        } else {
            Self(LabelRepr::Ref(slice.to_vec()))
        }
    }
}

#[derive(PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "0x")?;
        self.0.iter().try_for_each(|b| write!(f, "{:02X}", b))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<[u8; 32]> for Digest {
    fn from(bytes: [u8; 32]) -> Self {
        Digest(bytes)
    }
}

impl TryFrom<Vec<u8>> for Digest {
    type Error = Vec<u8>;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let a: Box<[u8; 32]> = bytes.into_boxed_slice().try_into()?;
        Ok(Digest(*a))
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

pub struct Hasher(Sha256);

impl Hasher {
    pub fn for_domain(domain: &str) -> Self {
        assert!(domain.len() < 256);
        let mut hasher = Self(Sha256::new());
        hasher.update(&[domain.len() as u8][..]);
        hasher.update(domain.as_bytes());
        hasher
    }
    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
    pub fn finalize(self) -> Digest {
        Digest(self.0.finish())
    }
}

/// Public spec [hash-tree](https://hydra.dfinity.systems/latest/dfinity-ci-build/ic-ref.pr-218/public-spec/1/index.html#_encoding_of_certificates)
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum HashTree {
    Empty,
    Fork(Box<(HashTree, HashTree)>),
    Labeled(Label, Box<HashTree>),
    Leaf(Vec<u8>),
    Pruned(Digest),
}

impl HashTree {
    /// Recomputes root hash of the full tree that this hash tree was
    /// constructed from.
    pub fn digest(&self) -> Digest {
        match self {
            Self::Empty => empty_subtree_hash(),
            Self::Fork(lr) => compute_fork_digest(&lr.0.digest(), &lr.1.digest()),
            Self::Labeled(label, subtree) => compute_node_digest(label, &subtree.digest()),
            Self::Leaf(buf) => compute_leaf_digest(&buf[..]),
            Self::Pruned(digest) => digest.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidHashTreeError {
    UnlabeledLeaf,
}

fn new_leaf_hasher() -> Hasher {
    Hasher::for_domain(DOMAIN_HASHTREE_LEAF)
}

fn new_fork_hasher() -> Hasher {
    Hasher::for_domain(DOMAIN_HASHTREE_FORK)
}

fn new_node_hasher() -> Hasher {
    Hasher::for_domain(DOMAIN_HASHTREE_NODE)
}

fn empty_subtree_hash() -> Digest {
    Hasher::for_domain(DOMAIN_HASHTREE_EMPTY_SUBTREE).finalize()
}

fn compute_leaf_digest(contents: &[u8]) -> Digest {
    let mut hasher = new_leaf_hasher();
    hasher.update(contents);
    hasher.finalize()
}

fn compute_node_digest(label: &Label, subtree_digest: &Digest) -> Digest {
    let mut hasher = new_node_hasher();
    hasher.update(label.as_bytes());
    hasher.update(&subtree_digest.0);
    hasher.finalize()
}

fn compute_fork_digest(left_digest: &Digest, right_digest: &Digest) -> Digest {
    let mut hasher = new_fork_hasher();
    hasher.update(&left_digest.0);
    hasher.update(&right_digest.0);
    hasher.finalize()
}

#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub enum Simple<X> {
    Leaf(X),
    Node(BTreeMap<Label, Simple<X>>),
}

impl<X> Simple<X> {
    fn lookup_rec(&self, path: Path, pos: usize) -> Option<&X> {
        if pos < path.len() {
            match self {
                Simple::Node(m) => match m.get(&path[pos]) {
                    Some(t) => t.lookup_rec(path, pos + 1),
                    None => None,
                },
                Simple::Leaf(_) => None,
            }
        } else {
            match self {
                Simple::Leaf(ref x) => Some(x),
                _ => None,
            }
        }
    }

    // lookup a path, as in [public spec](https://hydra.dfinity.systems/latest/dfinity-ci-build/ic-ref.pr-218/public-spec/1/index.html#_lookup)
    pub fn lookup(&self, path: Path) -> Option<&X> {
        self.lookup_rec(path, 0)
    }
}

/// Simplify the HashTree into a Simple tree.
impl TryFrom<HashTree> for Simple<Vec<u8>> {
    type Error = InvalidHashTreeError;

    fn try_from(root: HashTree) -> Result<Self, InvalidHashTreeError> {
        fn collect_children(
            t: HashTree,
            children: &mut BTreeMap<Label, Simple<Vec<u8>>>,
        ) -> Result<(), InvalidHashTreeError> {
            match t {
                HashTree::Leaf(_) => Err(InvalidHashTreeError::UnlabeledLeaf),
                HashTree::Labeled(label, subtree) => {
                    children.insert(label, (*subtree).try_into()?);
                    Ok(())
                }
                HashTree::Fork(lr) => {
                    collect_children(lr.0, children)?;
                    collect_children(lr.1, children)
                }
                HashTree::Pruned(_) | HashTree::Empty => Ok(()),
            }
        }

        Ok(match root {
            HashTree::Leaf(data) => Simple::Leaf(data),
            HashTree::Labeled(_, _) | HashTree::Fork(_) => {
                let mut children = BTreeMap::new();
                collect_children(root, &mut children)?;
                Simple::Node(children)
            }
            HashTree::Pruned(_) | HashTree::Empty => Simple::Node(Default::default()),
        })
    }
}

impl<'de> serde::de::Deserialize<'de> for HashTree {
    fn deserialize<D>(deserializer: D) -> Result<HashTree, D::Error>
        where
            D: serde::de::Deserializer<'de>,
    {
        use serde::de::{self, IgnoredAny, SeqAccess, Visitor};

        struct SeqVisitor;

        impl<'de> Visitor<'de> for SeqVisitor {
            type Value = HashTree;

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
                        if let Some(IgnoredAny) = seq.next_element()? {
                            return Err(de::Error::invalid_length(2, &self));
                        }

                        Ok(HashTree::Empty)
                    }
                    1 => {
                        let left: HashTree = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                        let right: HashTree = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(2, &self))?;

                        if let Some(IgnoredAny) = seq.next_element()? {
                            return Err(de::Error::invalid_length(4, &self));
                        }

                        Ok(HashTree::Fork(Box::new((left, right))))
                    }
                    2 => {
                        let label: Label = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                        let subtree: HashTree = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(2, &self))?;

                        if let Some(IgnoredAny) = seq.next_element()? {
                            return Err(de::Error::invalid_length(4, &self));
                        }

                        Ok(HashTree::Labeled(label, Box::new(subtree)))
                    }
                    3 => {
                        let bytes: serde_bytes::ByteBuf = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?;

                        if let Some(IgnoredAny) = seq.next_element()? {
                            return Err(de::Error::invalid_length(3, &self));
                        }

                        Ok(HashTree::Leaf(bytes.into_vec()))
                    }
                    4 => {
                        let digest_bytes: serde_bytes::ByteBuf = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?;

                        if let Some(IgnoredAny) = seq.next_element()? {
                            return Err(de::Error::invalid_length(3, &self));
                        }

                        let digest = Digest::try_from(digest_bytes.into_vec()).map_err(|err| {
                            de::Error::invalid_length(err.len(), &"Expected digest blob")
                        })?;

                        Ok(HashTree::Pruned(digest))
                    }
                    _ => Err(de::Error::custom(format!(
                        "unknown tag: {}, expected the tag to be one of {{0, 1, 2, 3, 4}}",
                        tag
                    ))),
                }
            }
        }

        deserializer.deserialize_seq(SeqVisitor)
    }
}
