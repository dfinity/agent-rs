#![cfg(test)]
use crate::hash_tree::{HashTree, HashTreeNode, Label, LookupResult, Sha256Digest};

fn fork(left: HashTreeNode, right: HashTreeNode) -> HashTreeNode {
    HashTreeNode::Fork(Box::new((left, right)))
}
fn label(label: &str, node: HashTreeNode) -> HashTreeNode {
    HashTreeNode::Labeled(label.into(), Box::new(node))
}
fn pruned(hash: &str) -> HashTreeNode {
    let digest: Sha256Digest =
        std::convert::TryFrom::try_from(hex::decode(hash.as_bytes()).unwrap().as_ref()).unwrap();
    HashTreeNode::Pruned(digest)
}
fn leaf(value: &[u8]) -> HashTreeNode {
    HashTreeNode::Leaf(value.to_vec())
}
fn empty() -> HashTreeNode {
    HashTreeNode::Empty()
}

fn lookup_path<P: AsRef<[&'static str]>>(tree: &HashTree, path: P) -> LookupResult {
    let path: Vec<Label> = path.as_ref().iter().map(|l| l.into()).collect();

    tree.lookup_path(path)
}

#[test]
fn works_with_simple_tree() {
    let tree = HashTree {
        root: fork(
            label("label 1", empty()),
            fork(
                pruned("0101010101010101010101010101010101010101010101010101010101010101"),
                leaf(&[1, 2, 3, 4, 5, 6]),
            ),
        ),
    };

    assert_eq!(
        hex::encode(tree.digest().to_vec()),
        "69cf325d0f20505b261821a7e77ff72fb9a8753a7964f0b587553bfb44e72532"
    );
}

#[test]
fn spec_example() {
    // This is the example straight from the spec.
    let tree = HashTree {
        root: fork(
            fork(
                label(
                    "a",
                    fork(
                        fork(label("x", leaf(b"hello")), empty()),
                        label("y", leaf(b"world")),
                    ),
                ),
                label("b", leaf(b"good")),
            ),
            fork(label("c", empty()), label("d", leaf(b"morning"))),
        ),
    };

    // Check CBOR serialization.
    assert_eq!(
        hex::encode(serde_cbor::to_vec(&tree).unwrap()),
        "8301830183024161830183018302417882034568656c6c6f810083024179820345776f726c6483024162820344676f6f648301830241638100830241648203476d6f726e696e67"
    );

    assert_eq!(
        hex::encode(tree.digest().to_vec()),
        "eb5c5b2195e62d996b84c9bcc8259d19a83786a2f59e0878cec84c811f669aa0"
    );
}

#[test]
fn spec_example_pruned() {
    // This is the example straight from the spec.
    let tree = HashTree {
        root: fork(
            fork(
                label(
                    "a",
                    fork(
                        pruned("1b4feff9bef8131788b0c9dc6dbad6e81e524249c879e9f10f71ce3749f5a638"),
                        label("y", leaf(b"world")),
                    ),
                ),
                label(
                    "b",
                    pruned("7b32ac0c6ba8ce35ac82c255fc7906f7fc130dab2a090f80fe12f9c2cae83ba6"),
                ),
            ),
            fork(
                pruned("ec8324b8a1f1ac16bd2e806edba78006479c9877fed4eb464a25485465af601d"),
                label("d", leaf(b"morning")),
            ),
        ),
    };

    assert_eq!(
        hex::encode(tree.digest().to_vec()),
        "eb5c5b2195e62d996b84c9bcc8259d19a83786a2f59e0878cec84c811f669aa0"
    );

    assert_eq!(lookup_path(&tree, ["a", "a"]), LookupResult::Unknown);
    assert_eq!(
        lookup_path(&tree, ["a", "y"]),
        LookupResult::Found(b"world")
    );
    assert_eq!(lookup_path(&tree, ["aa"]), LookupResult::Absent);
    assert_eq!(lookup_path(&tree, ["ax"]), LookupResult::Absent);
    assert_eq!(lookup_path(&tree, ["b"]), LookupResult::Unknown);
    assert_eq!(lookup_path(&tree, ["bb"]), LookupResult::Unknown);
    assert_eq!(lookup_path(&tree, ["d"]), LookupResult::Found(b"morning"));
    assert_eq!(lookup_path(&tree, ["e"]), LookupResult::Absent);

    // lookup_path(["a", "a"], pruned_tree) = Unknown
    // lookup_path(["a", "y"], pruned_tree) = Found "world"
    // lookup_path(["aa"],     pruned_tree) = Absent
    // lookup_path(["ax"],     pruned_tree) = Absent
    // lookup_path(["b"],      pruned_tree) = Unknown
    // lookup_path(["bb"],     pruned_tree) = Unknown
    // lookup_path(["d"],      pruned_tree) = Found "morning"
    // lookup_path(["e"],      pruned_tree) = Absent
}

#[test]
fn can_lookup_paths() {
    let tree = HashTree {
        root: HashTreeNode::Fork(Box::new((
            HashTreeNode::Labeled("label 1".into(), Box::new(HashTreeNode::Empty())),
            HashTreeNode::Fork(Box::new((
                HashTreeNode::Pruned([1; 32]),
                HashTreeNode::Fork(Box::new((
                    HashTreeNode::Labeled(
                        "label 2".into(),
                        Box::new(HashTreeNode::Leaf(vec![1, 2, 3, 4, 5, 6])),
                    ),
                    HashTreeNode::Labeled("label 3".into(), Box::new(HashTreeNode::Empty())),
                ))),
            ))),
        ))),
    };

    assert_eq!(
        tree.lookup_path(["label 2".into()]),
        LookupResult::Found(&[1, 2, 3, 4, 5, 6])
    )
}
