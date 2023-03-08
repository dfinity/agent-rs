#![cfg(test)]

use crate::hash_tree::{
    empty, fork, label, leaf, pruned, pruned_from_hex, HashTree, Label, LookupResult,
    SubtreeLookupResult,
};

fn lookup_path<'a, P: AsRef<[&'static str]>>(tree: &'a HashTree<'a>, path: P) -> LookupResult<'a> {
    let path: Vec<Label> = path.as_ref().iter().map(|l| l.into()).collect();

    tree.lookup_path(&path)
}

fn lookup_subtree<'a, P: AsRef<[&'static str]>>(
    tree: &'a HashTree<'a>,
    path: P,
) -> SubtreeLookupResult<'a> {
    let path: Vec<Label> = path.as_ref().iter().map(|l| l.into()).collect();

    tree.lookup_subtree(&path)
}

#[test]
fn works_with_simple_tree() {
    let tree = fork(
        label("label 1", empty()),
        fork(
            pruned(*b"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"),
            leaf([1u8, 2, 3, 4, 5, 6]),
        ),
    );

    assert_eq!(
        hex::encode(tree.digest()),
        "69cf325d0f20505b261821a7e77ff72fb9a8753a7964f0b587553bfb44e72532"
    );
}

#[test]
fn spec_example() {
    // This is the example straight from the spec.
    let tree = fork(
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
    );

    // Check CBOR serialization.
    #[cfg(feature = "serde")]
    assert_eq!(
        hex::encode(serde_cbor::to_vec(&tree).unwrap()),
        "8301830183024161830183018302417882034568656c6c6f810083024179820345776f726c6483024162820344676f6f648301830241638100830241648203476d6f726e696e67"
    );

    assert_eq!(
        hex::encode(tree.digest()),
        "eb5c5b2195e62d996b84c9bcc8259d19a83786a2f59e0878cec84c811f669aa0"
    );
}

#[test]
fn spec_example_pruned() {
    // This is the example straight from the spec.
    let tree = fork(
        fork(
            label(
                "a",
                fork(
                    pruned_from_hex(
                        "1b4feff9bef8131788b0c9dc6dbad6e81e524249c879e9f10f71ce3749f5a638",
                    )
                    .unwrap(),
                    label("y", leaf(b"world")),
                ),
            ),
            label(
                "b",
                pruned_from_hex("7b32ac0c6ba8ce35ac82c255fc7906f7fc130dab2a090f80fe12f9c2cae83ba6")
                    .unwrap(),
            ),
        ),
        fork(
            pruned_from_hex("ec8324b8a1f1ac16bd2e806edba78006479c9877fed4eb464a25485465af601d")
                .unwrap(),
            label("d", leaf(b"morning")),
        ),
    );

    assert_eq!(
        hex::encode(tree.digest()),
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
}

#[test]
fn can_lookup_paths_1() {
    let tree = fork(
        label("label 1", empty()),
        fork(
            pruned([1; 32]),
            fork(
                label("label 3", leaf(vec![1, 2, 3, 4, 5, 6])),
                label("label 5", empty()),
            ),
        ),
    );

    assert_eq!(tree.lookup_path(&["label 0".into()]), LookupResult::Absent);
    assert_eq!(tree.lookup_path(&["label 1".into()]), LookupResult::Absent);
    assert_eq!(tree.lookup_path(&["label 2".into()]), LookupResult::Unknown);
    assert_eq!(
        tree.lookup_path(&["label 3".into()]),
        LookupResult::Found(&[1, 2, 3, 4, 5, 6])
    );
    assert_eq!(tree.lookup_path(&["label 4".into()]), LookupResult::Absent);
    assert_eq!(tree.lookup_path(&["label 5".into()]), LookupResult::Absent);
    assert_eq!(tree.lookup_path(&["label 6".into()]), LookupResult::Absent);
}

#[test]
fn can_lookup_paths_2() {
    let tree = fork(
        label("label 1", empty()),
        fork(
            fork(
                label("label 3", leaf(vec![1, 2, 3, 4, 5, 6])),
                label("label 5", empty()),
            ),
            pruned([1; 32]),
        ),
    );

    assert_eq!(tree.lookup_path(&["label 0".into()]), LookupResult::Absent);
    assert_eq!(tree.lookup_path(&["label 1".into()]), LookupResult::Absent);
    assert_eq!(tree.lookup_path(&["label 2".into()]), LookupResult::Absent);
    assert_eq!(
        tree.lookup_path(&["label 3".into()]),
        LookupResult::Found(&[1, 2, 3, 4, 5, 6])
    );
    assert_eq!(tree.lookup_path(&["label 4".into()]), LookupResult::Absent);
    assert_eq!(tree.lookup_path(&["label 5".into()]), LookupResult::Absent);
    assert_eq!(tree.lookup_path(&["label 6".into()]), LookupResult::Unknown);
}

#[test]
fn can_lookup_paths_3() {
    let tree = fork(
        pruned([0; 32]),
        fork(
            pruned([1; 32]),
            fork(
                label("label 3", leaf(vec![1, 2, 3, 4, 5, 6])),
                label("label 5", empty()),
            ),
        ),
    );

    assert_eq!(tree.lookup_path(&["label 2".into()]), LookupResult::Unknown);
    assert_eq!(
        tree.lookup_path(&["label 3".into()]),
        LookupResult::Found(&[1, 2, 3, 4, 5, 6])
    );
    assert_eq!(tree.lookup_path(&["label 4".into()]), LookupResult::Absent);
    assert_eq!(tree.lookup_path(&["label 5".into()]), LookupResult::Absent);
    assert_eq!(tree.lookup_path(&["label 6".into()]), LookupResult::Absent);
}

#[test]
fn can_lookup_paths_4() {
    let tree = fork(
        pruned([0; 32]),
        fork(
            fork(
                label("label 3", leaf(vec![1, 2, 3, 4, 5, 6])),
                label("label 5", empty()),
            ),
            pruned([1; 32]),
        ),
    );

    assert_eq!(tree.lookup_path(&["label 2".into()]), LookupResult::Unknown);
    assert_eq!(
        tree.lookup_path(&["label 3".into()]),
        LookupResult::Found(&[1, 2, 3, 4, 5, 6])
    );
    assert_eq!(tree.lookup_path(&["label 4".into()]), LookupResult::Absent);
    assert_eq!(tree.lookup_path(&["label 5".into()]), LookupResult::Absent);
    assert_eq!(tree.lookup_path(&["label 6".into()]), LookupResult::Unknown);
}

#[test]
fn can_lookup_paths_5() {
    let tree = fork(
        fork(
            pruned([1; 32]),
            fork(
                label("label 3", leaf(vec![1, 2, 3, 4, 5, 6])),
                label("label 5", empty()),
            ),
        ),
        label("label 7", empty()),
    );

    assert_eq!(tree.lookup_path(&["label 2".into()]), LookupResult::Unknown);
    assert_eq!(
        tree.lookup_path(&["label 3".into()]),
        LookupResult::Found(&[1, 2, 3, 4, 5, 6])
    );
    assert_eq!(tree.lookup_path(&["label 4".into()]), LookupResult::Absent);
    assert_eq!(tree.lookup_path(&["label 5".into()]), LookupResult::Absent);
    assert_eq!(tree.lookup_path(&["label 6".into()]), LookupResult::Absent);
    assert_eq!(tree.lookup_path(&["label 7".into()]), LookupResult::Absent);
    assert_eq!(tree.lookup_path(&["label 8".into()]), LookupResult::Absent);
}

#[test]
fn can_lookup_paths_6() {
    let tree = fork(
        fork(
            fork(
                label("label 3", leaf(vec![1, 2, 3, 4, 5, 6])),
                label("label 5", empty()),
            ),
            pruned([1; 32]),
        ),
        label("label 7", empty()),
    );

    assert_eq!(tree.lookup_path(&["label 2".into()]), LookupResult::Absent);
    assert_eq!(
        tree.lookup_path(&["label 3".into()]),
        LookupResult::Found(&[1, 2, 3, 4, 5, 6])
    );
    assert_eq!(tree.lookup_path(&["label 4".into()]), LookupResult::Absent);
    assert_eq!(tree.lookup_path(&["label 5".into()]), LookupResult::Absent);
    assert_eq!(tree.lookup_path(&["label 6".into()]), LookupResult::Unknown);
    assert_eq!(tree.lookup_path(&["label 7".into()]), LookupResult::Absent);
    assert_eq!(tree.lookup_path(&["label 8".into()]), LookupResult::Absent);
}

#[test]
fn can_lookup_paths_7() {
    let tree = fork(
        fork(
            pruned([1; 32]),
            fork(
                label("label 3", leaf(vec![1, 2, 3, 4, 5, 6])),
                label("label 5", empty()),
            ),
        ),
        pruned([0; 32]),
    );

    assert_eq!(tree.lookup_path(&["label 2".into()]), LookupResult::Unknown);
    assert_eq!(
        tree.lookup_path(&["label 3".into()]),
        LookupResult::Found(&[1, 2, 3, 4, 5, 6])
    );
    assert_eq!(tree.lookup_path(&["label 4".into()]), LookupResult::Absent);
    assert_eq!(tree.lookup_path(&["label 5".into()]), LookupResult::Absent);
    assert_eq!(tree.lookup_path(&["label 6".into()]), LookupResult::Unknown);
}

#[test]
fn can_lookup_paths_8() {
    let tree = fork(
        fork(
            fork(
                label("label 3", leaf(vec![1, 2, 3, 4, 5, 6])),
                label("label 5", empty()),
            ),
            pruned([1; 32]),
        ),
        pruned([0; 32]),
    );

    assert_eq!(tree.lookup_path(&["label 2".into()]), LookupResult::Absent);
    assert_eq!(
        tree.lookup_path(&["label 3".into()]),
        LookupResult::Found(&[1, 2, 3, 4, 5, 6])
    );
    assert_eq!(tree.lookup_path(&["label 4".into()]), LookupResult::Absent);
    assert_eq!(tree.lookup_path(&["label 5".into()]), LookupResult::Absent);
    assert_eq!(tree.lookup_path(&["label 6".into()]), LookupResult::Unknown);
}

#[test]
fn can_lookup_subtrees_1() {
    use SubtreeLookupResult::*;

    let tree = fork(
        label("label 1", empty()),
        fork(
            pruned([1; 32]),
            fork(
                label("label 3", leaf(vec![1, 2, 3, 4, 5, 6])),
                label("label 5", empty()),
            ),
        ),
    );

    assert_eq!(lookup_subtree(&tree, ["label 0"]), Absent);
    assert_eq!(lookup_subtree(&tree, ["label 1"]), Found(empty()));
    assert_eq!(lookup_subtree(&tree, ["label 2"]), Unknown);
    assert_eq!(
        lookup_subtree(&tree, ["label 3"]),
        Found(leaf(vec![1, 2, 3, 4, 5, 6]))
    );
    assert_eq!(lookup_subtree(&tree, ["label 4"]), Absent);
    assert_eq!(lookup_subtree(&tree, ["label 5"]), Found(empty()));
    assert_eq!(lookup_subtree(&tree, ["label 6"]), Absent);
}

#[test]
fn can_lookup_subtrees_2() {
    use SubtreeLookupResult::*;

    let tree = fork(
        label("label 1", empty()),
        fork(
            fork(
                label("label 3", leaf(vec![1, 2, 3, 4, 5, 6])),
                label("label 5", empty()),
            ),
            pruned([1; 32]),
        ),
    );

    assert_eq!(lookup_subtree(&tree, ["label 0"]), Absent);
    assert_eq!(lookup_subtree(&tree, ["label 1"]), Found(empty()));
    assert_eq!(lookup_subtree(&tree, ["label 2"]), Absent);
    assert_eq!(
        lookup_subtree(&tree, ["label 3"]),
        Found(leaf(vec![1, 2, 3, 4, 5, 6]))
    );
    assert_eq!(lookup_subtree(&tree, ["label 4"]), Absent);
    assert_eq!(lookup_subtree(&tree, ["label 5"]), Found(empty()));
    assert_eq!(lookup_subtree(&tree, ["label 6"]), Unknown);
}

#[test]
fn can_lookup_subtrees_3() {
    use SubtreeLookupResult::*;

    let tree = fork(
        pruned([0; 32]),
        fork(
            pruned([1; 32]),
            fork(
                label("label 3", leaf(vec![1, 2, 3, 4, 5, 6])),
                label("label 5", empty()),
            ),
        ),
    );

    assert_eq!(lookup_subtree(&tree, ["label 2"]), Unknown);
    assert_eq!(
        lookup_subtree(&tree, ["label 3"]),
        Found(leaf(vec![1, 2, 3, 4, 5, 6]))
    );
    assert_eq!(lookup_subtree(&tree, ["label 4"]), Absent);
    assert_eq!(lookup_subtree(&tree, ["label 5"]), Found(empty()));
    assert_eq!(lookup_subtree(&tree, ["label 6"]), Absent);
}

#[test]
fn can_lookup_subtrees_4() {
    use SubtreeLookupResult::*;

    let tree = fork(
        pruned([0; 32]),
        fork(
            fork(
                label("label 3", leaf(vec![1, 2, 3, 4, 5, 6])),
                label("label 5", empty()),
            ),
            pruned([1; 32]),
        ),
    );

    assert_eq!(lookup_subtree(&tree, ["label 2"]), Unknown);
    assert_eq!(
        lookup_subtree(&tree, ["label 3"]),
        Found(leaf(vec![1, 2, 3, 4, 5, 6]))
    );
    assert_eq!(lookup_subtree(&tree, ["label 4"]), Absent);
    assert_eq!(lookup_subtree(&tree, ["label 5"]), Found(empty()));
    assert_eq!(lookup_subtree(&tree, ["label 6"]), Unknown);
}

#[test]
fn can_lookup_subtrees_5() {
    use SubtreeLookupResult::*;

    let tree = fork(
        fork(
            pruned([1; 32]),
            fork(
                label("label 3", leaf(vec![1, 2, 3, 4, 5, 6])),
                label("label 5", empty()),
            ),
        ),
        label("label 7", empty()),
    );

    assert_eq!(lookup_subtree(&tree, ["label 2"]), Unknown);
    assert_eq!(
        lookup_subtree(&tree, ["label 3"]),
        Found(leaf(vec![1, 2, 3, 4, 5, 6]))
    );
    assert_eq!(lookup_subtree(&tree, ["label 4"]), Absent);
    assert_eq!(lookup_subtree(&tree, ["label 5"]), Found(empty()));
    assert_eq!(lookup_subtree(&tree, ["label 6"]), Absent);
    assert_eq!(lookup_subtree(&tree, ["label 7"]), Found(empty()));
    assert_eq!(lookup_subtree(&tree, ["label 8"]), Absent);
}

#[test]
fn can_lookup_subtrees_6() {
    use SubtreeLookupResult::*;

    let tree = fork(
        fork(
            fork(
                label("label 3", leaf(vec![1, 2, 3, 4, 5, 6])),
                label("label 5", empty()),
            ),
            pruned([1; 32]),
        ),
        label("label 7", empty()),
    );

    assert_eq!(lookup_subtree(&tree, ["label 2"]), Absent);
    assert_eq!(
        lookup_subtree(&tree, ["label 3"]),
        Found(leaf(vec![1, 2, 3, 4, 5, 6]))
    );
    assert_eq!(lookup_subtree(&tree, ["label 4"]), Absent);
    assert_eq!(lookup_subtree(&tree, ["label 5"]), Found(empty()));
    assert_eq!(lookup_subtree(&tree, ["label 6"]), Unknown);
    assert_eq!(lookup_subtree(&tree, ["label 7"]), Found(empty()));
    assert_eq!(lookup_subtree(&tree, ["label 8"]), Absent);
}

#[test]
fn can_lookup_subtrees_7() {
    use SubtreeLookupResult::*;

    let tree = fork(
        fork(
            pruned([1; 32]),
            fork(
                label("label 3", leaf(vec![1, 2, 3, 4, 5, 6])),
                label("label 5", empty()),
            ),
        ),
        pruned([0; 32]),
    );

    assert_eq!(lookup_subtree(&tree, ["label 2"]), Unknown);
    assert_eq!(
        lookup_subtree(&tree, ["label 3"]),
        Found(leaf(vec![1, 2, 3, 4, 5, 6]))
    );
    assert_eq!(lookup_subtree(&tree, ["label 4"]), Absent);
    assert_eq!(lookup_subtree(&tree, ["label 5"]), Found(empty()));
    assert_eq!(lookup_subtree(&tree, ["label 6"]), Unknown);
}

#[test]
fn can_lookup_subtrees_8() {
    use SubtreeLookupResult::*;

    let tree = fork(
        fork(
            fork(
                label("label 3", leaf(vec![1, 2, 3, 4, 5, 6])),
                label("label 5", empty()),
            ),
            pruned([1; 32]),
        ),
        pruned([0; 32]),
    );

    assert_eq!(lookup_subtree(&tree, ["label 2"]), Absent);
    assert_eq!(
        lookup_subtree(&tree, ["label 3"]),
        Found(leaf(vec![1, 2, 3, 4, 5, 6]))
    );
    assert_eq!(lookup_subtree(&tree, ["label 4"]), Absent);
    assert_eq!(lookup_subtree(&tree, ["label 5"]), Found(empty()));
    assert_eq!(lookup_subtree(&tree, ["label 6"]), Unknown);
}
