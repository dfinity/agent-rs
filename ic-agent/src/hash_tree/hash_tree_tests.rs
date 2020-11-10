#![cfg(test)]
use crate::hash_tree::{HashTree, HashTreeNode, LookupResult};

macro_rules! node {
    label $lbl: literal; $rest: tt => {
        HashTreeNode::Labeled($lbl.into(), node!($rest))
    };
    ( fork ($left: tt, $right: tt) ) => {
        HashTreeNode::Fork(Box::new(node!($left), node!($right)))
    };
    ( pruned ( $hash: tt ) ) => {
        HashTreeNode::Pruned($hash.into())
    };
    ( leaf $value: tt ) => {
        HashTreeNode::Leaf($value.into())
    };
    ( empty ) => {
        HashTreeNode::Empty()
    };
}

macro_rules! tree {
    ( $ex: tt ) => {
        HashTree {
            root: node! { $ex },
        }
    };
}

#[test]
fn works_with_example_from_spec() {
    let tree = tree!(
        fork(label "label 1" empty, fork ( pruned ( [1; 32] ), leaf ( vec![1,2,3,4,5,6] ) ) )
    );

    assert_eq!(
        hex::encode(tree.digest().to_vec()),
        "e40b2079db3811926c5325bf28b6cfe9682eed13d1a9479338accf60bbb0607f"
    );
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
