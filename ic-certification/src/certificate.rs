use crate::HashTree;

/// A `Certificate` as defined in <https://internetcomputer.org/docs/current/references/ic-interface-spec/#certificate>
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Certificate<'a> {
    /// The hash tree.
    pub tree: HashTree<'a>,

    /// The signature of the root hash in `tree`.
    #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))]
    pub signature: Vec<u8>,

    /// A delegation from the root key to the key used to sign `signature`, if one exists.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub delegation: Option<Delegation>,
}

/// A `Delegation` as defined in <https://internetcomputer.org/docs/current/references/ic-interface-spec/#certification-delegation>
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Delegation {
    #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))]
    pub subnet_id: Vec<u8>,

    #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))]
    pub certificate: Vec<u8>,
}

#[cfg(test)]
#[cfg(feature = "serde")]
mod tests {
    use super::*;
    use crate::hash_tree::{empty, fork, label, leaf};

    fn create_tree<'a>() -> HashTree<'a> {
        fork(
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
        )
    }

    #[test]
    fn serialize_to_cbor() {
        let tree = create_tree();
        let signature = vec![1, 2, 3, 4, 5, 6];

        let certificate = Certificate {
            tree,
            signature,
            delegation: None,
        };

        let cbor_bytes =
            serde_cbor::to_vec(&certificate).expect("Failed to encode certificate to cbor");
        let cbor_hex = hex::encode(cbor_bytes);

        assert_eq!(cbor_hex, "a264747265658301830183024161830183018302417882034568656c6c6f810083024179820345776f726c6483024162820344676f6f648301830241638100830241648203476d6f726e696e67697369676e617475726546010203040506");
    }

    #[test]
    fn serialize_to_cbor_with_delegation() {
        let tree = create_tree();
        let signature = vec![1, 2, 3, 4, 5, 6];
        let delegation = Delegation {
            subnet_id: vec![7, 8, 9, 10, 11, 12],
            certificate: vec![13, 14, 15, 16, 17, 18],
        };

        let certificate = Certificate {
            tree,
            signature,
            delegation: Some(delegation),
        };

        let cbor_bytes =
            serde_cbor::to_vec(&certificate).expect("Failed to encode certificate to cbor");
        let cbor_hex = hex::encode(cbor_bytes);

        assert_eq!(cbor_hex, "a364747265658301830183024161830183018302417882034568656c6c6f810083024179820345776f726c6483024162820344676f6f648301830241638100830241648203476d6f726e696e67697369676e6174757265460102030405066a64656c65676174696f6ea2697375626e65745f6964460708090a0b0c6b6365727469666963617465460d0e0f101112");
    }
}
