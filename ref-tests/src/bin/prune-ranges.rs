use ic_certification::{Certificate, Delegation, HashTreeNode};
use serde::{Deserialize, Serialize};
use serde_cbor::Serializer;

fn main() {
    let repo_dir = std::fs::canonicalize(format!("{}/..", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let response = std::fs::read(
        repo_dir.join("ic-agent/src/agent/agent_test/req_with_delegated_cert_response.bin"),
    )
    .unwrap();
    let response: Response = serde_cbor::from_slice(&response).unwrap();
    let cert: Certificate = serde_cbor::from_slice(&response.certificate).unwrap();
    let delegation = cert.delegation.clone().unwrap();
    let delegation_cert: Certificate = serde_cbor::from_slice(&delegation.certificate).unwrap();
    let mut pruned_delegation_tree = delegation_cert.tree.clone().into();
    prune_ranges(&mut pruned_delegation_tree);
    assert_eq!(
        pruned_delegation_tree.digest(),
        delegation_cert.tree.digest()
    );
    let pruned_delegation_cert = PrunedDelegationCert {
        tree: pruned_delegation_tree,
        signature: delegation_cert.signature,
    };
    let pruned_delegation_cert = tagged_serialize(&pruned_delegation_cert);
    let pruned_cert = Certificate {
        delegation: Some(Delegation {
            certificate: pruned_delegation_cert,
            ..delegation
        }),
        ..cert
    };
    let pruned_cert = tagged_serialize(&pruned_cert);
    let pruned_response = Response {
        certificate: pruned_cert,
    };
    let pruned_response = tagged_serialize(&pruned_response);
    std::fs::write(
        repo_dir.join("ic-agent/src/agent/agent_test/pruned_ranges.bin"),
        pruned_response,
    )
    .unwrap();
}

#[derive(Serialize, Deserialize)]
struct Response {
    #[serde(with = "serde_bytes")]
    certificate: Vec<u8>,
}

// annoyingly you cannot convert HashTreeNode directly to HashTree
#[derive(Serialize, Deserialize)]
struct PrunedDelegationCert {
    tree: HashTreeNode,
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
}

fn tagged_serialize<T: Serialize>(value: &T) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut serializer = Serializer::new(&mut buf);
    serializer.self_describe().unwrap();
    value.serialize(&mut serializer).unwrap();
    buf
}

fn prune_ranges(tree: &mut HashTreeNode) {
    match tree {
        HashTreeNode::Fork(lr) => {
            let (left, right) = lr.as_mut();
            prune_ranges(left);
            prune_ranges(right);
        }
        HashTreeNode::Labeled(label, subtree) => {
            if label.as_bytes() == b"canister_ranges" {
                *tree = HashTreeNode::Pruned(tree.digest());
            } else {
                prune_ranges(subtree);
            }
        }
        _ => {}
    }
}
