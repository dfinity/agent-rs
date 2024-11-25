use std::collections::HashMap;
use std::mem;
use std::sync::{Mutex, OnceLock};
use std::{fmt::Debug, hash::Hash, sync::Arc};

use ecdsa::signature::Signer;
use ic_certification::{empty, fork, label, leaf, Certificate, HashTree};
use indexmap::IndexMap;
use k256::ecdsa::{Signature, SigningKey};
use mockito::{Mock, Server, ServerOpts};
use rand::thread_rng;

use crate::agent::route_provider::RouteProvider;
use crate::agent::ApiBoundaryNode;
use crate::identity::Secp256k1Identity;
use crate::{Agent, Identity};

use super::dynamic_route_provider::MAINNET_ROOT_SUBNET_ID;

pub(super) fn route_n_times(n: usize, f: Arc<impl RouteProvider + ?Sized>) -> Vec<String> {
    (0..n)
        .map(|_| f.route().unwrap().domain().unwrap().to_string())
        .collect()
}

pub(super) fn assert_routed_domains<T>(
    actual: Vec<T>,
    expected: Vec<T>,
    expected_repetitions: usize,
) where
    T: AsRef<str> + Eq + Hash + Debug + Ord,
{
    fn build_count_map<T>(items: &[T]) -> HashMap<&T, usize>
    where
        T: Eq + Hash,
    {
        items.iter().fold(HashMap::new(), |mut map, item| {
            *map.entry(item).or_insert(0) += 1;
            map
        })
    }
    let count_actual = build_count_map(&actual);
    let count_expected = build_count_map(&expected);

    let mut keys_actual = count_actual.keys().collect::<Vec<_>>();
    keys_actual.sort();
    let mut keys_expected = count_expected.keys().collect::<Vec<_>>();
    keys_expected.sort();
    // Assert all routed domains are present.
    assert_eq!(keys_actual, keys_expected);

    // Assert the expected repetition count of each routed domain.
    let actual_repetitions = count_actual.values().collect::<Vec<_>>();
    assert!(actual_repetitions
        .iter()
        .all(|&x| x == &expected_repetitions));
}

pub fn mock_node(name: &str) -> ApiBoundaryNode {
    ApiBoundaryNode {
        domain: format!("{name}.localhost"),
        ipv4_address: Some("127.0.0.1".to_string()),
        ipv6_address: Some("::1".to_string()),
    }
}

static MOCK_SERVER: OnceLock<Mutex<Server>> = OnceLock::new();

fn get_server() -> &'static Mutex<Server> {
    MOCK_SERVER.get_or_init(|| {
        Mutex::new(Server::new_with_opts(ServerOpts {
            port: 7357,
            host: "::1",
            ..<_>::default()
        }))
    })
}

pub fn mock_topology(nodes: Vec<(ApiBoundaryNode, bool)>, root_domain: &str) -> MockTopology {
    let mut mocks = IndexMap::new();
    let root_key = SigningKey::random(&mut thread_rng());
    for (node, healthy) in nodes {
        let mock = node_mock(&node, healthy);
        mocks.insert(node, mock);
    }
    let root_node = mock_node(root_domain);
    let root_mock = root_node_mock(&mocks, root_domain, root_key.clone());
    let root_health_mock = get_server()
        .lock()
        .unwrap()
        .mock("GET", "/health")
        .match_header("host", root_domain)
        .with_status(204)
        .create();
    MockTopology {
        nodes: mocks,
        root_node,
        root_health_mock,
        root_mock,
    }
}

// pub fn default_test_key() -> SigningKey {
//     SigningKey::from_bytes(hex::decode("04 20 6B 9C A0 8A 33 7A 61 F1 E0 0B B2 6D F7 00 A2 01 4A 6D D1 0E FA D9 BB B0 24 7E D4 0D AD BE 58 EC").unwrap()[..].into()).unwrap()
// }

pub struct MockTopology {
    nodes: IndexMap<ApiBoundaryNode, NodeMock>,
    root_node: ApiBoundaryNode,
    root_mock: NodeMock,
    root_health_mock: Mock,
}

struct NodeMock {
    healthy: bool,
    mock: Mock,
    key: SigningKey,
}

impl MockTopology {
    pub fn agent(&self) -> Agent {
        Agent::builder()
            .with_url(self.root_node.to_routing_url())
            .with_preset_root_key(
                self.root_mock
                    .key
                    .verifying_key()
                    .to_sec1_bytes()
                    .into_vec(),
            )
            .build()
            .unwrap()
    }
    pub fn add_nodes(&mut self, nodes: impl IntoIterator<Item = (ApiBoundaryNode, bool)>) {
        for (node, healthy) in nodes {
            let node_mock = node_mock(&node, healthy);
            let old_mock = self.nodes.insert(node, node_mock);
            if let Some(old_mock) = old_mock {
                old_mock.mock.remove();
            }
        }
        self.update_root_mock();
    }
    pub fn remove_nodes<'a>(&mut self, nodes: impl IntoIterator<Item = &'a ApiBoundaryNode>) {
        for node in nodes {
            if let Some(mock) = self.nodes.swap_remove(node) {
                mock.mock.remove();
            }
        }
        self.update_root_mock();
    }
    pub fn set_node_health(&mut self, node: &ApiBoundaryNode, healthy: bool) {
        if let Some(mock) = self.nodes.get_mut(node) {
            mock.healthy = healthy;
            let old_mock = mem::replace(
                &mut mock.mock,
                get_server()
                    .lock()
                    .unwrap()
                    .mock("GET", "/health")
                    .match_header("host", &*node.domain)
                    .with_status(if healthy { 204 } else { 418 })
                    .create(),
            );
            old_mock.remove();
        }
    }
    pub fn update_root_mock(&mut self) {
        let root_key = self.root_mock.key.clone();
        let old_mock = mem::replace(
            &mut self.root_mock,
            root_node_mock(&self.nodes, &self.root_node.domain, root_key),
        );
        old_mock.mock.remove();
    }
}

fn node_mock(node: &ApiBoundaryNode, healthy: bool) -> NodeMock {
    let nk = SigningKey::random(&mut thread_rng());
    NodeMock {
        healthy,
        key: nk,
        mock: get_server()
            .lock()
            .unwrap()
            .mock("GET", "/health")
            .match_header("host", &*node.domain)
            .with_status(if healthy { 204 } else { 418 })
            .create(),
    }
}

fn root_node_mock<'a>(
    nodes: impl IntoIterator<Item = (&'a ApiBoundaryNode, &'a NodeMock)>,
    root_domain: &str,
    root_key: SigningKey,
) -> NodeMock {
    let mut tree = empty();
    for (node, mock) in nodes {
        let id = Secp256k1Identity::from_private_key(mock.key.clone().into());
        tree = fork(
            tree,
            label(
                id.sender().unwrap().to_text(),
                fork(
                    fork(
                        label("domain", leaf(&node.domain[..])),
                        node.ipv4_address
                            .as_deref()
                            .map_or_else(empty, |a| label("ipv4_address", leaf(&a[..]))),
                    ),
                    node.ipv6_address
                        .as_deref()
                        .map_or_else(empty, |a| label("ipv6_address", leaf(&a[..]))),
                ),
            ),
        );
    }
    let final_tree = label("api_boundary_nodes", tree);
    let signature: Signature = root_key.sign(&final_tree.digest());
    let certificate = Certificate {
        delegation: None,
        tree: final_tree,
        signature: signature.to_bytes().to_vec(),
    };
    let mock = get_server()
        .lock()
        .unwrap()
        .mock(
            "POST",
            &*format!("/api/v2/subnet/{}/read_state", MAINNET_ROOT_SUBNET_ID),
        )
        .match_header("host", &*format!("{root_domain}.localhost"))
        .with_body(serde_cbor::to_vec(&certificate).unwrap())
        .create();
    NodeMock {
        healthy: true,
        mock,
        key: root_key,
    }
}
