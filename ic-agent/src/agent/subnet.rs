//! Information about IC subnets.
//!
//! Fetch subnet information via [`Agent::fetch_subnet_by_id`](crate::Agent::fetch_subnet_by_id) or
//! [`Agent::get_subnet_by_canister`](crate::Agent::get_subnet_by_canister).

use std::{collections::HashMap, ops::RangeInclusive};

use candid::Principal;
use rangemap::RangeInclusiveSet;

use crate::agent::PrincipalStep;

/// Information about a subnet, including its public key, member nodes, and assigned canister ranges.
///
/// Range information may be incomplete depending on how the subnet was fetched. The lack of a canister ID
/// within assigned ranges should not be treated immediately as an authorization failure without fetching
/// fresh data with [`Agent::fetch_subnet_by_canister`](crate::Agent::fetch_subnet_by_canister).
#[derive(Clone)]
pub struct Subnet {
    pub(crate) id: Principal,
    // This key is just fetched for completeness. Do not actually use this value as it is not authoritative in case of a rogue subnet.
    // If a future agent needs to know the subnet key then it should fetch /subnet from the *root* subnet.
    pub(crate) key: Vec<u8>,
    pub(crate) node_keys: HashMap<Principal, Vec<u8>>,
    pub(crate) canister_ranges: RangeInclusiveSet<Principal, PrincipalStep>,
}

impl Subnet {
    /// Checks whether the given canister ID is contained within the subnet's assigned canister ranges.
    pub fn contains_canister(&self, canister_id: &Principal) -> bool {
        self.canister_ranges.contains(canister_id)
    }
    /// Returns an iterator over the known canister ID ranges assigned to this subnet.
    pub fn iter_canister_ranges(&self) -> CanisterRangesIter<'_> {
        CanisterRangesIter {
            inner: self.canister_ranges.iter(),
        }
    }
    /// Returns the self-reported public key of the subnet.
    ///
    /// Note that this key is not authoritative if the subnet is rogue.
    pub fn self_reported_key(&self) -> &[u8] {
        &self.key
    }
    /// Checks whether the given node ID is a member of this subnet.
    pub fn contains_node(&self, node_id: &Principal) -> bool {
        self.node_keys.contains_key(node_id)
    }
    /// Returns the public key of the given node ID, if it is a member of this subnet.
    pub fn get_node_key(&self, node_id: &Principal) -> Option<&[u8]> {
        self.node_keys.get(node_id).map(|k| &k[..])
    }
    /// Returns an iterator over the nodes in this subnet.
    pub fn iter_nodes(&self) -> SubnetNodeIter<'_> {
        SubnetNodeIter {
            inner: self.node_keys.keys(),
        }
    }
    /// Returns an iterator over the node IDs and their corresponding public keys in this subnet.
    pub fn iter_node_keys(&self) -> SubnetKeysIter<'_> {
        SubnetKeysIter {
            inner: self.node_keys.iter(),
        }
    }
    /// Returns the subnet's ID.
    pub fn id(&self) -> Principal {
        self.id
    }
}

/// Iterator over the canister ID ranges assigned to a subnet.
pub struct CanisterRangesIter<'a> {
    inner: rangemap::inclusive_set::Iter<'a, Principal>,
}

impl Iterator for CanisterRangesIter<'_> {
    type Item = RangeInclusive<Principal>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().cloned()
    }
}

/// Iterator over the node IDs in a subnet.
pub struct SubnetNodeIter<'a> {
    inner: std::collections::hash_map::Keys<'a, Principal, Vec<u8>>,
}

impl<'a> Iterator for SubnetNodeIter<'a> {
    type Item = Principal;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().copied()
    }
}

/// Iterator over the node IDs and their corresponding public keys in a subnet.
pub struct SubnetKeysIter<'a> {
    inner: std::collections::hash_map::Iter<'a, Principal, Vec<u8>>,
}

impl<'a> Iterator for SubnetKeysIter<'a> {
    type Item = (Principal, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(k, v)| (*k, &v[..]))
    }
}
