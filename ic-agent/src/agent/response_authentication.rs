use crate::agent::{ApiBoundaryNode, RejectCode, RejectResponse, RequestStatusResponse};
use crate::{export::Principal, AgentError, RequestId};
use ic_certification::hash_tree::{HashTree, SubtreeLookupResult};
use ic_certification::{certificate::Certificate, hash_tree::Label, LookupResult};
use ic_transport_types::{ReplyResponse, SubnetMetrics};
use rangemap::RangeInclusiveSet;
use std::collections::{HashMap, HashSet};
use std::str::from_utf8;

use super::Subnet;

const DER_PREFIX: &[u8; 37] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00";
const KEY_LENGTH: usize = 96;

pub fn extract_der(buf: Vec<u8>) -> Result<Vec<u8>, AgentError> {
    let expected_length = DER_PREFIX.len() + KEY_LENGTH;
    if buf.len() != expected_length {
        return Err(AgentError::DerKeyLengthMismatch {
            expected: expected_length,
            actual: buf.len(),
        });
    }

    let prefix = &buf[0..DER_PREFIX.len()];
    if prefix[..] != DER_PREFIX[..] {
        return Err(AgentError::DerPrefixMismatch {
            expected: DER_PREFIX.to_vec(),
            actual: prefix.to_vec(),
        });
    }

    let key = &buf[DER_PREFIX.len()..];
    Ok(key.to_vec())
}

pub(crate) fn lookup_canister_info<Storage: AsRef<[u8]>>(
    certificate: Certificate<Storage>,
    canister_id: Principal,
    path: &str,
) -> Result<Vec<u8>, AgentError> {
    let path_canister = [
        "canister".as_bytes(),
        canister_id.as_slice(),
        path.as_bytes(),
    ];
    lookup_value(&certificate.tree, path_canister).map(<[u8]>::to_vec)
}

pub(crate) fn lookup_canister_metadata<Storage: AsRef<[u8]>>(
    certificate: Certificate<Storage>,
    canister_id: Principal,
    path: &str,
) -> Result<Vec<u8>, AgentError> {
    let path_canister = [
        "canister".as_bytes(),
        canister_id.as_slice(),
        "metadata".as_bytes(),
        path.as_bytes(),
    ];

    lookup_value(&certificate.tree, path_canister).map(<[u8]>::to_vec)
}

pub(crate) fn lookup_subnet_metrics<Storage: AsRef<[u8]>>(
    certificate: Certificate<Storage>,
    subnet_id: Principal,
) -> Result<SubnetMetrics, AgentError> {
    let path_stats = [b"subnet", subnet_id.as_slice(), b"metrics"];
    let metrics = lookup_value(&certificate.tree, path_stats)?;
    Ok(serde_cbor::from_slice(metrics)?)
}

pub(crate) fn lookup_request_status<Storage: AsRef<[u8]>>(
    certificate: Certificate<Storage>,
    request_id: &RequestId,
) -> Result<RequestStatusResponse, AgentError> {
    use AgentError::*;
    let path_status = [
        "request_status".into(),
        request_id.to_vec().into(),
        "status".into(),
    ];
    match certificate.tree.lookup_path(&path_status) {
        LookupResult::Absent => Ok(RequestStatusResponse::Unknown),
        LookupResult::Unknown => Err(LookupPathUnknown(path_status.to_vec())),
        LookupResult::Found(status) => match from_utf8(status)? {
            "done" => Ok(RequestStatusResponse::Done),
            "processing" => Ok(RequestStatusResponse::Processing),
            "received" => Ok(RequestStatusResponse::Received),
            "rejected" => lookup_rejection(&certificate, request_id),
            "replied" => lookup_reply(&certificate, request_id),
            other => Err(InvalidRequestStatus(path_status.into(), other.to_string())),
        },
        LookupResult::Error => Err(LookupPathError(path_status.into())),
    }
}

pub(crate) fn lookup_rejection<Storage: AsRef<[u8]>>(
    certificate: &Certificate<Storage>,
    request_id: &RequestId,
) -> Result<RequestStatusResponse, AgentError> {
    let reject_code = lookup_reject_code(certificate, request_id)?;
    let reject_message = lookup_reject_message(certificate, request_id)?;

    Ok(RequestStatusResponse::Rejected(RejectResponse {
        reject_code,
        reject_message,
        error_code: None,
    }))
}

pub(crate) fn lookup_reject_code<Storage: AsRef<[u8]>>(
    certificate: &Certificate<Storage>,
    request_id: &RequestId,
) -> Result<RejectCode, AgentError> {
    let path = [
        "request_status".as_bytes(),
        request_id.as_slice(),
        "reject_code".as_bytes(),
    ];
    let code = lookup_value(&certificate.tree, path)?;
    let mut readable = code;
    let code_digit = leb128::read::unsigned(&mut readable)?;
    Ok(RejectCode::try_from(code_digit)?)
}

pub(crate) fn lookup_reject_message<Storage: AsRef<[u8]>>(
    certificate: &Certificate<Storage>,
    request_id: &RequestId,
) -> Result<String, AgentError> {
    let path = [
        "request_status".as_bytes(),
        request_id.as_slice(),
        "reject_message".as_bytes(),
    ];
    let msg = lookup_value(&certificate.tree, path)?;
    Ok(from_utf8(msg)?.to_string())
}

pub(crate) fn lookup_reply<Storage: AsRef<[u8]>>(
    certificate: &Certificate<Storage>,
    request_id: &RequestId,
) -> Result<RequestStatusResponse, AgentError> {
    let path = [
        "request_status".as_bytes(),
        request_id.as_slice(),
        "reply".as_bytes(),
    ];
    let reply_data = lookup_value(&certificate.tree, path)?;
    let arg = Vec::from(reply_data);
    Ok(RequestStatusResponse::Replied(ReplyResponse { arg }))
}

pub(crate) fn lookup_subnet<Storage: AsRef<[u8]> + Clone>(
    certificate: &Certificate<Storage>,
    root_key: &[u8],
) -> Result<(Principal, Subnet), AgentError> {
    let subnet_id = if let Some(delegation) = &certificate.delegation {
        Principal::from_slice(delegation.subnet_id.as_ref())
    } else {
        Principal::self_authenticating(root_key)
    };
    let subnet_tree = lookup_tree(&certificate.tree, [b"subnet", subnet_id.as_slice()])?;
    let key = lookup_value(&subnet_tree, [b"public_key".as_ref()])?.to_vec();
    let canister_ranges: Vec<(Principal, Principal)> =
        if let Some(delegation) = &certificate.delegation {
            let delegation: Certificate<Vec<u8>> =
                serde_cbor::from_slice(delegation.certificate.as_ref())?;
            serde_cbor::from_slice(lookup_value(
                &delegation.tree,
                [b"subnet", subnet_id.as_slice(), b"canister_ranges"],
            )?)?
        } else {
            serde_cbor::from_slice(lookup_value(&subnet_tree, [b"canister_ranges".as_ref()])?)?
        };
    let node_keys_subtree = lookup_tree(&subnet_tree, [b"node".as_ref()])?;
    let mut node_keys = HashMap::new();
    for path in node_keys_subtree.list_paths() {
        if path.len() < 2 {
            // if it's absent, it's because this is the wrong subnet
            return Err(AgentError::CertificateNotAuthorized());
        }
        if path[1].as_bytes() != b"public_key" {
            continue;
        }
        if path.len() > 2 {
            return Err(AgentError::LookupPathError(
                path.into_iter()
                    .map(|label| label.as_bytes().to_vec().into())
                    .collect(),
            ));
        }
        let node_id = Principal::from_slice(path[0].as_bytes());
        let node_key = lookup_value(&node_keys_subtree, [node_id.as_slice(), b"public_key"])?;
        node_keys.insert(node_id, node_key.to_vec());
    }
    let mut range_set = RangeInclusiveSet::new_with_step_fns();
    for (low, high) in canister_ranges {
        range_set.insert(low..=high);
    }
    let subnet = Subnet {
        canister_ranges: range_set,
        _key: key,
        node_keys,
    };
    Ok((subnet_id, subnet))
}

pub(crate) fn lookup_api_boundary_nodes<Storage: AsRef<[u8]> + Clone>(
    certificate: Certificate<Storage>,
) -> Result<Vec<ApiBoundaryNode>, AgentError> {
    // API Boundary Node paths in the State Tree, as defined in the spec (https://github.com/dfinity/interface-spec/pull/248 to be merged soon).
    let api_bn_path = "api_boundary_nodes".as_bytes();
    let domain_path = "domain".as_bytes();
    let ipv4_path = "ipv4_address".as_bytes();
    let ipv6_path = "ipv6_address".as_bytes();

    let api_bn_tree = lookup_tree(&certificate.tree, [api_bn_path])?;

    let mut api_bns = Vec::<ApiBoundaryNode>::new();
    let paths = api_bn_tree.list_paths();
    let node_ids: HashSet<&[u8]> = paths.iter().map(|path| path[0].as_bytes()).collect();

    for node_id in node_ids {
        let domain =
            String::from_utf8(lookup_value(&api_bn_tree, [node_id, domain_path])?.to_vec())
                .map_err(|err| AgentError::Utf8ReadError(err.utf8_error()))?;

        let ipv6_address =
            String::from_utf8(lookup_value(&api_bn_tree, [node_id, ipv6_path])?.to_vec())
                .map_err(|err| AgentError::Utf8ReadError(err.utf8_error()))?;

        let ipv4_address = match lookup_value(&api_bn_tree, [node_id, ipv4_path]) {
            Ok(ipv4) => Some(
                String::from_utf8(ipv4.to_vec())
                    .map_err(|err| AgentError::Utf8ReadError(err.utf8_error()))?,
            ),
            // By convention an absent path `/api_boundary_nodes/<node_id>/ipv4_address` in the State Tree signifies that ipv4 is None.
            Err(AgentError::LookupPathAbsent(_)) => None,
            Err(err) => return Err(err),
        };

        let api_bn = ApiBoundaryNode {
            domain,
            ipv6_address,
            ipv4_address,
        };

        api_bns.push(api_bn);
    }
    Ok(api_bns)
}

/// The path to [`lookup_value`]
pub trait LookupPath {
    type Item: AsRef<[u8]>;
    type Iter<'a>: Iterator<Item = &'a Self::Item>
    where
        Self: 'a;
    fn iter(&self) -> Self::Iter<'_>;
    fn into_vec(self) -> Vec<Label<Vec<u8>>>;
}

impl<'b, const N: usize> LookupPath for [&'b [u8]; N] {
    type Item = &'b [u8];
    type Iter<'a> = std::slice::Iter<'a, &'b [u8]> where Self: 'a;
    fn iter(&self) -> Self::Iter<'_> {
        self.as_slice().iter()
    }
    fn into_vec(self) -> Vec<Label<Vec<u8>>> {
        self.map(Label::from_bytes).into()
    }
}
impl<'b, 'c> LookupPath for &'c [&'b [u8]] {
    type Item = &'b [u8];
    type Iter<'a> = std::slice::Iter<'a, &'b [u8]> where Self: 'a;
    fn iter(&self) -> Self::Iter<'_> {
        <[_]>::iter(self)
    }
    fn into_vec(self) -> Vec<Label<Vec<u8>>> {
        self.iter().map(|v| Label::from_bytes(v)).collect()
    }
}
impl<'b> LookupPath for Vec<&'b [u8]> {
    type Item = &'b [u8];
    type Iter<'a> = std::slice::Iter<'a, &'b [u8]> where Self: 'a;
    fn iter(&self) -> Self::Iter<'_> {
        <[_]>::iter(self.as_slice())
    }
    fn into_vec(self) -> Vec<Label<Vec<u8>>> {
        self.into_iter().map(Label::from_bytes).collect()
    }
}

impl<const N: usize> LookupPath for [Vec<u8>; N] {
    type Item = Vec<u8>;
    type Iter<'a> = std::slice::Iter<'a, Vec<u8>> where Self: 'a;
    fn iter(&self) -> Self::Iter<'_> {
        self.as_slice().iter()
    }
    fn into_vec(self) -> Vec<Label<Vec<u8>>> {
        self.map(Label::from).into()
    }
}
impl<'c> LookupPath for &'c [Vec<u8>] {
    type Item = Vec<u8>;
    type Iter<'a> = std::slice::Iter<'a, Vec<u8>> where Self: 'a;
    fn iter(&self) -> Self::Iter<'_> {
        <[_]>::iter(self)
    }
    fn into_vec(self) -> Vec<Label<Vec<u8>>> {
        self.iter().map(|v| Label::from(v.clone())).collect()
    }
}
impl LookupPath for Vec<Vec<u8>> {
    type Item = Vec<u8>;
    type Iter<'a> = std::slice::Iter<'a, Vec<u8>> where Self: 'a;
    fn iter(&self) -> Self::Iter<'_> {
        <[_]>::iter(self.as_slice())
    }
    fn into_vec(self) -> Vec<Label<Vec<u8>>> {
        self.into_iter().map(Label::from).collect()
    }
}

impl<Storage: AsRef<[u8]> + Into<Vec<u8>>, const N: usize> LookupPath for [Label<Storage>; N] {
    type Item = Label<Storage>;
    type Iter<'a> = std::slice::Iter<'a, Label<Storage>> where Self: 'a;
    fn iter(&self) -> Self::Iter<'_> {
        self.as_slice().iter()
    }
    fn into_vec(self) -> Vec<Label<Vec<u8>>> {
        self.map(Label::from_label).into()
    }
}
impl<'c, Storage: AsRef<[u8]> + Into<Vec<u8>>> LookupPath for &'c [Label<Storage>] {
    type Item = Label<Storage>;
    type Iter<'a> = std::slice::Iter<'a, Label<Storage>> where Self: 'a;
    fn iter(&self) -> Self::Iter<'_> {
        <[_]>::iter(self)
    }
    fn into_vec(self) -> Vec<Label<Vec<u8>>> {
        self.iter()
            .map(|v| Label::from_bytes(v.as_bytes()))
            .collect()
    }
}
impl LookupPath for Vec<Label<Vec<u8>>> {
    type Item = Label<Vec<u8>>;
    type Iter<'a> = std::slice::Iter<'a, Label<Vec<u8>>> where Self: 'a;
    fn iter(&self) -> Self::Iter<'_> {
        <[_]>::iter(self.as_slice())
    }
    fn into_vec(self) -> Vec<Label<Vec<u8>>> {
        self
    }
}

/// Looks up a value in the certificate's tree at the specified hash.
///
/// Returns the value if it was found; otherwise, errors with `LookupPathAbsent`, `LookupPathUnknown`, or `LookupPathError`.
pub fn lookup_value<P: LookupPath, Storage: AsRef<[u8]>>(
    tree: &HashTree<Storage>,
    path: P,
) -> Result<&[u8], AgentError> {
    use AgentError::*;
    match tree.lookup_path(path.iter()) {
        LookupResult::Absent => Err(LookupPathAbsent(path.into_vec())),
        LookupResult::Unknown => Err(LookupPathUnknown(path.into_vec())),
        LookupResult::Found(value) => Ok(value),
        LookupResult::Error => Err(LookupPathError(path.into_vec())),
    }
}

/// Looks up a subtree in the certificate's tree at the specified hash.
///
/// Returns the value if it was found; otherwise, errors with `LookupPathAbsent` or `LookupPathUnknown`.
pub fn lookup_tree<P: LookupPath, Storage: AsRef<[u8]> + Clone>(
    tree: &HashTree<Storage>,
    path: P,
) -> Result<HashTree<Storage>, AgentError> {
    use AgentError::*;
    match tree.lookup_subtree(path.iter()) {
        SubtreeLookupResult::Absent => Err(LookupPathAbsent(path.into_vec())),
        SubtreeLookupResult::Unknown => Err(LookupPathUnknown(path.into_vec())),
        SubtreeLookupResult::Found(value) => Ok(value),
    }
}
