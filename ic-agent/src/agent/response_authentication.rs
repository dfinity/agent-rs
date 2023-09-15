use crate::agent::{RejectCode, RejectResponse, RequestStatusResponse};
use crate::{export::Principal, AgentError, RequestId};
use ic_certification::{certificate::Certificate, hash_tree::Label, LookupResult};
use ic_transport_types::ReplyResponse;
use std::str::from_utf8;

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
    lookup_value(&certificate, path_canister).map(<[u8]>::to_vec)
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

    lookup_value(&certificate, path_canister).map(<[u8]>::to_vec)
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
    let code = lookup_value(certificate, path)?;
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
    let msg = lookup_value(certificate, path)?;
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
    let reply_data = lookup_value(certificate, path)?;
    let arg = Vec::from(reply_data);
    Ok(RequestStatusResponse::Replied(ReplyResponse { arg }))
}

/// The path to [`lookup_value`]
pub trait LookupPath {
    type Item<'a>: AsRef<[u8]>
    where
        Self: 'a;
    type Iter<'a>: Iterator<Item = Self::Item<'a>>
    where
        Self: 'a;
    fn iter(&self) -> Self::Iter<'_>;
    fn into_vec(self) -> Vec<Label<Vec<u8>>>;
}

impl<'b, const N: usize> LookupPath for [&'b [u8]; N] {
    type Item<'a> = &'a &'b [u8] where Self: 'a;
    type Iter<'a> = std::slice::Iter<'a, &'b [u8]> where Self: 'a;
    fn iter(&self) -> Self::Iter<'_> {
        self.as_slice().iter()
    }
    fn into_vec(self) -> Vec<Label<Vec<u8>>> {
        self.map(Label::from_bytes).into()
    }
}
impl<'b, 'c> LookupPath for &'c [&'b [u8]] {
    type Item<'a> = &'a &'b [u8] where Self: 'a;
    type Iter<'a> = std::slice::Iter<'a, &'b [u8]> where Self: 'a;
    fn iter(&self) -> Self::Iter<'_> {
        <[_]>::iter(self)
    }
    fn into_vec(self) -> Vec<Label<Vec<u8>>> {
        self.iter().map(|v| Label::from_bytes(v)).collect()
    }
}
impl<'b> LookupPath for Vec<&'b [u8]> {
    type Item<'a> = &'a &'b [u8] where Self: 'a;
    type Iter<'a> = std::slice::Iter<'a, &'b [u8]> where Self: 'a;
    fn iter(&self) -> Self::Iter<'_> {
        <[_]>::iter(self.as_slice())
    }
    fn into_vec(self) -> Vec<Label<Vec<u8>>> {
        self.into_iter().map(Label::from_bytes).collect()
    }
}

impl<const N: usize> LookupPath for [Vec<u8>; N] {
    type Item<'a> = &'a Vec<u8> where Self: 'a;
    type Iter<'a> = std::slice::Iter<'a, Vec<u8>> where Self: 'a;
    fn iter(&self) -> Self::Iter<'_> {
        self.as_slice().iter()
    }
    fn into_vec(self) -> Vec<Label<Vec<u8>>> {
        self.map(Label::from).into()
    }
}
impl<'c> LookupPath for &'c [Vec<u8>] {
    type Item<'a> = &'a Vec<u8> where Self: 'a;
    type Iter<'a> = std::slice::Iter<'a, Vec<u8>> where Self: 'a;
    fn iter(&self) -> Self::Iter<'_> {
        <[_]>::iter(self)
    }
    fn into_vec(self) -> Vec<Label<Vec<u8>>> {
        self.iter().map(|v| Label::from(v.clone())).collect()
    }
}
impl LookupPath for Vec<Vec<u8>> {
    type Item<'a> = &'a Vec<u8> where Self: 'a;
    type Iter<'a> = std::slice::Iter<'a, Vec<u8>> where Self: 'a;
    fn iter(&self) -> Self::Iter<'_> {
        <[_]>::iter(self.as_slice())
    }
    fn into_vec(self) -> Vec<Label<Vec<u8>>> {
        self.into_iter().map(Label::from).collect()
    }
}

impl<Storage: AsRef<[u8]> + Into<Vec<u8>>, const N: usize> LookupPath for [Label<Storage>; N] {
    type Item<'a> = &'a Label<Storage> where Self: 'a;
    type Iter<'a> = std::slice::Iter<'a, Label<Storage>> where Self: 'a;
    fn iter(&self) -> Self::Iter<'_> {
        self.as_slice().iter()
    }
    fn into_vec(self) -> Vec<Label<Vec<u8>>> {
        self.map(Label::from_label).into()
    }
}
impl<'c, Storage: AsRef<[u8]> + Into<Vec<u8>>> LookupPath for &'c [Label<Storage>] {
    type Item<'a> = &'a Label<Storage> where Self: 'a;
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
    type Item<'a> = &'a Label<Vec<u8>> where Self: 'a;
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
    certificate: &Certificate<Storage>,
    path: P,
) -> Result<&[u8], AgentError> {
    use AgentError::*;
    match certificate.tree.lookup_path(path.iter()) {
        LookupResult::Absent => Err(LookupPathAbsent(path.into_vec())),
        LookupResult::Unknown => Err(LookupPathUnknown(path.into_vec())),
        LookupResult::Found(value) => Ok(value),
        LookupResult::Error => Err(LookupPathError(path.into_vec())),
    }
}
