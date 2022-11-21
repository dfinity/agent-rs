use crate::agent::{Replied, RequestStatusResponse};
use crate::{export::Principal, AgentError, RequestId};
use ic_certification::{Certificate, Label, LookupResult};
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

pub(crate) fn lookup_canister_info(
    certificate: Certificate,
    canister_id: Principal,
    path: &str,
) -> Result<Vec<u8>, AgentError> {
    let path_canister = ["canister".into(), canister_id.into(), path.into()];
    lookup_value(&certificate, path_canister).map(<[u8]>::to_vec)
}

pub(crate) fn lookup_canister_metadata(
    certificate: Certificate,
    canister_id: Principal,
    path: &str,
) -> Result<Vec<u8>, AgentError> {
    let path_canister = [
        "canister".into(),
        canister_id.into(),
        "metadata".into(),
        path.into(),
    ];
    lookup_value(&certificate, path_canister).map(<[u8]>::to_vec)
}

pub(crate) fn lookup_request_status(
    certificate: Certificate,
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
        LookupResult::Unknown => Ok(RequestStatusResponse::Unknown),
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

pub(crate) fn lookup_rejection(
    certificate: &Certificate,
    request_id: &RequestId,
) -> Result<RequestStatusResponse, AgentError> {
    let reject_code = lookup_reject_code(certificate, request_id)?;
    let reject_message = lookup_reject_message(certificate, request_id)?;

    Ok(RequestStatusResponse::Rejected {
        reject_code,
        reject_message,
    })
}

pub(crate) fn lookup_reject_code(
    certificate: &Certificate,
    request_id: &RequestId,
) -> Result<u64, AgentError> {
    let path = [
        "request_status".into(),
        request_id.to_vec().into(),
        "reject_code".into(),
    ];
    let code = lookup_value(certificate, path)?;
    let mut readable = code;
    Ok(leb128::read::unsigned(&mut readable)?)
}

pub(crate) fn lookup_reject_message(
    certificate: &Certificate,
    request_id: &RequestId,
) -> Result<String, AgentError> {
    let path = [
        "request_status".into(),
        request_id.to_vec().into(),
        "reject_message".into(),
    ];
    let msg = lookup_value(certificate, path)?;
    Ok(from_utf8(msg)?.to_string())
}

pub(crate) fn lookup_reply(
    certificate: &Certificate,
    request_id: &RequestId,
) -> Result<RequestStatusResponse, AgentError> {
    let path = [
        "request_status".into(),
        request_id.to_vec().into(),
        "reply".into(),
    ];
    let reply_data = lookup_value(certificate, path)?;
    let reply = Replied::CallReplied(Vec::from(reply_data));
    Ok(RequestStatusResponse::Replied { reply })
}

/// Looks up a value in the certificate's tree at the specified hash.
///
/// Returns the value if it was found; otherwise, errors with `LookupPathAbsent`, `LookupPathUnknown`, or `LookupPathError`.
pub fn lookup_value<'a, P>(
    certificate: &'a Certificate<'a>,
    path: P,
) -> Result<&'a [u8], AgentError>
where
    for<'p> &'p P: IntoIterator<Item = &'p Label>,
    P: Into<Vec<Label>>,
{
    use AgentError::*;
    match certificate.tree.lookup_path(&path) {
        LookupResult::Absent => Err(LookupPathAbsent(path.into())),
        LookupResult::Unknown => Err(LookupPathUnknown(path.into())),
        LookupResult::Found(value) => Ok(value),
        LookupResult::Error => Err(LookupPathError(path.into())),
    }
}
