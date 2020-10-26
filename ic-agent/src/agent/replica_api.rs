use crate::export::Principal;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct Envelope<T: Serialize> {
    pub content: T,
    #[serde(with = "serde_bytes")]
    pub sender_pubkey: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sender_sig: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "request_type")]
pub enum AsyncContent {
    #[serde(rename = "call")]
    CallRequest {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(with = "serde_bytes")]
        nonce: Option<Vec<u8>>,
        ingress_expiry: u64,
        sender: Principal,
        canister_id: Principal,
        method_name: String,
        #[serde(with = "serde_bytes")]
        arg: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PathElement(Vec<u8>);

impl PathElement {
    pub fn new(v: Vec<u8>) -> Self {
        Self(v)
    }
}

// /// Vector TryFrom. The slice and array version of this trait are defined below.
// impl TryFrom<Vec<u8>> for Principal {
//     type Error = PrincipalError;
//
//     fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
//         if let Some(last_byte) = bytes.last() {
//             match PrincipalClass::try_from(*last_byte)? {
//                 PrincipalClass::OpaqueId => Ok(Principal(PrincipalInner::OpaqueId(bytes))),
//                 PrincipalClass::SelfAuthenticating => {
//                     Ok(Principal(PrincipalInner::SelfAuthenticating(bytes)))
//                 }
//                 PrincipalClass::DerivedId => Ok(Principal(PrincipalInner::DerivedId(bytes))),
//                 PrincipalClass::Anonymous => {
//                     if bytes.len() == 1 {
//                         Ok(Principal(PrincipalInner::Anonymous))
//                     } else {
//                         Err(PrincipalError::BufferTooLong())
//                     }
//                 }
//                 PrincipalClass::Unassigned => Ok(Principal(PrincipalInner::Unassigned(bytes))),
//             }
//         } else {
//             Ok(Principal(PrincipalInner::ManagementCanister))
//         }
//     }
// }
//
// impl TryFrom<&Vec<u8>> for Principal {
//     type Error = PrincipalError;
//
//     fn try_from(bytes: &Vec<u8>) -> Result<Self, Self::Error> {
//         Self::try_from(bytes.as_slice())
//     }
// }
//
// /// Implement try_from for a generic sized slice.
// impl TryFrom<&[u8]> for Principal {
//     type Error = PrincipalError;
//
//     fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
//         Self::try_from(bytes.to_vec())
//     }
// }
//
// impl AsRef<[u8]> for Principal {
//     fn as_ref(&self) -> &[u8] {
//         self.0.as_ref()
//     }
// }

// Serialization
#[cfg(feature = "serde")]
impl serde::Serialize for PathElement {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            self.to_text().serialize(serializer)
        } else {
            serializer.serialize_bytes(self.0.as_ref())
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PathElement {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<PathElement, D::Error> {
        use serde::de::Error;
        deserializer
            .deserialize_bytes(deserialize::PrincipalVisitor)
            .map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "request_type")]
pub enum SyncContent {
    #[serde(rename = "read_state")]
    ReadStateRequest {
        ingress_expiry: u64,
        sender: Principal,
        paths: Vec<Vec<serde_bytes::ByteBuf>>,
    },
    #[serde(rename = "request_status")]
    RequestStatusRequest {
        ingress_expiry: u64,
        #[serde(with = "serde_bytes")]
        request_id: Vec<u8>,
    },
    #[serde(rename = "query")]
    QueryRequest {
        ingress_expiry: u64,
        sender: Principal,
        canister_id: Principal,
        method_name: String,
        #[serde(with = "serde_bytes")]
        arg: Vec<u8>,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReadStateResponse {
    #[serde(with = "serde_bytes")]
    pub certificate: Vec<u8>,
}

// #[derive(Debug, Clone, Deserialize, Serialize)]
// pub struct RequestStatusResponse {
//     pub status: Status,
//     #[serde(rename = "time")]
//     pub time: u64,
// }

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "status")]
pub enum Status {
    #[serde(rename = "unknown")]
    Unknown {},
    #[serde(rename = "received")]
    Received {},
    #[serde(rename = "processing")]
    Processing {},
    #[serde(rename = "replied")]
    Replied { reply: RequestStatusResponseReplied },
    #[serde(rename = "rejected")]
    Rejected {
        reject_code: u64,
        reject_message: String,
    },
    #[serde(rename = "done")]
    Done {},
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum RequestStatusResponseReplied {
    CallReply(CallReply),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CallReply {
    #[serde(with = "serde_bytes")]
    pub arg: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "status")]
pub enum QueryResponse {
    #[serde(rename = "replied")]
    Replied { reply: CallReply },
    #[serde(rename = "rejected")]
    Rejected {
        reject_code: u64,
        reject_message: String,
    },
}
