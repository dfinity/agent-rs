use sha2::{Digest, Sha224};
use std::cmp::min;
use std::convert::TryFrom;
use std::fmt::Write;
use thiserror::Error;

/// An error happened while encoding, decoding or serializing a principal.
#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum PrincipalError {
    #[error("Buffer is too long.")]
    BufferTooLong(),

    #[error(r#"Invalid textual format: expected "{0}""#)]
    AbnormalTextualFormat(String),

    #[error("Text must be a base 32 string.")]
    InvalidTextualFormatNotBase32(),

    #[error("Text cannot be converted to a Principal; too small.")]
    TextTooSmall(),

    #[error("A custom tool returned an error instead of a Principal: {0}")]
    ExternalError(String),
}

/// A class of principal. Because this should not be exposed it
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
enum PrincipalClass {
    OpaqueId = 1,
    SelfAuthenticating = 2,
    DerivedId = 3,
    Anonymous = 4,
    Unassigned,
}

impl Into<u8> for PrincipalClass {
    fn into(self) -> u8 {
        match self {
            PrincipalClass::Unassigned => 0,
            PrincipalClass::OpaqueId => 1,
            PrincipalClass::SelfAuthenticating => 2,
            PrincipalClass::DerivedId => 3,
            PrincipalClass::Anonymous => 4,
        }
    }
}

impl TryFrom<u8> for PrincipalClass {
    type Error = PrincipalError;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            1 => Ok(PrincipalClass::OpaqueId),
            2 => Ok(PrincipalClass::SelfAuthenticating),
            3 => Ok(PrincipalClass::DerivedId),
            4 => Ok(PrincipalClass::Anonymous),
            _ => Ok(PrincipalClass::Unassigned),
        }
    }
}

/// A principal describes the security context of an identity, namely
/// any identity that can be authenticated along with a specific
/// role. In the case of the Internet Computer this maps currently to
/// the identities that can be authenticated by a canister. For example,
/// a canister ID is a Principal. So is a user.
///
/// Note a principal is not necessarily tied with a public key-pair,
/// yet we need at least a key-pair of a related principal to sign
/// requests.
///
/// A Principal can be serialized to a byte array ([`Vec<u8>`]) or a text
/// representation, but the inner structure of the byte representation
/// is kept private.
///
/// Example of using a Principal object:
/// ```
/// use ic_types::Principal;
///
/// let text = "aaaaa-aa";  // The management canister ID.
/// let principal = Principal::from_text(text).expect("Could not decode the principal.");
/// assert_eq!(principal.as_slice(), &[]);
/// assert_eq!(principal.to_text(), text);
/// ```
///
/// Serialization is enabled with the "serde" feature. It supports serializing
/// to a byte bufer for non-human readable serializer, and a string version for human
/// readable serializers.
///
/// ```
/// use ic_types::Principal;
/// use serde::{Deserialize, Serialize};
/// use std::str::FromStr;
///
/// #[derive(Serialize)]
/// struct Data {
///     id: Principal,
/// }
///
/// let id = Principal::from_str("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();
///
/// // JSON is human readable, so this will serialize to a textual
/// // main.rsrepresentation of the Principal.
/// assert_eq!(
///     serde_json::to_string(&Data { id: id.clone() }).unwrap(),
///     r#"{"id":"2chl6-4hpzw-vqaaa-aaaaa-c"}"#
/// );
///
/// // CBOR is not human readable, so will serialize to bytes.
/// assert_eq!(
///     serde_cbor::to_vec(&Data { id: id.clone() }).unwrap(),
///     &[161, 98, 105, 100, 73, 239, 205, 171, 0, 0, 0, 0, 0, 1],
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Principal(PrincipalInner);

impl Principal {
    pub fn management_canister() -> Self {
        Self(PrincipalInner::management_canister())
    }

    /// Right now we are enforcing a Twisted Edwards Curve 25519 point
    /// as the public key.
    pub fn self_authenticating<P: AsRef<[u8]>>(public_key: P) -> Self {
        Self(PrincipalInner::self_authenticating(public_key.as_ref()))
    }

    /// An anonymous Principal.
    pub fn anonymous() -> Self {
        Self(PrincipalInner::anonymous())
    }

    /// Parse the text format for canister IDs (e.g., `jkies-sibbb-ap6`).
    ///
    /// The text format follows the public spec (see Textual IDs section).
    pub fn from_text<S: AsRef<str>>(text: S) -> Result<Self, PrincipalError> {
        // Strategy: Parse very liberally, then pretty-print and compare output
        // This is both simpler and yields better error messages

        let mut s = text.as_ref().to_string();
        s.make_ascii_lowercase();
        s.retain(|c| c != '-');
        match base32::decode(base32::Alphabet::RFC4648 { padding: false }, &s) {
            Some(mut bytes) => {
                if bytes.len() < PrincipalInner::CRC_LENGTH_IN_BYTES {
                    return Err(PrincipalError::TextTooSmall());
                }
                let result = Self::try_from(bytes.split_off(PrincipalInner::CRC_LENGTH_IN_BYTES))?;
                let expected = format!("{}", result);

                if text.as_ref() != expected {
                    return Err(PrincipalError::AbnormalTextualFormat(expected));
                }
                Ok(result)
            }
            None => Err(PrincipalError::InvalidTextualFormatNotBase32()),
        }
    }

    /// Returns this Principal's text representation. The text representation is described
    /// in the spec.
    pub fn to_text(&self) -> String {
        format!("{}", self)
    }

    /// Returns this Principal's bytes.
    pub fn as_slice(&self) -> &[u8] {
        self.as_ref()
    }
}

impl std::fmt::Display for Principal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let blob: &[u8] = self.0.as_ref();

        // calc checksum
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(blob);
        let checksum = hasher.finalize();

        // combine blobs
        let mut bytes = vec![];
        bytes.extend_from_slice(&checksum.to_be_bytes());
        bytes.extend_from_slice(blob);

        // base32
        let mut s = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &bytes);
        s.make_ascii_lowercase();

        // write out string with dashes
        let mut s = s.as_str();
        while s.len() > 5 {
            f.write_str(&s[..5])?;
            f.write_char('-')?;
            s = &s[5..];
        }
        f.write_str(&s)
    }
}

impl std::str::FromStr for Principal {
    type Err = PrincipalError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Principal::from_text(s)
    }
}

impl TryFrom<&str> for Principal {
    type Error = PrincipalError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Principal::from_text(s)
    }
}

/// Vector TryFrom. The slice and array version of this trait are defined below.
impl TryFrom<Vec<u8>> for Principal {
    type Error = PrincipalError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        match bytes.as_slice() {
            [] => Ok(Principal(PrincipalInner::management_canister())),
            [4] => Ok(Principal(PrincipalInner::anonymous())),
            [.., 4] => Err(PrincipalError::BufferTooLong()),
            bytes @ [..] => Ok(Principal(PrincipalInner::from(bytes))),
        }
    }
}

impl TryFrom<&Vec<u8>> for Principal {
    type Error = PrincipalError;

    fn try_from(bytes: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

/// Implement try_from for a generic sized slice.
impl TryFrom<&[u8]> for Principal {
    type Error = PrincipalError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from(bytes.to_vec())
    }
}

impl AsRef<[u8]> for Principal {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

// Serialization
#[cfg(feature = "serde")]
impl serde::Serialize for Principal {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            self.to_text().serialize(serializer)
        } else {
            serializer.serialize_bytes(self.0.as_ref())
        }
    }
}

// Deserialization
#[cfg(feature = "serde")]
mod deserialize {
    use super::Principal;
    use std::convert::TryFrom;

    /// Simple visitor for deserialization from bytes. We don't support other number types
    /// as there's no need for it.
    pub(super) struct PrincipalVisitor;

    impl<'de> serde::de::Visitor<'de> for PrincipalVisitor {
        type Value = super::Principal;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("bytes or string")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Principal::from_text(v).map_err(E::custom)
        }

        fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Principal::try_from(value).map_err(E::custom)
        }
        /// This visitor should only be used by the Candid crate.
        fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if v.is_empty() || v[0] != 2u8 {
                Err(E::custom("Not called by Candid"))
            } else {
                Principal::try_from(&v[1..]).map_err(E::custom)
            }
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Principal {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Principal, D::Error> {
        use serde::de::Error;
        deserializer
            .deserialize_bytes(deserialize::PrincipalVisitor)
            .map_err(D::Error::custom)
    }
}

/// Inner structure of a Principal. This is not meant to be public as the different classes
/// of principals are not public.
///
/// This is a length (1 byte) and 29 bytes. The length can be 0, but won't ever be longer
/// than 29. The current interface spec says that principals cannot be longer than 29 bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(packed)]
struct PrincipalInner {
    /// Length.
    len: u8,

    /// The content buffer. When returning slices this should always be sized according to
    /// `len`.
    bytes: [u8; Self::MAX_LENGTH_IN_BYTES],
}

impl PrincipalInner {
    const MAX_LENGTH_IN_BYTES: usize = 29;
    const CRC_LENGTH_IN_BYTES: usize = 4;

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    #[inline]
    pub fn management_canister() -> Self {
        Self {
            len: 0,
            bytes: [0; Self::MAX_LENGTH_IN_BYTES],
        }
    }

    #[inline]
    pub fn anonymous() -> Self {
        let mut bytes = [0u8; Self::MAX_LENGTH_IN_BYTES];
        bytes[0] = PrincipalClass::Anonymous as u8;
        Self { len: 1, bytes }
    }

    #[inline]
    pub fn self_authenticating(public_key: &[u8]) -> Self {
        let mut bytes = [0u8; PrincipalInner::MAX_LENGTH_IN_BYTES];
        let hash = Sha224::digest(public_key);
        let len = hash.len();
        bytes[..len].copy_from_slice(&hash);
        // Now add a suffix denoting the identifier as representing a
        // self-authenticating principal.
        bytes[len] = PrincipalClass::SelfAuthenticating as u8;

        Self {
            len: (len + 1) as u8,
            bytes,
        }
    }
}

impl AsRef<[u8]> for PrincipalInner {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl From<&[u8]> for PrincipalInner {
    fn from(slice: &[u8]) -> Self {
        let len = min(slice.len(), Self::MAX_LENGTH_IN_BYTES) as u8;
        let mut bytes = [0u8; Self::MAX_LENGTH_IN_BYTES];
        bytes[..len as usize].copy_from_slice(slice);
        Self { len, bytes }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[cfg(feature = "serde")]
    #[test]
    fn serializes() {
        let seed = [
            0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
            0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44,
            0x33, 0x22, 0x11, 0x00,
        ];
        let principal: Principal = Principal::self_authenticating(&seed);
        assert_eq!(
            serde_cbor::from_slice::<Principal>(
                serde_cbor::to_vec(&principal)
                    .expect("Failed to serialize")
                    .as_slice()
            )
            .unwrap(),
            principal
        );
    }

    #[test]
    fn parse_management_canister_ok() {
        assert_eq!(
            Principal::from_str("aaaaa-aa").unwrap(),
            Principal::management_canister(),
        );
    }

    #[test]
    fn parse_management_canister_to_text_ok() {
        assert_eq!(Principal::from_str("aaaaa-aa").unwrap().as_slice(), &[]);
    }

    #[test]
    fn create_managment_cid_from_empty_blob_ok() {
        assert_eq!(Principal::management_canister().to_text(), "aaaaa-aa");
    }

    #[test]
    fn create_managment_cid_from_text_ok() {
        assert_eq!(
            Principal::from_str("aaaaa-aa").unwrap().to_text(),
            "aaaaa-aa",
        );
    }

    #[test]
    fn display_canister_id() {
        assert_eq!(
            Principal::try_from(vec![0xef, 0xcd, 0xab, 0, 0, 0, 0, 0, 1])
                .unwrap()
                .to_text(),
            "2chl6-4hpzw-vqaaa-aaaaa-c",
        );
    }

    #[test]
    fn display_canister_id_from_bytes_as_bytes() {
        assert_eq!(
            Principal::try_from(vec![0xef, 0xcd, 0xab, 0, 0, 0, 0, 0, 1])
                .unwrap()
                .as_slice(),
            &[0xef, 0xcd, 0xab, 0, 0, 0, 0, 0, 1],
        );
    }

    #[test]
    fn display_canister_id_from_blob_as_bytes() {
        assert_eq!(
            Principal::try_from(vec![0xef, 0xcd, 0xab, 0, 0, 0, 0, 0, 1])
                .unwrap()
                .as_slice(),
            &[0xef, 0xcd, 0xab, 0, 0, 0, 0, 0, 1],
        );
    }

    #[test]
    fn display_canister_id_from_text_as_bytes() {
        assert_eq!(
            Principal::from_str("2chl6-4hpzw-vqaaa-aaaaa-c")
                .unwrap()
                .as_slice(),
            &[0xef, 0xcd, 0xab, 0, 0, 0, 0, 0, 1],
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn check_serialize_deserialize() {
        let id = Principal::from_str("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();

        // Use cbor serialization.
        let vec = serde_cbor::to_vec(&id).unwrap();
        let value = serde_cbor::from_slice(vec.as_slice()).unwrap();

        assert_eq!(id, value);
    }

    #[test]
    fn text_form() {
        let cid = Principal::try_from(vec![1, 8, 64, 255]).unwrap();
        let text = cid.to_text();
        let cid2 = Principal::from_str(&text).unwrap();
        assert_eq!(cid, cid2);
        assert_eq!(text, "jkies-sibbb-ap6");
    }
}
