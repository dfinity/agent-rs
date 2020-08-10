use sha2::{Digest, Sha224};
use std::convert::TryFrom;
use thiserror::Error;

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
}

const ID_ANONYMOUS_BYTES: &[u8] = &[PrincipalClass::Anonymous as u8];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum PrincipalClass {
    Unassigned = 0,
    OpaqueId = 1,
    SelfAuthenticating = 2,
    DerivedId = 3,
    Anonymous = 4,
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Principal(PrincipalInner);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PrincipalInner {
    /// An empty principal that marks the system canister.
    ManagementCanister,

    /// A Principal created by the system (the Internet Computer). This can only be created by
    /// using [`try_from`].
    OpaqueId(Vec<u8>),

    /// Defined as H(public_key) || 0x02.
    SelfAuthenticating(Vec<u8>),

    /// A Principal derived by another.
    /// Defined as H(|registering_principal| || registering_principal || derivation_nonce) || 0x03
    DerivedId(Vec<u8>),

    /// The anonymous Principal.
    Anonymous,

    /// An unknown principal class was found. This is unspecified from the spec, but we can use it.
    Unassigned(Vec<u8>),
}

impl Principal {
    pub fn management_canister() -> Self {
        Self(PrincipalInner::ManagementCanister)
    }

    /// Right now we are enforcing a Twisted Edwards Curve 25519 point
    /// as the public key.
    pub fn self_authenticating<P: AsRef<[u8]>>(public_key: P) -> Self {
        let mut bytes: Vec<u8> = Vec::with_capacity(Sha224::output_size() + 1);
        let hash = Sha224::digest(public_key.as_ref());
        bytes.extend(&hash);

        // Now add a suffix denoting the identifier as representing a
        // self-authenticating principal.
        bytes.push(PrincipalClass::SelfAuthenticating as u8);
        Self(PrincipalInner::SelfAuthenticating(bytes))
    }

    pub fn anonymous() -> Self {
        Self(PrincipalInner::Anonymous)
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
                if bytes.len() < 4 {
                    return Err(PrincipalError::TextTooSmall());
                }
                let result = Self::try_from(bytes.split_off(4))?;
                let expected = format!("{}", result);

                if text.as_ref() != expected {
                    return Err(PrincipalError::AbnormalTextualFormat(expected));
                }
                Ok(result)
            }
            None => Err(PrincipalError::InvalidTextualFormatNotBase32()),
        }
    }

    pub fn to_text(&self) -> String {
        format!("{}", self)
    }

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
        while s.len() > 5 {
            // to bad split_off does not work the other way
            let rest = s.split_off(5);
            f.write_fmt(format_args!("{}-", s))?;
            s = rest;
        }
        write!(f, "{}", s).unwrap();
        Ok(())
    }
}

impl std::str::FromStr for Principal {
    type Err = PrincipalError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Principal::from_text(s)
    }
}

impl TryFrom<Vec<u8>> for Principal {
    type Error = PrincipalError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        if let Some(last_byte) = bytes.last() {
            match PrincipalClass::try_from(*last_byte)? {
                PrincipalClass::OpaqueId => Ok(Principal(PrincipalInner::OpaqueId(bytes))),
                PrincipalClass::SelfAuthenticating => {
                    Ok(Principal(PrincipalInner::SelfAuthenticating(bytes)))
                }
                PrincipalClass::DerivedId => Ok(Principal(PrincipalInner::DerivedId(bytes))),
                PrincipalClass::Anonymous => {
                    if bytes.len() == 1 {
                        Ok(Principal(PrincipalInner::Anonymous))
                    } else {
                        Err(PrincipalError::BufferTooLong())
                    }
                }
                PrincipalClass::Unassigned => Ok(Principal(PrincipalInner::Unassigned(bytes))),
            }
        } else {
            Ok(Principal(PrincipalInner::ManagementCanister))
        }
    }
}

/// Implement try_from for a generic sized slice.
impl TryFrom<&[u8]> for Principal {
    type Error = PrincipalError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from(bytes.to_vec())
    }
}

/// Implement try_from for a statically sized slice up to the maximum allowed by the spec.
macro_rules! impl_try_from_for_size {
    ($($n: literal),+) => {
        $(
            impl TryFrom<&[u8; $n]> for Principal {
                type Error = PrincipalError;

                fn try_from(bytes: &[u8; $n]) -> Result<Self, Self::Error> {
                    Self::try_from(bytes.to_vec())
                }
            }
        )*
    };
}
impl_try_from_for_size!(
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29
);

impl AsRef<[u8]> for Principal {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsRef<[u8]> for PrincipalInner {
    fn as_ref(&self) -> &[u8] {
        match self {
            PrincipalInner::Unassigned(v) => v,
            PrincipalInner::ManagementCanister => &[],
            PrincipalInner::OpaqueId(v) => v,

            PrincipalInner::SelfAuthenticating(v) => v,
            PrincipalInner::DerivedId(v) => v,
            PrincipalInner::Anonymous => ID_ANONYMOUS_BYTES,
        }
    }
}

// Serialization
#[cfg(feature = "serde")]
impl serde::Serialize for Principal {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0.as_ref())
    }
}

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
            formatter.write_str("a binary large object (bytes)")
        }

        fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Principal::try_from(value).map_err(E::custom)
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
            Principal(PrincipalInner::ManagementCanister)
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
