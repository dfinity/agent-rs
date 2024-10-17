//! This module deals with computing Request IDs based on the content of a
//! message.
//!
//! A request ID is a SHA256 hash of the request's body. See
//! [Representation-independent Hashing of Structured Data](https://internetcomputer.org/docs/current/references/ic-interface-spec#hash-of-map)
//! from the IC spec for the method of calculation.
use error::RequestIdFromStringError;
use serde::{
    de::{self, Error as _, Visitor},
    ser::{
        SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTuple,
        SerializeTupleStruct, SerializeTupleVariant,
    },
    Deserialize, Deserializer, Serialize, Serializer,
};
use sha2::{Digest, Sha256};
use std::{
    fmt::{self, Display, Formatter},
    io::Write,
    ops::Deref,
    str::FromStr,
};

mod error;
#[doc(inline)]
pub use error::RequestIdError;

const IC_REQUEST_DOMAIN_SEPARATOR: &[u8; 11] = b"\x0Aic-request";

/// Type alias for a sha256 result (ie. a u256).
type Sha256Hash = [u8; 32];

/// Derive the request ID from a serializable data structure. This does not include the `ic-request` domain prefix.
///
/// See [Representation-independent Hashing of Structured Data](https://internetcomputer.org/docs/current/references/ic-interface-spec#hash-of-map)
/// from the IC spec for the method of calculation.
///
/// # Serialization
///
/// This section is only relevant if you're using this function to hash your own types.
///
/// * Per the spec, neither of bools, floats, or nulls are supported.
/// * Enum variants are serialized identically to `serde_json`.
/// * `Option::None` fields are omitted entirely.
/// * Byte strings are serialized *differently* to arrays of bytes -
///   use of `serde_bytes` is required for correctness.
pub fn to_request_id<'a, V>(value: &V) -> Result<RequestId, RequestIdError>
where
    V: 'a + Serialize,
{
    value
        .serialize(RequestIdSerializer)
        .transpose()
        .unwrap_or(Err(RequestIdError::EmptySerializer))
        .map(RequestId)
}

/// A Request ID.
#[derive(Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct RequestId(Sha256Hash);

impl RequestId {
    /// Creates a new `RequestId` from a SHA-256 hash.
    pub fn new(from: &[u8; 32]) -> RequestId {
        RequestId(*from)
    }

    /// Returns the signable form of the request ID, by prepending `"\x0Aic-request"` to it,
    /// for use in [`Identity::sign`](https://docs.rs/ic-agent/latest/ic_agent/trait.Identity.html#tymethod.sign).
    pub fn signable(&self) -> Vec<u8> {
        let mut signable = Vec::with_capacity(43);
        signable.extend_from_slice(IC_REQUEST_DOMAIN_SEPARATOR);
        signable.extend_from_slice(&self.0);
        signable
    }
}

impl Deref for RequestId {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromStr for RequestId {
    type Err = RequestIdFromStringError;

    fn from_str(from: &str) -> Result<Self, Self::Err> {
        let mut blob: [u8; 32] = [0; 32];
        let vec = hex::decode(from).map_err(RequestIdFromStringError::FromHexError)?;
        if vec.len() != 32 {
            return Err(RequestIdFromStringError::InvalidSize(vec.len()));
        }

        blob.copy_from_slice(vec.as_slice());
        Ok(RequestId::new(&blob))
    }
}

impl From<RequestId> for String {
    fn from(id: RequestId) -> String {
        hex::encode(id.0)
    }
}

impl Display for RequestId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        hex::encode(self.0).fmt(f)
    }
}

// Request ID hashing in all contexts is implemented as a serde Serializer to eliminate any special-casing.
struct RequestIdSerializer;

impl Serializer for RequestIdSerializer {
    // Serde conveniently allows us to have each serialization operation return a value.
    // Since this serializer is a hash function, this eliminates any need for a state-machine.
    type Ok = Option<Sha256Hash>;
    type Error = RequestIdError;

    // We support neither floats nor bools nor nulls.

    fn serialize_bool(self, _v: bool) -> Result<Self::Ok, Self::Error> {
        Err(RequestIdError::UnsupportedTypeBool)
    }
    fn serialize_f32(self, _v: f32) -> Result<Self::Ok, Self::Error> {
        Err(RequestIdError::UnsupportedTypeF32)
    }
    fn serialize_f64(self, _v: f64) -> Result<Self::Ok, Self::Error> {
        Err(RequestIdError::UnsupportedTypeF64)
    }
    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Err(RequestIdError::UnsupportedTypeUnit)
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        Err(RequestIdError::UnsupportedTypeUnitStruct)
    }

    // Ints are serialized using signed LEB128 encoding.

    fn serialize_i64(self, v: i64) -> Result<Self::Ok, Self::Error> {
        let mut arr = [0u8; 10];
        let n = leb128::write::signed(&mut &mut arr[..], v).unwrap();
        Ok(Some(Sha256::digest(&arr[..n]).into()))
    }
    fn serialize_i8(self, v: i8) -> Result<Self::Ok, Self::Error> {
        self.serialize_i64(v as i64)
    }
    fn serialize_i16(self, v: i16) -> Result<Self::Ok, Self::Error> {
        self.serialize_i64(v as i64)
    }
    fn serialize_i32(self, v: i32) -> Result<Self::Ok, Self::Error> {
        self.serialize_i64(v as i64)
    }

    // Uints are serialized using unsigned LEB128 encoding.

    fn serialize_u64(self, v: u64) -> Result<Self::Ok, Self::Error> {
        let mut arr = [0u8; 10];
        let n = leb128::write::unsigned(&mut &mut arr[..], v).unwrap();
        Ok(Some(Sha256::digest(&arr[..n]).into()))
    }
    fn serialize_u8(self, v: u8) -> Result<Self::Ok, Self::Error> {
        self.serialize_u64(v as u64)
    }
    fn serialize_u16(self, v: u16) -> Result<Self::Ok, Self::Error> {
        self.serialize_u64(v as u64)
    }
    fn serialize_u32(self, v: u32) -> Result<Self::Ok, Self::Error> {
        self.serialize_u64(v as u64)
    }

    // Bytes are serialized as-is.

    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
        Ok(Some(Sha256::digest(v).into()))
    }

    // Strings are serialized as UTF-8 bytes.

    fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error> {
        self.serialize_bytes(v.as_bytes())
    }
    fn serialize_char(self, v: char) -> Result<Self::Ok, Self::Error> {
        let mut utf8 = [0u8; 4];
        let str = v.encode_utf8(&mut utf8);
        self.serialize_bytes(str.as_bytes())
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        self.serialize_str(variant)
    }

    // Newtypes, including Option::Some, are transparent.

    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<Self::Ok, Self::Error> {
        value.serialize(self)
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        value.serialize(self)
    }

    // Fields containing None are omitted from the containing struct or array.

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        Ok(None)
    }

    // Arrays, tuples, and tuple structs are treated identically.

    type SerializeSeq = SeqSerializer;
    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        self.serialize_tuple(len.unwrap_or(8))
    }
    type SerializeTuple = SeqSerializer;
    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Ok(SeqSerializer {
            elems: Vec::with_capacity(len),
        })
    }
    type SerializeTupleStruct = SeqSerializer;
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        self.serialize_tuple(len)
    }

    // Maps and structs are treated identically.

    type SerializeMap = StructSerializer;
    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        self.serialize_struct("", len.unwrap_or(8))
    }
    type SerializeStruct = StructSerializer;
    fn serialize_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        Ok(StructSerializer {
            fields: Vec::with_capacity(len),
            field_name: <_>::default(),
        })
    }

    // We apply serde_json's handling of complex variants. That is,
    // the body is placed within a struct with one field, named the same thing as the variant.

    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        let mut s = self.serialize_struct(name, 1)?;
        SerializeStruct::serialize_field(&mut s, variant, value)?;
        SerializeStruct::end(s)
    }
    type SerializeTupleVariant = TupleVariantSerializer;
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Ok(TupleVariantSerializer {
            name: variant,
            seq_ser: SeqSerializer {
                elems: Vec::with_capacity(len),
            },
        })
    }
    type SerializeStructVariant = StructVariantSerializer;
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Ok(StructVariantSerializer {
            name: variant,
            struct_ser: StructSerializer {
                fields: Vec::with_capacity(len),
                field_name: <_>::default(),
            },
        })
    }

    // We opt into the binary encoding for Principal and other such types.
    fn is_human_readable(&self) -> bool {
        false
    }
    // Optimized version of serialize_str for types that serialize by rendering themselves to strings.
    fn collect_str<T: Display + ?Sized>(self, value: &T) -> Result<Self::Ok, Self::Error> {
        let mut hasher = Sha256::new();
        write!(hasher, "{value}").map_err(|e| RequestIdError::CustomSerdeError(format!("{e}")))?;
        Ok(Some(hasher.finalize().into()))
    }
}

struct StructSerializer {
    fields: Vec<(Sha256Hash, Sha256Hash)>,
    field_name: Sha256Hash,
}

// Structs are hashed by hashing each key-value pair, sorting them, concatenating them, and hashing the result.

impl SerializeStruct for StructSerializer {
    type Ok = Option<Sha256Hash>;
    type Error = RequestIdError;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        if let Some(hash) = value.serialize(RequestIdSerializer)? {
            self.fields
                .push((Sha256::digest(key.as_bytes()).into(), hash));
        }
        Ok(())
    }
    fn end(mut self) -> Result<Self::Ok, Self::Error> {
        self.fields.sort_unstable();
        let mut hasher = Sha256::new();
        for (key, value) in self.fields {
            hasher.update(key);
            hasher.update(value);
        }
        Ok(Some(hasher.finalize().into()))
    }
}

impl SerializeMap for StructSerializer {
    type Ok = Option<Sha256Hash>;
    type Error = RequestIdError;
    // This implementation naïvely assumes serialize_key is called before serialize_value, with no checks.
    // SerializeMap's documentation states that such a case is 'allowed to panic or produce bogus results.'
    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), Self::Error> {
        match key.serialize(RequestIdSerializer)? {
            Some(hash) => {
                self.field_name = hash;
                Ok(())
            }
            None => Err(RequestIdError::KeyWasNone),
        }
    }
    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        if let Some(hash) = value.serialize(RequestIdSerializer)? {
            self.fields.push((self.field_name, hash));
        }
        Ok(())
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        SerializeStruct::end(self)
    }
}

struct SeqSerializer {
    elems: Vec<Sha256Hash>,
}

// Sequences are hashed by hashing each element, concatenating the hashes, and hashing the result.

impl SerializeSeq for SeqSerializer {
    type Ok = Option<Sha256Hash>;
    type Error = RequestIdError;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        if let Some(hash) = value.serialize(RequestIdSerializer)? {
            self.elems.push(hash);
        }
        Ok(())
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        let mut hasher = Sha256::new();
        for elem in self.elems {
            hasher.update(elem);
        }
        Ok(Some(hasher.finalize().into()))
    }
}

impl SerializeTuple for SeqSerializer {
    type Ok = Option<Sha256Hash>;
    type Error = RequestIdError;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        SerializeSeq::serialize_element(self, value)
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        SerializeSeq::end(self)
    }
}

impl SerializeTupleStruct for SeqSerializer {
    type Ok = Option<Sha256Hash>;
    type Error = RequestIdError;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        SerializeSeq::serialize_element(self, value)
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        SerializeSeq::end(self)
    }
}

struct StructVariantSerializer {
    name: &'static str,
    struct_ser: StructSerializer,
}

// Struct variants are serialized like structs, but then placed within another struct
// under a key corresponding to the variant name.

impl SerializeStructVariant for StructVariantSerializer {
    type Ok = Option<Sha256Hash>;
    type Error = RequestIdError;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        SerializeStruct::serialize_field(&mut self.struct_ser, key, value)
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        let Some(inner_struct_hash) = SerializeStruct::end(self.struct_ser)? else {
            return Ok(None);
        };
        let outer_struct = StructSerializer {
            field_name: <_>::default(),
            fields: vec![(Sha256::digest(self.name).into(), inner_struct_hash)],
        };
        SerializeStruct::end(outer_struct)
    }
}

struct TupleVariantSerializer {
    name: &'static str,
    seq_ser: SeqSerializer,
}

// Tuple variants are serialized like tuples, but then placed within another struct
// under a key corresponding to the variant name.

impl SerializeTupleVariant for TupleVariantSerializer {
    type Ok = Option<Sha256Hash>;
    type Error = RequestIdError;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        SerializeSeq::serialize_element(&mut self.seq_ser, value)
    }
    fn end(self) -> Result<Self::Ok, Self::Error> {
        let Some(inner_seq_hash) = SerializeSeq::end(self.seq_ser)? else {
            return Ok(None);
        };
        let outer_struct = StructSerializer {
            field_name: <_>::default(),
            fields: vec![(Sha256::digest(self.name).into(), inner_seq_hash)],
        };
        SerializeStruct::end(outer_struct)
    }
}

// can't use serde_bytes on by-value arrays
// these impls are effectively #[serde(with = "serde_bytes")]
impl Serialize for RequestId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let mut text = [0u8; 64];
            hex::encode_to_slice(self.0, &mut text).unwrap();
            serializer.serialize_str(std::str::from_utf8(&text).unwrap())
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for RequestId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(RequestIdVisitor)
        } else {
            deserializer.deserialize_bytes(RequestIdVisitor)
        }
    }
}

struct RequestIdVisitor;

impl<'de> Visitor<'de> for RequestIdVisitor {
    type Value = RequestId;
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a sha256 hash")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(RequestId::new(v.try_into().map_err(|_| {
            E::custom(format_args!("must be 32 bytes long, was {}", v.len()))
        })?))
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut arr = Sha256Hash::default();
        for (i, byte) in arr.iter_mut().enumerate() {
            *byte = seq.next_element()?.ok_or(A::Error::custom(format_args!(
                "must be 32 bytes long, was {}",
                i - 1
            )))?;
        }
        if seq.next_element::<u8>()?.is_some() {
            Err(A::Error::custom("must be 32 bytes long, was more"))
        } else {
            Ok(RequestId(arr))
        }
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if v.len() != 64 {
            return Err(E::custom(format_args!(
                "must be 32 bytes long, was {}",
                v.len() / 2
            )));
        }
        let mut arr = Sha256Hash::default();
        hex::decode_to_slice(v, &mut arr).map_err(E::custom)?;
        Ok(RequestId(arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid::Principal;
    use std::{collections::HashMap, convert::TryFrom};

    /// The actual example used in the public spec in the Request ID section.
    #[test]
    fn public_spec_example_old() {
        #[derive(Serialize)]
        struct PublicSpecExampleStruct {
            request_type: &'static str,
            canister_id: Principal,
            method_name: &'static str,
            #[serde(with = "serde_bytes")]
            arg: &'static [u8],
            sender: Option<Principal>,
            ingress_expiry: Option<u64>,
        }
        // The current example
        let current = PublicSpecExampleStruct {
            request_type: "call",
            sender: Some(Principal::anonymous()),
            ingress_expiry: Some(1_685_570_400_000_000_000),
            canister_id: Principal::from_slice(b"\x00\x00\x00\x00\x00\x00\x04\xD2"),
            method_name: "hello",
            arg: b"DIDL\x00\xFD*",
        };

        // Hash taken from the example on the public spec.
        let request_id = to_request_id(&current).unwrap();
        assert_eq!(
            hex::encode(request_id.0),
            "1d1091364d6bb8a6c16b203ee75467d59ead468f523eb058880ae8ec80e2b101"
        );

        // A previous example
        let old = PublicSpecExampleStruct {
            request_type: "call",
            canister_id: Principal::from_slice(b"\x00\x00\x00\x00\x00\x00\x04\xD2"), // 1234 in u64
            method_name: "hello",
            arg: b"DIDL\x00\xFD*",
            ingress_expiry: None,
            sender: None,
        };

        let request_id = to_request_id(&old).unwrap();
        assert_eq!(
            hex::encode(request_id.0),
            "8781291c347db32a9d8c10eb62b710fce5a93be676474c42babc74c51858f94b"
        );
    }

    /// The same example as above, except we use the `ApiClient` enum newtypes.
    #[test]
    fn public_spec_example_api_client() {
        #[derive(Serialize)]
        #[serde(rename_all = "snake_case")]
        #[serde(tag = "request_type")]
        enum PublicSpec {
            Call {
                canister_id: Principal,
                method_name: String,
                #[serde(with = "serde_bytes")]
                arg: Option<Vec<u8>>,
                sender: Option<Principal>,
                ingress_expiry: Option<u64>,
            },
        }
        let current = PublicSpec::Call {
            sender: Some(Principal::anonymous()),
            ingress_expiry: Some(1_685_570_400_000_000_000),
            canister_id: Principal::from_slice(b"\x00\x00\x00\x00\x00\x00\x04\xD2"),
            method_name: "hello".to_owned(),
            arg: Some(b"DIDL\x00\xFD*".to_vec()),
        };
        // Hash taken from the example on the public spec.
        let request_id = to_request_id(&current).unwrap();
        assert_eq!(
            hex::encode(request_id.0),
            "1d1091364d6bb8a6c16b203ee75467d59ead468f523eb058880ae8ec80e2b101"
        );

        let old = PublicSpec::Call {
            canister_id: Principal::from_slice(b"\x00\x00\x00\x00\x00\x00\x04\xD2"), // 1234 in u64
            method_name: "hello".to_owned(),
            arg: Some(b"DIDL\x00\xFD*".to_vec()),
            ingress_expiry: None,
            sender: None,
        };
        let request_id = to_request_id(&old).unwrap();
        assert_eq!(
            hex::encode(request_id.0),
            "8781291c347db32a9d8c10eb62b710fce5a93be676474c42babc74c51858f94b"
        );
    }

    /// A simple example with nested arrays and blobs
    #[test]
    #[allow(clippy::string_lit_as_bytes)]
    fn array_example() {
        #[derive(Serialize)]
        struct NestedArraysExample {
            sender: Principal,
            paths: Vec<Vec<serde_bytes::ByteBuf>>,
        }
        let data = NestedArraysExample {
            sender: Principal::try_from(&vec![0, 0, 0, 0, 0, 0, 0x04, 0xD2]).unwrap(), // 1234 in u64
            paths: vec![
                vec![],
                vec![serde_bytes::ByteBuf::from("".as_bytes())],
                vec![
                    serde_bytes::ByteBuf::from("hello".as_bytes()),
                    serde_bytes::ByteBuf::from("world".as_bytes()),
                ],
            ],
        };

        let request_id = to_request_id(&data).unwrap();
        assert_eq!(
            hex::encode(request_id.0),
            "97d6f297aea699aec85d3377c7643ea66db810aba5c4372fbc2082c999f452dc"
        );

        /* The above was generated using ic-ref as follows:

        ~/dfinity/ic-ref/impl $ cabal repl ic-ref
        Build profile: -w ghc-8.8.4 -O1
        …
        *Main> :set -XOverloadedStrings
        *Main> :m + IC.HTTP.RequestId IC.HTTP.GenR
        *Main IC.HTTP.RequestId IC.HTTP.GenR> import qualified Data.HashMap.Lazy as HM
        *Main IC.HTTP.RequestId IC.HTTP.GenR HM> let input = GRec (HM.fromList [("sender", GBlob "\0\0\0\0\0\0\x04\xD2"), ("paths", GList [ GList [], GList [GBlob ""], GList [GBlob "hello", GBlob "world"]])])
        *Main IC.HTTP.RequestId IC.HTTP.GenR HM> putStrLn $ IC.Types.prettyBlob (requestId input )
        0x97d6f297aea699aec85d3377c7643ea66db810aba5c4372fbc2082c999f452dc
        */
    }

    /// A simple example with just an empty array
    #[test]
    fn array_example_empty_array() {
        #[derive(Serialize)]
        struct NestedArraysExample {
            paths: Vec<Vec<serde_bytes::ByteBuf>>,
        }
        let data = NestedArraysExample { paths: vec![] };

        let request_id = to_request_id(&data).unwrap();
        assert_eq!(
            hex::encode(request_id.0),
            "99daa8c80a61e87ac1fdf9dd49e39963bfe4dafb2a45095ebf4cad72d916d5be"
        );

        /* The above was generated using ic-ref as follows:

        ~/dfinity/ic-ref/impl $ cabal repl ic-ref
        Build profile: -w ghc-8.8.4 -O1
        …
        *Main> :set -XOverloadedStrings
        *Main> :m + IC.HTTP.RequestId IC.HTTP.GenR
        *Main IC.HTTP.RequestId IC.HTTP.GenR> import qualified Data.HashMap as HM
        *Main IC.HTTP.RequestId IC.HTTP.GenR HM> let input = GRec (HM.fromList [("paths", GList [])])
        *Main IC.HTTP.RequestId IC.HTTP.GenR HM> putStrLn $ IC.Types.prettyBlob (requestId input )
        0x99daa8c80a61e87ac1fdf9dd49e39963bfe4dafb2a45095ebf4cad72d916d5be
        */
    }

    /// A simple example with an array that holds an empty array
    #[test]
    fn array_example_array_with_empty_array() {
        #[derive(Serialize)]
        struct NestedArraysExample {
            paths: Vec<Vec<serde_bytes::ByteBuf>>,
        }
        let data = NestedArraysExample {
            paths: vec![vec![]],
        };

        let request_id = to_request_id(&data).unwrap();
        assert_eq!(
            hex::encode(request_id.0),
            "ea01a9c3d3830db108e0a87995ea0d4183dc9c6e51324e9818fced5c57aa64f5"
        );

        /* The above was generated using ic-ref as follows:

        ~/dfinity/ic-ref/impl $ cabal repl ic-ref
        Build profile: -w ghc-8.8.4 -O1
        …
        *Main> :set -XOverloadedStrings
        *Main> :m + IC.HTTP.RequestId IC.HTTP.GenR
        *Main IC.HTTP.RequestId IC.HTTP.GenR> import qualified Data.HashMap.Lazy as HM
        *Main IC.HTTP.RequestId IC.HTTP.GenR HM> let input = GRec (HM.fromList [("paths", GList [ GList [] ])])
        *Main IC.HTTP.RequestId IC.HTTP.GenR HM> putStrLn $ IC.Types.prettyBlob (requestId input )
        0xea01a9c3d3830db108e0a87995ea0d4183dc9c6e51324e9818fced5c57aa64f5
        */
    }

    #[test]
    fn nested_map() {
        #[derive(Serialize)]
        struct Outer {
            foo: Inner,
            #[serde(with = "serde_bytes")]
            bar: &'static [u8],
        }
        #[derive(Serialize)]
        struct Inner {
            baz: &'static str,
            quux: u64,
        }
        let outer = Outer {
            foo: Inner {
                baz: "hello",
                quux: 3,
            },
            bar: b"world",
        };
        assert_eq!(
            hex::encode(to_request_id(&outer).unwrap().0),
            "3d447339cc0c2b894ee215c8141770bf4b86c72b6c37d9873213a786ec7f9f31"
        );
    }

    #[test]
    fn structural_equivalence_collections() {
        #[derive(Serialize)]
        struct Maplike {
            foo: i32,
        }
        let hashed_struct = to_request_id(&Maplike { foo: 73 }).unwrap();
        assert_eq!(
            hashed_struct,
            to_request_id(&HashMap::from([("foo", 73_i32)])).unwrap(),
            "map hashed identically to struct"
        );

        assert_eq!(
            hex::encode(&hashed_struct[..]),
            "7b3d327026e6bb5b4c13b898a6ca8fff6fd6838f44f6c27d9adf34542add75a0"
        );

        #[derive(Serialize)]
        struct Seqlike(u8, u8, u8);
        let hashed_array = to_request_id(&[1, 2, 3]).unwrap();
        assert_eq!(
            hashed_array,
            to_request_id(&Seqlike(1, 2, 3)).unwrap(),
            "tuple struct hashed identically to array"
        );
        assert_eq!(
            hashed_array,
            to_request_id(&(1, 2, 3)).unwrap(),
            "tuple hashed identically to array"
        );
        assert_eq!(
            hex::encode(&hashed_array[..]),
            "2628a7cbda257cd0dc45779e43080e0a93037468fe270faae515f7c7941069e3"
        );
    }

    #[test]
    fn structural_equivalence_option() {
        #[derive(Serialize)]
        struct WithOpt {
            x: u64,
            y: Option<&'static str>,
        }

        #[derive(Serialize)]
        struct WithoutOptSome {
            x: u64,
            y: &'static str,
        }

        #[derive(Serialize)]
        struct WithoutOptNone {
            x: u64,
        }
        let without_some = to_request_id(&WithoutOptSome { x: 3, y: "hello" }).unwrap();
        assert_eq!(
            without_some,
            to_request_id(&WithOpt {
                x: 3,
                y: Some("hello")
            })
            .unwrap(),
            "Option::Some(x) hashed identically to x"
        );
        assert_eq!(
            hex::encode(&without_some[..]),
            "f9532efd31fe55f5013d84fa4e1585b9a52e6cf82842adabe22fd3ac359c4143"
        );
        let without_none = to_request_id(&WithoutOptNone { x: 7_000_000 }).unwrap();
        assert_eq!(
            without_none,
            to_request_id(&WithOpt {
                x: 7_000_000,
                y: None
            })
            .unwrap(),
            "Option::None field deleted from struct"
        );
        assert_eq!(
            hex::encode(&without_none[..]),
            "fe4c9222ee2bffbc3ff7f25510d5b258adfa38a16740050a112ccc98eb886de5"
        );
    }

    #[test]
    fn structural_equivalence_variant() {
        #[derive(Serialize)]
        #[serde(rename_all = "snake_case")]
        enum Complex {
            Newtype(u64),
            Tuple(&'static str, [u64; 2]),
            Struct {
                #[serde(with = "serde_bytes")]
                field: &'static [u8],
            },
        }
        #[derive(Serialize)]
        struct NewtypeWrapper {
            newtype: u64,
        }
        #[derive(Serialize)]
        struct TupleWrapper {
            tuple: (&'static str, [u64; 2]),
        }
        #[derive(Serialize)]
        struct Inner {
            #[serde(with = "serde_bytes")]
            field: &'static [u8],
        }
        #[derive(Serialize)]
        struct StructWrapper {
            r#struct: Inner,
        }
        let newtype = to_request_id(&NewtypeWrapper { newtype: 673 }).unwrap();
        assert_eq!(
            newtype,
            to_request_id(&Complex::Newtype(673)).unwrap(),
            "newtype variant serialized as field"
        );
        assert_eq!(
            hex::encode(&newtype[..]),
            "87371cb37e4a28512e898a691ccbd8cd33efb902a5ac9ecf3a73e5e97f9c23f8"
        );
        let tuple = to_request_id(&TupleWrapper {
            tuple: ("four", [5, 6]),
        })
        .unwrap();
        assert_eq!(
            tuple,
            to_request_id(&Complex::Tuple("four", [5, 6])).unwrap(),
            "tuple variant serialized as field"
        );
        assert_eq!(
            hex::encode(&tuple[..]),
            "729d2b57c442203f83b347ec644c8b38277076b5a9ebb3c2873ac64ddd793304"
        );
        let r#struct = to_request_id(&StructWrapper {
            r#struct: Inner {
                field: b"\x0Aic-request",
            },
        })
        .unwrap();
        assert_eq!(
            r#struct,
            to_request_id(&Complex::Struct {
                field: b"\x0Aic-request"
            })
            .unwrap(),
            "struct variant serialized as field"
        );
        assert_eq!(
            hex::encode(&r#struct[..]),
            "c2b325a8f7633df8054e9bd538ac8d26dc85cba4ad542cdbfca7109e1a60cf0c"
        );
    }
}
