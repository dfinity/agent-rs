//! This module deals with computing Request IDs based on the content of a
//! message.
//!
//! We compute the `RequestId` according to the public spec, which
//! specifies it as a "sha256" digest.
//!
//! A single method is exported, to_request_id, which returns a RequestId
//! (a 256 bits slice) or an error.
use error::RequestIdFromStringError;
use openssl::sha::Sha256;
use serde::{ser, Deserialize, Serialize};
use std::{collections::BTreeMap, iter::Extend, str::FromStr};

pub mod error;
pub use error::RequestIdError;

/// Type alias for a sha256 result (ie. a u256).
type Sha256Hash = [u8; 32];

/// A Request ID.
#[derive(Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq, Deserialize, Serialize)]
pub struct RequestId(Sha256Hash);

impl RequestId {
    pub fn new(from: &[u8; 32]) -> RequestId {
        RequestId(*from)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
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

enum Hasher {
    /// The hasher for the overall request id.  This is the only part
    /// that may directly contain a Struct.
    RequestId(Sha256),

    /// A structure to be included in the hash.  May not contain other structures.
    Struct {
        // We use a BTreeMap here as there is no indication that keys might not be duplicated,
        // and we want to make sure they're overwritten in that case.
        fields: BTreeMap<Sha256Hash, Sha256Hash>,
        parent: Box<Hasher>,
    },

    /// The hasher for a value.  Array elements will append the hash of their
    /// contents into the hasher of the array.
    Value(Sha256),
}

impl Hasher {
    fn request_id() -> Hasher {
        Hasher::RequestId(Sha256::new())
    }

    fn fields(parent: Box<Hasher>) -> Hasher {
        Hasher::Struct {
            fields: BTreeMap::new(),
            parent,
        }
    }

    fn value() -> Hasher {
        Hasher::Value(Sha256::new())
    }
}

/// A Serde Serializer that collects fields and values in order to hash them later.
/// We serialize the type to this structure, then use the trait to hash its content.
/// It is a simple state machine that contains 3 states:
///   1. The root value, which is a structure. If a value other than a structure is
///      serialized, this errors. This is determined by whether `fields` is Some(_).
///   2. The structure is being processed, and the value of a field is being
///      serialized. The field_value_hash will be set to Some(_).
///   3. The finish() function has been called and the hasher cannot be reused. The
///      hash should have been gotten at this point.
///
/// Inconsistent state are when a field is being serialized and `fields` is None, or
/// when a value (not struct) is being serialized and field_value_hash is None.
///
/// This will always fail on types that are unknown to the Request format (e.g. i8).
/// An UnsupportedTypeXXX error will be returned.
///
/// The only types that are supported right now are:
///   . Strings and string slices.
///   . Vector of u8 (byte strings).
///   . A structure as the base level. Its typename and fields are not validated.
///
/// Additionally, this will fail if there are unsupported data structure, for example
/// if a UnitVariant of another type than Blob is used, or a structure inside a
/// structure.
///
/// This does not validate whether a message is valid. This is very important as
/// the message format might change faster than the ID calculation.
struct RequestIdSerializer {
    element_encoder: Option<Hasher>,
}

impl RequestIdSerializer {
    pub fn new() -> RequestIdSerializer {
        Default::default()
    }

    /// Finish the hashing and returns the RequestId for the structure that was
    /// serialized.
    ///
    /// This can only be called once (it borrows self). Since this whole class is not public,
    /// it should not be a problem.
    pub fn finish(self) -> Result<RequestId, RequestIdError> {
        match self.element_encoder {
            Some(Hasher::RequestId(hasher)) => Ok(RequestId(hasher.finish())),
            _ => Err(RequestIdError::EmptySerializer),
        }
    }

    /// Hash a single value, returning its sha256_hash. If there is already a value
    /// being hashed it will return an InvalidState. This cannot happen currently
    /// as we don't allow embedded structures, but is left as a safeguard when
    /// making changes.
    fn hash_value<T>(&mut self, value: &T) -> Result<Sha256Hash, RequestIdError>
    where
        T: ?Sized + Serialize,
    {
        let prev_encoder = self.element_encoder.take();

        self.element_encoder = Some(Hasher::value());

        value.serialize(&mut *self)?;
        let result = match self.element_encoder.take() {
            Some(Hasher::Value(hasher)) => Ok(hasher.finish()),
            _ => Err(RequestIdError::InvalidState),
        };
        self.element_encoder = prev_encoder;
        result
    }

    fn hash_fields(&mut self) -> Result<(), RequestIdError> {
        match self.element_encoder.take() {
            Some(Hasher::Struct { fields, parent }) => {
                // Sort the fields.
                let mut keyvalues: Vec<Vec<u8>> = fields
                    .keys()
                    .zip(fields.values())
                    .map(|(k, v)| {
                        let mut x = k.to_vec();
                        x.extend(v);
                        x
                    })
                    .collect();
                keyvalues.sort();

                let mut parent = *parent;

                match &mut parent {
                    Hasher::RequestId(hasher) => {
                        for kv in keyvalues {
                            hasher.update(&kv);
                        }
                        Ok(())
                    }
                    _ => Err(RequestIdError::InvalidState),
                }?;

                self.element_encoder = Some(parent);
                Ok(())
            }
            _ => Err(RequestIdError::InvalidState),
        }
    }
}

impl Default for RequestIdSerializer {
    fn default() -> RequestIdSerializer {
        RequestIdSerializer {
            element_encoder: Some(Hasher::request_id()),
        }
    }
}

/// See https://serde.rs/data-format.html for more information on how to implement a
/// custom data format.
impl<'a> ser::Serializer for &'a mut RequestIdSerializer {
    /// The output type produced by this `Serializer` during successful
    /// serialization. Most serializers that produce text or binary output
    /// should set `Ok = ()` and serialize into an [`io::Write`] or buffer
    /// contained within the `Serializer` instance. Serializers that build
    /// in-memory data structures may be simplified by using `Ok` to propagate
    /// the data structure around.
    ///
    /// [`io::Write`]: https://doc.rust-lang.org/std/io/trait.Write.html
    type Ok = ();

    /// The error type when some error occurs during serialization.
    type Error = RequestIdError;

    // Associated types for keeping track of additional state while serializing
    // compound data structures like sequences and maps. In this case no
    // additional state is required beyond what is already stored in the
    // Serializer struct.
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    /// Serialize a `bool` value.
    fn serialize_bool(self, _v: bool) -> Result<Self::Ok, Self::Error> {
        Err(RequestIdError::UnsupportedTypeBool)
    }

    /// Serialize an `i8` value.
    fn serialize_i8(self, _v: i8) -> Result<Self::Ok, Self::Error> {
        Err(RequestIdError::UnsupportedTypeI8)
    }

    /// Serialize an `i16` value.
    fn serialize_i16(self, _v: i16) -> Result<Self::Ok, Self::Error> {
        Err(RequestIdError::UnsupportedTypeI16)
    }

    /// Serialize an `i32` value.
    fn serialize_i32(self, _v: i32) -> Result<Self::Ok, Self::Error> {
        Err(RequestIdError::UnsupportedTypeI32)
    }

    /// Serialize an `i64` value.
    fn serialize_i64(self, _v: i64) -> Result<Self::Ok, Self::Error> {
        Err(RequestIdError::UnsupportedTypeI64)
    }

    /// Serialize a `u8` value.
    fn serialize_u8(self, v: u8) -> Result<Self::Ok, Self::Error> {
        self.serialize_u64(v as u64)
    }

    /// Serialize a `u16` value.
    fn serialize_u16(self, v: u16) -> Result<Self::Ok, Self::Error> {
        self.serialize_u64(v as u64)
    }

    /// Serialize a `u32` value.
    fn serialize_u32(self, v: u32) -> Result<Self::Ok, Self::Error> {
        self.serialize_u64(v as u64)
    }

    /// Serialize a `u64` value.
    fn serialize_u64(self, v: u64) -> Result<Self::Ok, Self::Error> {
        // 10 bytes is enough for a 64-bit number in leb128.
        let mut buffer = [0; 10];
        let mut writable = &mut buffer[..];
        let n_bytes =
            leb128::write::unsigned(&mut writable, v).expect("Could not serialize number.");
        self.serialize_bytes(&buffer[..n_bytes])
    }

    /// Serialize an `f32` value.
    fn serialize_f32(self, _v: f32) -> Result<Self::Ok, Self::Error> {
        Err(RequestIdError::UnsupportedTypeF32)
    }

    /// Serialize an `f64` value.
    fn serialize_f64(self, _v: f64) -> Result<Self::Ok, Self::Error> {
        Err(RequestIdError::UnsupportedTypeF64)
    }

    /// Serialize a character.
    fn serialize_char(self, _v: char) -> Result<Self::Ok, Self::Error> {
        Err(RequestIdError::UnsupportedTypeChar)
    }

    /// Serialize a `&str`.
    fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error> {
        self.serialize_bytes(v.as_bytes())
    }

    /// Serialize a chunk of raw byte data.
    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
        match &mut self.element_encoder {
            Some(Hasher::RequestId(hasher)) => {
                hasher.update(v);
                Ok(())
            }
            Some(Hasher::Value(hasher)) => {
                hasher.update(v);
                Ok(())
            }
            _ => Err(RequestIdError::InvalidState),
        }
    }

    /// Serialize a [`None`] value.
    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        // Compute the hash as if it was empty string or blob.
        Ok(())
    }

    /// Serialize a [`Some(T)`] value.
    fn serialize_some<T: ?Sized>(self, value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize,
    {
        // Compute the hash as if it was the value itself.
        value.serialize(self)
    }

    /// Serialize a `()` value.
    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Err(RequestIdError::UnsupportedTypeUnit)
    }

    /// Serialize a unit struct like `struct Unit` or `PhantomData<T>`.
    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        Err(RequestIdError::UnsupportedTypePhantomData)
    }

    /// Serialize a unit variant like `E::A` in `enum E { A, B }`.
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        Err(RequestIdError::UnsupportedTypeUnitVariant)
    }

    /// Serialize a newtype struct like `struct Millimeters(u8)`.
    fn serialize_newtype_struct<T: ?Sized>(
        self,
        name: &'static str,
        _value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize,
    {
        Err(RequestIdError::UnsupportedTypeNewtypeStruct(
            name.to_owned(),
        ))
    }

    /// Serialize a newtype variant like `E::N` in `enum E { N(u8) }`.
    fn serialize_newtype_variant<T: ?Sized>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: Serialize,
    {
        Err(RequestIdError::UnsupportedTypeNewTypeVariant)
    }

    /// Begin to serialize a variably sized sequence. This call must be
    /// followed by zero or more calls to `serialize_element`, then a call to
    /// `end`.
    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Ok(self)
    }

    /// Begin to serialize a statically sized sequence whose length will be
    /// known at deserialization time without looking at the serialized data.
    /// This call must be followed by zero or more calls to `serialize_element`,
    /// then a call to `end`.
    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Err(RequestIdError::UnsupportedTypeTuple)
    }

    /// Begin to serialize a tuple struct like `struct Rgb(u8, u8, u8)`. This
    /// call must be followed by zero or more calls to `serialize_field`, then a
    /// call to `end`.
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        Err(RequestIdError::UnsupportedTypeTupleStruct)
    }

    /// Begin to serialize a tuple variant like `E::T` in `enum E { T(u8, u8)
    /// }`. This call must be followed by zero or more calls to
    /// `serialize_field`, then a call to `end`.
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Err(RequestIdError::UnsupportedTypeTupleVariant)
    }

    /// Begin to serialize a map. This call must be followed by zero or more
    /// calls to `serialize_key` and `serialize_value`, then a call to `end`.
    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Err(RequestIdError::UnsupportedTypeMap)
    }

    /// Begin to serialize a struct like `struct Rgb { r: u8, g: u8, b: u8 }`.
    /// This call must be followed by zero or more calls to `serialize_field`,
    /// then a call to `end`.
    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        let parent_encoder = self.element_encoder.take();
        match &parent_encoder {
            Some(Hasher::RequestId(_)) => {
                self.element_encoder = Some(Hasher::fields(Box::new(parent_encoder.unwrap())));
                Ok(self)
            }
            _ => Err(RequestIdError::UnsupportedStructInsideStruct),
        }
    }

    /// Begin to serialize a struct variant like `E::S` in `enum E { S { r: u8,
    /// g: u8, b: u8 } }`. This call must be followed by zero or more calls to
    /// `serialize_field`, then a call to `end`.
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Err(RequestIdError::UnsupportedTypeStructVariant)
    }

    fn is_human_readable(&self) -> bool {
        false
    }
}

// The following 7 impls deal with the serialization of compound types like
// sequences and maps. Serialization of such types is begun by a Serializer
// method and followed by zero or more calls to serialize individual elements of
// the compound type and one call to end the compound type.
//
// This impl is SerializeSeq so these methods are called after `serialize_seq`
// is called on the Serializer.
impl<'a> ser::SerializeSeq for &'a mut RequestIdSerializer {
    // Must match the `Ok` type of the serializer.
    type Ok = ();
    // Must match the `Error` type of the serializer.
    type Error = RequestIdError;

    // Serialize a single element of the sequence.
    fn serialize_element<T>(&mut self, value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        let mut prev_encoder = self.element_encoder.take();

        self.element_encoder = Some(Hasher::value());

        value.serialize(&mut **self)?;

        let value_encoder = self.element_encoder.take();
        let hash = match value_encoder {
            Some(Hasher::Value(hasher)) => Ok(hasher.finish()),
            _ => Err(RequestIdError::InvalidState),
        }?;

        self.element_encoder = prev_encoder.take();
        match &mut self.element_encoder {
            Some(Hasher::Value(hasher)) => {
                hasher.update(&hash);
                Ok(())
            }
            _ => Err(RequestIdError::InvalidState),
        }
    }

    // Close the sequence.
    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

// Same thing but for tuples.
impl<'a> ser::SerializeTuple for &'a mut RequestIdSerializer {
    type Ok = ();
    type Error = RequestIdError;

    fn serialize_element<T>(&mut self, _value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        Err(RequestIdError::UnsupportedTypeTuple)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

// Same thing but for tuple structs.
impl<'a> ser::SerializeTupleStruct for &'a mut RequestIdSerializer {
    type Ok = ();
    type Error = RequestIdError;

    fn serialize_field<T>(&mut self, _value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        Err(RequestIdError::UnsupportedTypeTupleStruct)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

// Tuple variants are a little different. Refer back to the
// `serialize_tuple_variant` method above:
//
//    self.output += "{";
//    variant.serialize(&mut *self)?;
//    self.output += ":[";
//
// So the `end` method in this impl is responsible for closing both the `]` and
// the `}`.
impl<'a> ser::SerializeTupleVariant for &'a mut RequestIdSerializer {
    type Ok = ();
    type Error = RequestIdError;

    fn serialize_field<T>(&mut self, _value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        Err(RequestIdError::UnsupportedTypeTupleVariant)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

// Some `Serialize` types are not able to hold a key and value in memory at the
// same time so `SerializeMap` implementations are required to support
// `serialize_key` and `serialize_value` individually.
//
// There is a third optional method on the `SerializeMap` trait. The
// `serialize_entry` method allows serializers to optimize for the case where
// key and value are both available simultaneously. In JSON it doesn't make a
// difference so the default behavior for `serialize_entry` is fine.
impl<'a> ser::SerializeMap for &'a mut RequestIdSerializer {
    type Ok = ();
    type Error = RequestIdError;

    // The Serde data model allows map keys to be any serializable type. JSON
    // only allows string keys so the implementation below will produce invalid
    // JSON if the key serializes as something other than a string.
    //
    // A real JSON serializer would need to validate that map keys are strings.
    // This can be done by using a different Serializer to serialize the key
    // (instead of `&mut **self`) and having that other serializer only
    // implement `serialize_str` and return an error on any other data type.
    fn serialize_key<T>(&mut self, _key: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        Err(RequestIdError::UnsupportedTypeMap)
    }

    // It doesn't make a difference whether the colon is printed at the end of
    // `serialize_key` or at the beginning of `serialize_value`. In this case
    // the code is a bit simpler having it here.
    fn serialize_value<T>(&mut self, _value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        Err(RequestIdError::UnsupportedTypeMap)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.hash_fields()
    }
}

// Structs are like maps in which the keys are constrained to be compile-time
// constant strings.
impl<'a> ser::SerializeStruct for &'a mut RequestIdSerializer {
    type Ok = ();
    type Error = RequestIdError;

    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        let key_hash = self.hash_value(key)?;
        let value_hash = self.hash_value(value)?;
        match &mut self.element_encoder {
            Some(Hasher::Struct { fields, .. }) => {
                fields.insert(key_hash, value_hash);
                Ok(())
            }
            _ => Err(RequestIdError::InvalidState),
        }
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.hash_fields()
    }
}

// Similar to `SerializeTupleVariant`, here the `end` method is responsible for
// closing both of the curly braces opened by `serialize_struct_variant`.
impl<'a> ser::SerializeStructVariant for &'a mut RequestIdSerializer {
    type Ok = ();
    type Error = RequestIdError;

    fn serialize_field<T>(
        &mut self,
        _key: &'static str,
        _value: &T,
    ) -> Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        Err(RequestIdError::UnsupportedTypeStructVariant)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

/// Derive the request ID from a serializable data structure.
///
/// See https://hydra.dfinity.systems//build/268411/download/1/dfinity/spec/public/index.html#api-request-id
///
/// # Warnings
///
/// The argument type simply needs to be serializable; the function
/// does NOT sift between fields to include them or not and assumes
/// the passed value only includes fields that are not part of the
/// envelope and should be included in the calculation of the request
/// id.
///
/// # Panics
///
/// This function panics if the value provided is not a struct or a map.
pub fn to_request_id<'a, V>(value: &V) -> Result<RequestId, RequestIdError>
where
    V: 'a + Serialize,
{
    let mut serializer = RequestIdSerializer::new();
    value.serialize(&mut serializer)?;
    serializer.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export::Principal;
    use std::convert::TryFrom;

    /// The actual example used in the public spec in the Request ID section.
    #[test]
    fn public_spec_example() {
        #[derive(Serialize)]
        struct PublicSpecExampleStruct {
            request_type: &'static str,
            canister_id: Principal,
            method_name: &'static str,
            #[serde(with = "serde_bytes")]
            arg: Vec<u8>,
        }
        let data = PublicSpecExampleStruct {
            request_type: "call",
            canister_id: Principal::try_from(&vec![0, 0, 0, 0, 0, 0, 0x04, 0xD2]).unwrap(), // 1234 in u64
            method_name: "hello",
            arg: b"DIDL\x00\xFD*".to_vec(),
        };

        // Hash taken from the example on the public spec.
        let request_id = to_request_id(&data).unwrap();
        assert_eq!(
            hex::encode(request_id.0.to_vec()),
            "8781291c347db32a9d8c10eb62b710fce5a93be676474c42babc74c51858f94b"
        );
    }

    /// The same example as above, except we use the ApiClient enum newtypes.
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
            },
        }
        let data = PublicSpec::Call {
            canister_id: Principal::try_from(&vec![0, 0, 0, 0, 0, 0, 0x04, 0xD2]).unwrap(), // 1234 in u64
            method_name: "hello".to_owned(),
            arg: Some(b"DIDL\x00\xFD*".to_vec()),
        };

        // Hash taken from the example on the public spec.
        let request_id = to_request_id(&data).unwrap();
        assert_eq!(
            hex::encode(request_id.0.to_vec()),
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
            hex::encode(request_id.0.to_vec()),
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
            hex::encode(request_id.0.to_vec()),
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
            hex::encode(request_id.0.to_vec()),
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

    /// We do not support creating a request id from a map.
    /// It adds complexity, and isn't that useful anyway because a real request would
    /// have to have different kinds of values (strings, principals, arrays) and
    /// we don't support the wrappers that would be required to make that work
    /// with rust maps.
    #[test]
    fn maps_are_not_supported() {
        let mut data = BTreeMap::new();
        data.insert("request_type", "call");
        data.insert("canister_id", "a principal / the canister id");
        data.insert("method_name", "hello");
        data.insert("arg", "some argument value");

        let error = to_request_id(&data).unwrap_err();
        assert_eq!(error, RequestIdError::UnsupportedTypeMap);
    }
}
