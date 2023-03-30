//! Error type for the RequestId calculation.
use thiserror::Error;

/// Errors from reading a RequestId from a string. This is not the same as
/// deserialization.
#[derive(Error, Debug)]
pub enum RequestIdFromStringError {
    /// The string was not of a valid length.
    #[error("Invalid string size: {0}. Must be even.")]
    InvalidSize(usize),

    /// The string was not in a valid hexadecimal format.
    #[error("Error while decoding hex: {0}")]
    FromHexError(hex::FromHexError),
}

/// An error during the calculation of the RequestId.
///
/// Since we use serde for serializing a data type into a hash, this has to support traits that
/// serde expects, such as Display
#[derive(Error, Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum RequestIdError {
    /// An unknown error occurred inside `serde`.
    #[error("A custom error happened inside Serde: {0}")]
    CustomSerdeError(String),
    /// The serializer was not given any data.
    #[error("Need to provide data to serialize")]
    EmptySerializer,
    /// The serializer was in an invalid state.
    #[error("RequestId Serializer was in an invalid state")]
    InvalidState,
    /// The serializer received a nested struct, which it does not support.
    #[error("RequestId does not support struct inside other structs")]
    UnsupportedStructInsideStruct,
    /// The serializer received a `bool`, which it does not support.
    #[error("Unsupported type: Bool")]
    UnsupportedTypeBool,
    /// The serializer received a `u8`, which it does not support.
    #[error("Unsupported type: U8")]
    UnsupportedTypeU8,
    /// The serializer received a `u16`, which it does not support.
    #[error("Unsupported type: U16")]
    UnsupportedTypeU16,
    /// The serializer received a `u32`, which it does not support.
    #[error("Unsupported type: U32")]
    UnsupportedTypeU32,
    /// The serializer received a `u64`, which it does not support.
    #[error("Unsupported type: U64")]
    UnsupportedTypeU64,
    /// The serializer received a `u128`, which it does not support.
    #[error("Unsupported type: U128")]
    UnsupportedTypeU128,
    /// The serializer received a `i8`, which it does not support.
    #[error("Unsupported type: I8")]
    UnsupportedTypeI8,
    /// The serializer received a `i16`, which it does not support.
    #[error("Unsupported type: I16")]
    UnsupportedTypeI16,
    /// The serializer received a `i32`, which it does not support.
    #[error("Unsupported type: I32")]
    UnsupportedTypeI32,
    /// The serializer received a `i64`, which it does not support.
    #[error("Unsupported type: I64")]
    UnsupportedTypeI64,
    /// The serializer received a `i128`, which it does not support.
    #[error("Unsupported type: I128")]
    UnsupportedTypeI128,
    /// The serializer received a `f32`, which it does not support.
    #[error("Unsupported type: F32")]
    UnsupportedTypeF32,
    /// The serializer received a `f64`, which it does not support.
    #[error("Unsupported type: F64")]
    UnsupportedTypeF64,
    /// The serializer received a `char`, which it does not support.
    #[error("Unsupported type: Char")]
    UnsupportedTypeChar,
    // UnsupportedTypeStr, // Supported
    /// The serializer received a byte sequence, which it does not support.
    #[error("Unsupported type: Bytes")]
    UnsupportedTypeBytes,
    // UnsupportedTypeNone, // Supported
    // UnsupportedTypeSome, // Supported
    /// The serializer received a `()`, which it does not support.
    #[error("Unsupported type: Unit")]
    UnsupportedTypeUnit,
    /// The serializer received a `PhantomData`, which it does not support.
    #[error("Unsupported type: PhantomData")]
    UnsupportedTypePhantomData,

    // Variants and complex types.
    /// The serializer received an enum unit variant, which it does not support.
    #[error("Unsupported type: UnitVariant")]
    UnsupportedTypeUnitVariant,
    /// The serializer received a newtype struct, which it does not support.
    #[error("Unsupported type: NewtypeStruct")]
    UnsupportedTypeNewtypeStruct(String),
    /// The serializer received an enum newtype variant, which it does not support.
    #[error("Unsupported type: NewTypeVariant")]
    UnsupportedTypeNewTypeVariant,
    /// The serializer received a sequence, which it does not support.
    #[error("Unsupported type: Sequence")]
    UnsupportedTypeSequence,
    /// The serializer received a tuple, which it does not support.
    #[error("Unsupported type: Tuple")]
    UnsupportedTypeTuple,
    /// The serializer received a tuple struct, which it does not support.
    #[error("Unsupported type: TupleStruct")]
    UnsupportedTypeTupleStruct,
    /// The serializer received an enum tuple variant, which it does not support.
    #[error("Unsupported type: TupleVariant")]
    UnsupportedTypeTupleVariant,
    /// The serializer received a map, which it does not support.
    #[error("Unsupported type: Map")]
    UnsupportedTypeMap,
    // UnsupportedTypeStruct, // Supported
    /// The serializer received an enum struct variant, which it does not support.
    #[error("Unsupported type: StructVariant")]
    UnsupportedTypeStructVariant,
}

impl serde::ser::Error for RequestIdError {
    fn custom<T>(msg: T) -> Self
    where
        T: std::fmt::Display,
    {
        RequestIdError::CustomSerdeError(msg.to_string())
    }
}
