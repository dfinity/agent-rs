//! Error type for the RequestId calculation.
use thiserror::Error;

/// Errors from reading a RequestId from a string. This is not the same as
/// deserialization.
#[derive(Error, Debug)]
pub enum RequestIdFromStringError {
    #[error("Invalid string size: {0}. Must be even.")]
    InvalidSize(usize),

    #[error("Error while decoding hex: {0}")]
    FromHexError(hex::FromHexError),
}

/// An error during the calculation of the RequestId.
/// Since we use serde for serializing a data type into a hash, this has to support traits that
/// serde expects, such as Display
#[derive(Error, Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum RequestIdError {
    #[error("A custom error happened inside Serde: {0}")]
    CustomSerdeError(String),

    #[error("Need to provide data to serialize")]
    EmptySerializer,

    #[error("RequestId Serializer was in an invalid state")]
    InvalidState,

    #[error("RequestId does not support struct inside other structs")]
    UnsupportedStructInsideStruct,

    #[error("Unsupported type: Bool")]
    UnsupportedTypeBool,
    #[error("Unsupported type: U8")]
    UnsupportedTypeU8,
    #[error("Unsupported type: U16")]
    UnsupportedTypeU16,
    #[error("Unsupported type: U32")]
    UnsupportedTypeU32,
    #[error("Unsupported type: U64")]
    UnsupportedTypeU64,
    #[error("Unsupported type: U128")]
    UnsupportedTypeU128,
    #[error("Unsupported type: I8")]
    UnsupportedTypeI8,
    #[error("Unsupported type: I16")]
    UnsupportedTypeI16,
    #[error("Unsupported type: I32")]
    UnsupportedTypeI32,
    #[error("Unsupported type: I64")]
    UnsupportedTypeI64,
    #[error("Unsupported type: I128")]
    UnsupportedTypeI128,
    #[error("Unsupported type: F32")]
    UnsupportedTypeF32,
    #[error("Unsupported type: F64")]
    UnsupportedTypeF64,
    #[error("Unsupported type: Char")]
    UnsupportedTypeChar,
    // UnsupportedTypeStr, // Supported
    #[error("Unsupported type: Bytes")]
    UnsupportedTypeBytes,
    // UnsupportedTypeNone, // Supported
    // UnsupportedTypeSome, // Supported
    #[error("Unsupported type: Unit")]
    UnsupportedTypeUnit,
    #[error("Unsupported type: PhantomData")]
    UnsupportedTypePhantomData,

    // Variants and complex types.
    #[error("Unsupported type: UnitVariant")]
    UnsupportedTypeUnitVariant,
    #[error("Unsupported type: NewtypeStruct")]
    UnsupportedTypeNewtypeStruct(String),
    #[error("Unsupported type: NewTypeVariant")]
    UnsupportedTypeNewTypeVariant,
    #[error("Unsupported type: Sequence")]
    UnsupportedTypeSequence,
    #[error("Unsupported type: Tuple")]
    UnsupportedTypeTuple,
    #[error("Unsupported type: TupleStruct")]
    UnsupportedTypeTupleStruct,
    #[error("Unsupported type: TupleVariant")]
    UnsupportedTypeTupleVariant,
    #[error("Unsupported type: Map")]
    UnsupportedTypeMap,
    // UnsupportedTypeStruct, // Supported
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
