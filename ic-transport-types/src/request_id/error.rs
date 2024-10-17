//! Error type for the `RequestId` calculation.
use thiserror::Error;

/// Errors from reading a `RequestId` from a string. This is not the same as
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

/// An error during the calculation of the `RequestId`.
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
    /// A map was serialized with a key of `None`.
    #[error("Struct serializer received a key of None")]
    KeyWasNone,
    /// The serializer received a `bool`, which it does not support.
    #[error("Unsupported type: Bool")]
    UnsupportedTypeBool,
    /// The serializer received a `f32`, which it does not support.
    #[error("Unsupported type: f32")]
    UnsupportedTypeF32,
    /// The serializer received a `f64`, which it does not support.
    #[error("Unsupported type: f64")]
    UnsupportedTypeF64,
    /// The serializer received a `()`, which it does not support.
    #[error("Unsupported type: ()")]
    UnsupportedTypeUnit,
    // Variants and complex types.
    /// The serializer received an enum unit variant, which it does not support.
    #[error("Unsupported type: unit struct")]
    UnsupportedTypeUnitStruct,
}

impl serde::ser::Error for RequestIdError {
    fn custom<T>(msg: T) -> Self
    where
        T: std::fmt::Display,
    {
        RequestIdError::CustomSerdeError(msg.to_string())
    }
}
