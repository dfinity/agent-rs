#![cfg(feature = "pem")]

use thiserror::Error;

/// An error happened while reading a PEM file.
#[derive(Error, Debug)]
pub enum PemError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[cfg(feature = "pem")]
    #[error("An error occurred while reading the file")]
    PemError,

    #[error("A key was rejected: {0}")]
    KeyRejected(String),

    #[error("A key was rejected by OpenSSL: {0}")]
    ErrorStack(#[from] openssl::error::ErrorStack),
}
