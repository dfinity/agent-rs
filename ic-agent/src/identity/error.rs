#![cfg(feature = "pem")]

use thiserror::Error;

/// An error happened while reading a PEM file.
#[derive(Error, Debug)]
pub enum PemError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[cfg(feature = "pem")]
    #[error("An error occurred while reading the file: {0}")]
    PemError(#[from] pem::PemError),

    #[cfg(feature = "std")]
    #[error("A key was rejected by Ring: {0}")]
    KeyRejected(#[from] ring::error::KeyRejected),

    #[cfg(feature = "std")]
    #[error("A key was rejected by OpenSSL: {0}")]
    ErrorStack(#[from] openssl::error::ErrorStack),
}
