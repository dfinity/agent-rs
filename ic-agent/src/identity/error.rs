use ic_transport_types::Delegation;
use thiserror::Error;

/// An error happened while reading a PEM file.
#[cfg(feature = "pem")]
#[derive(Error, Debug)]
pub enum PemError {
    /// An error occurred with disk I/O.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// An unsupported curve was detected
    #[error("Only {0} curve is supported: {1:?}")]
    UnsupportedKeyCurve(String, Vec<u8>),

    /// An error occurred while reading the file in PEM format.
    #[cfg(feature = "pem")]
    #[error("An error occurred while reading the file: {0}")]
    PemError(#[from] pem::PemError),

    /// An error occurred while reading the file in DER format.
    #[cfg(feature = "pem")]
    #[error("An error occurred while reading the file: {0}")]
    DerError(#[from] der::Error),

    /// The Private Key is invalid.
    #[error("Invalid Private Key: {0}")]
    InvalidPrivateKey(String),

    /// The key was rejected by k256.
    #[error("A key was rejected by k256: {0}")]
    ErrorStack(#[from] k256::pkcs8::Error),
}

/// An error occurred constructing a [`DelegatedIdentity`](super::delegated::DelegatedIdentity).
#[derive(Error, Debug)]
pub enum DelegationError {
    /// Parsing error in delegation bytes.
    #[error("A delegation could not be parsed")]
    Parse,
    /// A key in the chain did not match the signature of the next chain link.
    #[error("A link was missing in the delegation chain")]
    BrokenChain {
        /// The key that should have matched the next delegation
        from: Vec<u8>,
        /// The delegation that didn't match, or `None` if the `Identity` didn't match
        to: Option<Delegation>,
    },
    /// A key with an unknown algorithm was used. The IC supports Ed25519, secp256k1, and prime256v1, and in ECDSA the curve must be specified.
    #[error("The delegation chain contained a key with an unknown algorithm")]
    UnknownAlgorithm,
    /// One of `Identity`'s functions returned an error.
    #[error("A delegated-to identity encountered an error: {0}")]
    IdentityError(String),
}
