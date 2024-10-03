use ic_transport_types::Delegation;
use thiserror::Error;

/// An error happened while reading a PEM file.
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

    /// The key was rejected by Ring.
    #[error("A key was rejected by Ring: {0}")]
    KeyRejected(#[from] ring::error::KeyRejected),

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
    /// A key in the chain did not match the signature of the next chain link. If `to` is `None` then it refers to the `Identity`.
    #[error("A link was missing in the delegation chain")]
    BrokenChain {
        from: Vec<u8>,
        to: Option<Delegation>,
    },
    /// A key with an unknown algorithm was used. The IC supports Ed25519, secp256k1, and prime256v1, and in ECDSA the curve must be specified.
    #[error("The delegation chain contained a key with an unknown algorithm")]
    UnknownAlgorithm,
    /// One of `Identity`'s functions returned an error.
    #[error("A delegated-to identity encountered an error: {0}")]
    IdentityError(String),
}
