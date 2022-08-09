//! [super::ReplicaV2Transport] implementations.

#[cfg(feature = "reqwest")]
pub mod reqwest_transport;

#[cfg(feature = "reqwest")]
pub use reqwest_transport::*;

#[cfg(feature = "hyper")]
pub mod hyper_transport;

#[cfg(feature = "hyper")]
pub use hyper_transport::*;

const IC0_DOMAIN: &str = "ic0.app";
const IC0_SUB_DOMAIN: &str = ".ic0.app";
