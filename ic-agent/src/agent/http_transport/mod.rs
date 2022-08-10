//! [super::ReplicaV2Transport] implementations.

#[cfg(feature = "reqwest")]
pub mod reqwest_transport;

#[cfg(feature = "reqwest")]
pub use reqwest_transport::*;

#[cfg(feature = "hyper")]
pub mod hyper_transport;

#[cfg(feature = "hyper")]
pub use hyper_transport::*;

#[allow(dead_code)]
const IC0_DOMAIN: &str = "ic0.app";
#[allow(dead_code)]
const IC0_SUB_DOMAIN: &str = ".ic0.app";
