//! [`Transport`](super::Transport) implementations.

#[cfg(feature = "reqwest")]
pub mod reqwest_transport;

#[cfg(feature = "reqwest")]
#[doc(inline)]
pub use reqwest_transport::ReqwestTransport;
#[cfg(feature = "reqwest")]
#[doc(hidden)]
#[deprecated]
pub use reqwest_transport::*; // remove after 0.25

#[cfg(feature = "hyper")]
pub mod hyper_transport;

#[cfg(feature = "hyper")]
#[doc(inline)]
pub use hyper_transport::HyperTransport;
#[cfg(feature = "hyper")]
#[doc(hidden)]
#[deprecated]
pub use hyper_transport::*; // remove after 0.25

#[allow(dead_code)]
const IC0_DOMAIN: &str = "ic0.app";
#[allow(dead_code)]
const IC0_SUB_DOMAIN: &str = ".ic0.app";

pub mod route_provider;
