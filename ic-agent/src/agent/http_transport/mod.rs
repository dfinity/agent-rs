//! This module has been deprecated in favor of builder methods on `AgentBuilder`.

#[deprecated(since = "0.38.0", note = "use the AgentBuilder methods")]
#[doc(hidden)]
pub mod reqwest_transport;
#[doc(hidden)]
#[allow(deprecated)]
pub use reqwest_transport::ReqwestTransport;
