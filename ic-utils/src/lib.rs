//! ic-utils is a collection of utilities to help build clients and canisters running
//! on the Internet Computer. It is meant as a higher level tool.

/// Utilities to encapsulate calls to a canister.
pub mod call;
pub mod canister;
pub mod canisters;

pub use canister::Canister;
