//! ic-utils is a collection of utilities to help build clients and canisters running
//! on the Internet Computer. It is meant as a higher level tool.

#![deny(
    missing_docs,
    missing_debug_implementations,
    rustdoc::broken_intra_doc_links,
    rustdoc::private_intra_doc_links
)]

/// Utilities to encapsulate calls to a canister.
pub mod call;
/// A higher-level canister type for managing various aspects of a canister.
pub mod canister;
/// A few known canister types for use with [`Canister`](canister::Canister).
pub mod interfaces;

pub use canister::{Argument, Canister};
