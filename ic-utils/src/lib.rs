//! ic-utils is a collection of utilities to help build clients and canisters running
//! on the Internet Computer. It is meant as a higher level tool.

#![warn(
    missing_docs,
    missing_debug_implementations,
    rustdoc::broken_intra_doc_links,
    rustdoc::private_intra_doc_links
)]
#![cfg_attr(not(target_family = "wasm"), warn(clippy::future_not_send))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

/// Utilities to encapsulate calls to a canister.
pub mod call;
/// A higher-level canister type for managing various aspects of a canister.
pub mod canister;
/// A few known canister types for use with [`Canister`](canister::Canister).
pub mod interfaces;

pub use canister::{Argument, Canister};
