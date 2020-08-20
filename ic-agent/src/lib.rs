//! `ic-agent` is a simple to use library to interact with the
//! [Internet Computer](https://dfinity.org) in Rust. It is the backend for
//! [`dfx`](https://sdk.dfinity.org).
//!
//! ## About
//! `ic-agent` is a crate to talk directly to an ICP replica. It can handle multiple version
//! of the Replica API, and exposes with both low level and high level APIs (like talking to
//! canisters).
//!
//! ## Example
//! The following examples show how to use the `Agent` low-level API to send a call to the management
//! canister to create a new canister ID.
//!
//! ```rust
//! use ic_agent::{Agent, Principal};
//! use candid::{Encode, Decode, CandidType};
//! use serde::Deserialize;
//!
//! #[derive(CandidType, Deserialize)]
//! struct CreateCanisterResult {
//!   canister_id: candid::Principal,  // Temporarily, while waiting for Candid to use ic-types
//! }
//!
//! async fn create_a_canister() -> Result<Principal, Box<dyn std::error::Error>> {
//!   let agent = Agent::builder()
//!     .with_url("http://gw.dfinity.org")
//!     .build()?;
//!   let canister_id = Principal::from_text("aaaaa-aa")?;
//!
//!   let response = agent.update_raw(&canister_id, "create_canister", &Encode!()?).await?;
//!   let result = Decode!(response.as_slice(), CreateCanisterResult)?;
//!   let canister_id: Principal = Principal::from_text(&result.canister_id.to_text())?;
//!   Ok(canister_id)
//! }
//! ```
//!
//! See the Documentation for more information.
//!
//! ## References
//! The public specification of the Internet Computer is, at this moment, privately shared. When it
//! is made public a reference to the version(s) supported will be available here.
//!
mod agent;
pub use agent::public::*;

mod identity;
pub use identity::public::*;

mod types;
pub use types::public::*;

mod canister;
pub use canister::public::*;
