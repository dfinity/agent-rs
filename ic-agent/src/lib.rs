//! The `ic-agent` is a simple-to-use library that enables you to
//! build applications and interact with the [Internet Computer](https://dfinity.org)
//! in Rust. It serves as a Rust-based low-level backend for the
//! DFINITY Canister Software Development Kit (SDK) and the
//! [Canister SDK](https://sdk.dfinity.org) command-line execution environment
//! [`dfx`](https://sdk.dfinity.org/docs/developers-guide/install-upgrade-remove.html#_what_gets_installed).
//!
//! ## Overview
//! The `ic-agent` is a Rust crate that can connect directly to the Internet
//! Computer through the Internet Computer protocol (ICP).
//! The key software components of the ICP are broadly referred to as the
//! [replica](https://sdk.dfinity.org/docs/developers-guide/introduction-key-concepts.html#_basic_architecture).
//!
//! The agent is designed to be compatible with multiple versions of the
//! replica API, and to expose both low-level APIs for communicating with
//! Internet Computer protocol components like the replica and to provide
//! higher-level APIs for communicating with software applications deployed
//! as [canisters](https://sdk.dfinity.org/docs/developers-guide/introduction-key-concepts.html#_writing_deploying_and_running_software).
//!
//! ## Example
//! The following example illustrates how to use the Agent interface to send
//! a call to an Internet Computer canister that performs network management
//! operations. In this example, the call to the Internet Computer management
//! canister (`aaaaa-aa`) creates a placeholder for a new canister by
//! registering a network-specific identifier. The management canister then
//! returns the result in the form of the textual representation of the canister
//! identifier to the caller.
//!
//! ```ignore
//! # // This test is ignored because it requires an ic to be running. We run these
//! # // in the ic-ref workflow.
//! use ic_agent::{Agent, export::Principal};
//! use candid::{Encode, Decode, CandidType, Nat};
//! use serde::Deserialize;
//!
//! #[derive(CandidType)]
//! struct Argument {
//!   amount: Option<Nat>,
//! }
//!
//! #[derive(CandidType, Deserialize)]
//! struct CreateCanisterResult {
//!   canister_id: Principal,
//! }
//!
//! # fn create_identity() -> impl ic_agent::Identity {
//! #     let rng = ring::rand::SystemRandom::new();
//! #     let key_pair = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
//! #         .expect("Could not generate a key pair.");
//! #
//! #     ic_agent::identity::BasicIdentity::from_key_pair(
//! #         ring::signature::Ed25519KeyPair::from_pkcs8(key_pair.as_ref())
//! #           .expect("Could not read the key pair."),
//! #     )
//! # }
//! #
//! # const URL: &'static str = concat!("http://localhost:", env!("IC_REF_PORT"));
//! #
//! async fn create_a_canister() -> Result<Principal, Box<dyn std::error::Error>> {
//!   let agent = Agent::builder()
//!     .with_url(URL)
//!     .with_identity(create_identity())
//!     .build()?;
//!   // Only do the following call when not contacting the IC main net (e.g. a local emulator).
//!   // This is important as the main net public key is static and a rogue network could return
//!   // a different key.
//!   // If you know the root key ahead of time, you can use `agent.set_root_key(root_key)?;`.
//!   agent.fetch_root_key().await?;
//!   let management_canister_id = Principal::from_text("aaaaa-aa")?;
//!
//!   // Create a call to the management canister to create a new canister ID,
//!   // and wait for a result.
//!   // The effective canister id must belong to the canister ranges of the subnet at which the canister is created.
//!   let effective_canister_id = Principal::from_text("rwlgt-iiaaa-aaaaa-aaaaa-cai").unwrap();
//!   let response = agent.update(&management_canister_id, "provisional_create_canister_with_cycles")
//!     .with_effective_canister_id(effective_canister_id)
//!     .with_arg(&Encode!(&Argument { amount: None})?)
//!     .call_and_wait()
//!     .await?;
//!
//!   let result = Decode!(response.as_slice(), CreateCanisterResult)?;
//!   let canister_id: Principal = result.canister_id;
//!   Ok(canister_id)
//! }
//!
//! # let mut runtime = tokio::runtime::Runtime::new().unwrap();
//! # runtime.block_on(async {
//! let canister_id = create_a_canister().await.unwrap();
//! eprintln!("{}", canister_id);
//! # });
//! ```
//! For more information about the Agent interface used in this example, see the
//! [Agent](https://agent-rust.netlify.app/ic_agent/struct.agent) documentation.
//!
//! ## References
//! For an introduction to the Internet Computer and the DFINITY Canister SDK,
//! see the following resources:
//!
//! - [Frequently Asked Questions](https://dfinity.org/faq)
//! - [DFINITY Canister SDK](https://sdk.dfinity.org/docs/index.html)
//!
//! The Internet Computer protocol and interface specifications are not
//! publicly available yet. When these specifications are made public and
//! generally available, additional details about the versions supported will
//! be available here.

#![deny(
    missing_docs,
    missing_debug_implementations,
    rustdoc::broken_intra_doc_links,
    rustdoc::private_intra_doc_links
)]

#[macro_use]
mod macros;

pub mod agent;
pub mod export;
pub mod identity;
pub mod request_id;

pub use agent::{
    agent_error, agent_error::AgentError, response_authentication::lookup_value, Agent,
    NonceFactory, NonceGenerator,
};
pub use identity::{Identity, Signature};
pub use request_id::{to_request_id, RequestId, RequestIdError};

// Re-export from ic_certification for backward compatibility.
pub use ic_certification::hash_tree;
pub use ic_certification::Certificate;
