//! The `ic-agent` is a simple-to-use library that enables you to
//! build applications and interact with the [Internet Computer](https://internetcomputer.org)
//! in Rust. It serves as a Rust-based low-level backend for the
//! DFINITY Canister Software Development Kit (SDK) and the command-line execution environment
//! [`dfx`](https://internetcomputer.org/docs/current/developer-docs/setup/install).
//!
//! ## Overview
//! The `ic-agent` is a Rust crate that can connect directly to the Internet
//! Computer through the Internet Computer protocol (ICP).
//! The key software components of the ICP are broadly referred to as the
//! [replica](https://internetcomputer.org/docs/current/concepts/nodes-subnets).
//!
//! The agent is designed to be compatible with multiple versions of the
//! replica API, and to expose both low-level APIs for communicating with
//! Internet Computer protocol components like the replica and to provide
//! higher-level APIs for communicating with software applications deployed
//! as [canisters](https://internetcomputer.org/docs/current/concepts/canisters-code).
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
//!   // If you know the root key ahead of time, you can use `agent.set_root_key(root_key);`.
//!   agent.fetch_root_key().await?;
//!   let management_canister_id = Principal::from_text("aaaaa-aa")?;
//!
//!   // Create a call to the management canister to create a new canister ID,
//!   // and wait for a result.
//!   // The effective canister id must belong to the canister ranges of the subnet at which the canister is created.
//!   let effective_canister_id = Principal::from_text("rwlgt-iiaaa-aaaaa-aaaaa-cai").unwrap();
//!   let response = agent.update(&management_canister_id, "provisional_create_canister_with_cycles")
//!     .with_effective_canister_id(effective_canister_id)
//!     .with_arg(Encode!(&Argument { amount: None})?)
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
//! [Agent] documentation.
//!
//! ## References
//! For an introduction to the Internet Computer and the DFINITY Canister SDK,
//! see the following resources:
//!
//! - [How the IC Works](https://internetcomputer.org/docs/current/concepts/)
//! - [DFINITY Canister SDK](https://internetcomputer.org/docs/current/references/cli-reference/)
//!
//! The Internet Computer protocol and interface specifications are not
//! publicly available yet. When these specifications are made public and
//! generally available, additional details about the versions supported will
//! be available here.

#![deny(
    missing_docs,
    rustdoc::broken_intra_doc_links,
    rustdoc::private_intra_doc_links
)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

#[cfg(all(feature = "hyper", target_family = "wasm"))]
compile_error!("Feature `hyper` cannot be used from WASM.");

pub mod agent;
pub mod export;
pub mod identity;

#[doc(inline)]
pub use agent::{
    agent_error, agent_error::AgentError, response_authentication::lookup_value, Agent,
    NonceFactory, NonceGenerator,
};
#[doc(inline)]
pub use ic_transport_types::{to_request_id, RequestId, RequestIdError};
#[doc(inline)]
pub use identity::{Identity, Signature};

// Re-export from ic_certification for backward compatibility.
pub use ic_certification::{hash_tree, Certificate};
