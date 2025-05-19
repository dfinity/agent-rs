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
//! a call to an Internet Computer's Ledger Canister to check the total ICP tokens supply.
//!
//! ```rust
//!use anyhow::{Context, Result};
//!use candid::{Decode, Nat};
//!use ic_agent::{export::Principal, Agent};
//!use url::Url;
//!
//!pub async fn create_agent(url: Url, use_mainnet: bool) -> Result<Agent> {
//!    let agent = Agent::builder().with_url(url).build()?;
//!    if !use_mainnet {
//!        agent.fetch_root_key().await?;
//!    }
//!    Ok(agent)
//!}
//!
//!#[tokio::main]
//!async fn main() -> Result<()> {
//!    // IC HTTP Gateway URL
//!    let url = Url::parse("https://ic0.app").unwrap();
//!    let agent = create_agent(url, true).await?;
//!
//!    // ICP Ledger Canister ID
//!    let canister_id = Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai")?;
//!
//!    // Method: icrc1_total_supply (takes no arguments, returns nat)
//!    let method_name = "icrc1_total_supply";
//!
//!    // Encode empty Candid arguments
//!    let args = candid::encode_args(())?;
//!
//!    // Dispatch query call
//!    let response = agent
//!        .query(&canister_id, method_name)
//!        .with_arg(args)
//!        .call()
//!        .await
//!        .context("Failed to query icrc1_total_supply method.")?;
//!
//!    // Decode the response as nat
//!    let total_supply_nat =
//!        Decode!(&response, Nat).context("Failed to decode total supply as nat.")?;
//!
//!    println!("Total ICP Supply: {} ICP", total_supply_nat);
//!
//!    Ok(())
//!}
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

#![warn(
    missing_docs,
    rustdoc::broken_intra_doc_links,
    rustdoc::private_intra_doc_links
)]
#![cfg_attr(not(target_family = "wasm"), warn(clippy::future_not_send))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

#[macro_use]
mod util;

pub mod agent;
pub mod export;
pub mod identity;

use agent::response_authentication::LookupPath;
#[doc(inline)]
pub use agent::{agent_error, agent_error::AgentError, Agent, NonceFactory, NonceGenerator};
#[doc(inline)]
pub use ic_transport_types::{to_request_id, RequestId, RequestIdError, TransportCallResponse};
#[doc(inline)]
pub use identity::{Identity, Signature};

// Re-export from ic_certification for backward compatibility.
pub use ic_certification::{hash_tree, Certificate};

/// Looks up a value in the certificate's tree at the specified hash.
///
/// Returns the value if it was found; otherwise, errors with `LookupPathAbsent`, `LookupPathUnknown`, or `LookupPathError`.
pub fn lookup_value<P: LookupPath, Storage: AsRef<[u8]>>(
    tree: &ic_certification::certificate::Certificate<Storage>,
    path: P,
) -> Result<&[u8], AgentError> {
    agent::response_authentication::lookup_value(&tree.tree, path)
}
