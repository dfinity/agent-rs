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
//! ```ignore
//! # // This test is ignored because it requires an ic to be running. We run these
//! # // in the ic-ref workflow.
//! use ic_agent::{Agent, Principal};
//! use candid::{Encode, Decode, CandidType};
//! use serde::Deserialize;
//! use std::time::{Duration, SystemTime, UNIX_EPOCH};
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
//! #     ic_agent::BasicIdentity::from_key_pair(
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
//!   let management_canister_id = Principal::from_text("aaaaa-aa")?;
//!
//!   let duration = Duration::from_secs(60 * 5);
//!   let start = SystemTime::now();
//!   let since_epoch = start
//!       .duration_since(UNIX_EPOCH)
//!       .expect("Time wrapped around");
//!   let valid_until = (since_epoch + duration).as_nanos() as u64;
//!
//!   let waiter = delay::Delay::builder()
//!     .throttle(std::time::Duration::from_millis(500))
//!     .timeout(duration)
//!     .build();
//!
//!   // Create a call to the management canister to create a new canister ID,
//!   // and wait for a result.
//!   let response = agent.update(&management_canister_id, "create_canister")
//!     .with_arg(&Encode!()?)  // Empty Candid.
//!     .with_expiry(valid_until)
//!     .call_and_wait(waiter)
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
