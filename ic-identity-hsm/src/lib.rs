//! A crate to manage identities related to HSM (Hardware Security Module),
//! allowing users to sign Internet Computer messages with their hardware key.
//! Also supports SoftHSM.
//!
//! # Example
//!
//! ```rust,no_run
//! use ic_agent::agent::Agent;
//! use ic_identity_hsm::HardwareIdentity;
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let replica_url = "";
//! # let lib_path = "";
//! # let slot_index = 0;
//! # let key_id = "";
//! let agent = Agent::builder()
//!     .with_url(replica_url)
//!     .with_identity(HardwareIdentity::new(lib_path, slot_index, key_id, || Ok("hunter2".to_string()))?)
//!     .build();
//! # Ok(())
//! # }

#![deny(
    missing_docs,
    missing_debug_implementations,
    rustdoc::broken_intra_doc_links,
    rustdoc::private_intra_doc_links
)]

pub(crate) mod hsm;
pub use hsm::{HardwareIdentity, HardwareIdentityError};
