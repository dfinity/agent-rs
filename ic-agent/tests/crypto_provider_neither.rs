//! Verify that building a default `Agent` panics when neither `tls-ring` nor
//! `tls-aws-lc-rs` is enabled, because reqwest's `rustls-no-provider` feature
//! requires a process-wide `CryptoProvider` to be installed and ic-agent's
//! helper is a no-op in this configuration.
//!
//! Only compiled when *neither* TLS feature is active. The companion CI step
//! exercises this with `--no-default-features --features pem`.

#![cfg(not(target_family = "wasm"))]
#![cfg(not(any(feature = "tls-ring", feature = "tls-aws-lc-rs")))]

use ic_agent::Agent;

#[test]
#[should_panic]
fn default_client_panics_without_provider() {
    // Reqwest panics with "No provider set" when it cannot find an installed
    // CryptoProvider. `Agent::builder().build()` triggers `Client::builder()`
    // which is where the panic surfaces.
    let _ = Agent::builder().with_url("https://ic0.app").build();
}
