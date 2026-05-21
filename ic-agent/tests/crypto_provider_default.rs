//! Verify that `Agent::new` installs the rustls `CryptoProvider` matching the
//! active cargo features (`tls-aws-lc-rs` or `tls-ring`).
//!
//! In its own integration-test file for process isolation: `CryptoProvider`'s
//! process-wide default slot is one-shot, so sharing a binary with other tests
//! that pre-install a provider would make ordering matter.

#![cfg(not(target_family = "wasm"))]
#![cfg(any(feature = "tls-ring", feature = "tls-aws-lc-rs"))]

use ic_agent::Agent;
use rustls::crypto::CryptoProvider;

/// Address of the static target behind a `&'static dyn Trait`. Each rustls
/// provider registers its own `&'static dyn SecureRandom` pointing at a
/// distinct singleton, so two providers compare unequal here.
fn secure_random_addr(p: &CryptoProvider) -> *const () {
    (p.secure_random as *const dyn rustls::crypto::SecureRandom).cast()
}

#[test]
fn default_client_installs_expected_provider() {
    let _agent = Agent::builder()
        .with_url("https://ic0.app")
        .build()
        .expect("Agent build should succeed with a provider feature enabled");

    let installed = CryptoProvider::get_default().expect("a provider must be installed");

    // aws-lc-rs wins when both features are on (additive rule).
    #[cfg(feature = "tls-aws-lc-rs")]
    let expected = rustls::crypto::aws_lc_rs::default_provider();
    #[cfg(all(feature = "tls-ring", not(feature = "tls-aws-lc-rs")))]
    let expected = rustls::crypto::ring::default_provider();

    assert!(
        std::ptr::eq(secure_random_addr(installed), secure_random_addr(&expected)),
        "installed provider does not match the one selected by active features"
    );
}
