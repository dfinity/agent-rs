//! Verify that `Agent::new` does not overwrite a `CryptoProvider` that the
//! application installed first, and does not panic in that case.
//!
//! In its own integration-test file for process isolation: the prior test in
//! `crypto_provider_default.rs` is the inverse setup (ic-agent installs first),
//! and `CryptoProvider`'s default slot is one-shot per process.

#![cfg(not(target_family = "wasm"))]
#![cfg(any(feature = "tls-ring", feature = "tls-aws-lc-rs"))]

use ic_agent::Agent;
use rustls::crypto::CryptoProvider;

#[test]
fn application_provider_wins() {
    // Pick the *opposite* of what ic-agent would install, to detect overwrites.
    #[cfg(feature = "tls-aws-lc-rs")]
    let user_choice = rustls::crypto::ring::default_provider();
    #[cfg(all(feature = "tls-ring", not(feature = "tls-aws-lc-rs")))]
    let user_choice = rustls::crypto::aws_lc_rs::default_provider();

    let user_ptr: *const dyn rustls::crypto::SecureRandom = user_choice.secure_random;
    user_choice
        .install_default()
        .expect("test must run before any other provider is installed");

    // ic-agent builds its default client; should not panic, and should not
    // change the installed default.
    let _agent = Agent::builder()
        .with_url("https://ic0.app")
        .build()
        .expect("Agent build should succeed");

    let installed = CryptoProvider::get_default().expect("provider still installed");
    // Compare the full `&'static dyn SecureRandom` wide pointer (data + vtable);
    // casting to `*const ()` would drop the vtable and could alias for ZSTs.
    assert!(
        std::ptr::eq(installed.secure_random, user_ptr),
        "ic-agent overwrote a previously installed CryptoProvider"
    );
}
