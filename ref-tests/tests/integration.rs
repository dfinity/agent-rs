//! In this file, please mark all tests that require a running ic-ref as ignored.
//!
//! Contrary to ic-ref.rs, these tests are not meant to match any other tests. They're
//! integration tests with a running IC-Ref.
use ic_agent::AgentError;
use ref_tests::universal_canister::payload;
use ref_tests::{create_waiter, with_universal_canister};

#[ignore]
#[test]
fn basic_expiry() {
    with_universal_canister(|agent, canister_id| async move {
        let arg = payload().reply_data(b"hello").build();

        // Verify this works first.
        let result = agent
            .update(&canister_id, "update")
            .with_arg(&arg)
            .expire_after(std::time::Duration::from_secs(120))
            .call_and_wait(create_waiter())
            .await?;

        assert_eq!(result.as_slice(), b"hello");

        // Verify a zero expiry will fail with the proper code.
        let result = agent
            .update(&canister_id, "update")
            .with_arg(&arg)
            .expire_after(std::time::Duration::from_secs(0))
            .call_and_wait(create_waiter())
            .await;

        match result.unwrap_err() {
            AgentError::HttpError { status, .. } => assert_eq!(status, 400),
            x => assert!(false, "Was expecting an error, got {:?}", x),
        }

        let result = agent
            .update(&canister_id, "update")
            .with_arg(&arg)
            .expire_after(std::time::Duration::from_secs(120))
            .call_and_wait(create_waiter())
            .await?;

        assert_eq!(result.as_slice(), b"hello");

        Ok(())
    })
}
