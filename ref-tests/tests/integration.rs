//! In this file, please mark all tests that require a running ic-ref as ignored.
//!
//! Contrary to ic-ref.rs, these tests are not meant to match any other tests. They're
//! integration tests with a running IC-Ref.
use ic_agent::{AgentError, HttpErrorPayload};
use ic_utils::call::AsyncCall;
use ic_utils::call::SyncCall;
use ic_utils::{interfaces, Canister};
use ref_tests::universal_canister::payload;
use ref_tests::{
    create_universal_canister, create_waiter, create_wallet_canister, with_universal_canister,
    with_wallet_canister,
};

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
            AgentError::HttpError(HttpErrorPayload { status, .. }) => assert_eq!(status, 400),
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

#[ignore]
#[test]
fn canister_query() {
    with_universal_canister(|agent, canister_id| async move {
        let universal = Canister::builder()
            .with_canister_id(canister_id)
            .with_agent(&agent)
            .build()?;

        let arg = payload().reply_data(b"hello").build();

        let out = unsafe {
            universal
                .query_("query")
                .with_arg_raw(arg)
                .build::<()>()
                .call_raw()
                .await?
        };

        assert_eq!(out, b"hello");

        Ok(())
    })
}

#[ignore]
#[test]
fn canister_reject_call() {
    // try to call a wallet method, but on the universal canister.
    // this lets us look up the reject code and reject message in the certificate.
    with_universal_canister(|agent, wallet_id| async move {
        let alice = interfaces::Wallet::create(&agent, wallet_id);
        let bob = interfaces::Wallet::create(&agent, create_wallet_canister(&agent).await?);

        let result = alice
            .send_cycles(&bob, 1_000_000)
            .call_and_wait(create_waiter())
            .await;

        assert_eq!(
            result,
            Err(AgentError::ReplicaError {
                reject_code: 3,
                reject_message: "method does not exist: send_cycles".to_string()
            })
        );

        Ok(())
    });
}

#[ignore]
#[test]
fn wallet_canister_forward() {
    with_wallet_canister(|agent, wallet_id| async move {
        let wallet = interfaces::Wallet::create(&agent, wallet_id);

        let universal_id = create_universal_canister(&agent).await?;
        let universal = Canister::builder()
            .with_canister_id(universal_id)
            .with_agent(&agent)
            .build()?;

        // Perform an "echo" call through the wallet canister.
        // We encode the result in DIDL to decode it on the other side (would normally get
        // a Vec<u8>).
        let arg = payload()
            .reply_data(b"DIDL\0\x01\x71\x0bHello World")
            .build();

        let forward = wallet
            .call_forward::<(String,)>(universal.update_("update").with_arg_raw(arg).build(), 0)?;
        let (result,) = forward.call_and_wait(create_waiter()).await.unwrap();

        assert_eq!(result, "Hello World");
        Ok(())
    });
}

#[ignore]
#[test]
fn wallet_canister_funds() {
    with_wallet_canister(|agent, wallet_id| async move {
        let alice = interfaces::Wallet::create(&agent, wallet_id);
        let bob = interfaces::Wallet::create(&agent, create_wallet_canister(&agent).await?);

        alice
            .send_cycles(&bob, 1_000_000)
            .call_and_wait(create_waiter())
            .await?;

        let (cycles,) = bob.cycle_balance().call().await?;
        assert_eq!(cycles, 1_000_001_000_000);

        let (cycles,) = alice.cycle_balance().call().await?;
        assert_eq!(cycles, 999_999_000_000);

        Ok(())
    });
}
