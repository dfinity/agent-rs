//! In this file, please mark all tests that require a running ic-ref as ignored.
//!
//! Contrary to ic-ref.rs, these tests are not meant to match any other tests. They're
//! integration tests with a running IC-Ref.
use ic_agent::export::Principal;
use ic_agent::{AgentError, HttpErrorPayload};
use ic_utils::call::AsyncCall;
use ic_utils::call::SyncCall;
use ic_utils::interfaces::management_canister::InstallMode;
use ic_utils::interfaces::Wallet;
use ic_utils::{Argument, Canister};
use ref_tests::universal_canister::payload;
use ref_tests::{
    create_agent, create_basic_identity, create_universal_canister, create_waiter,
    create_wallet_canister, with_universal_canister, with_wallet_canister,
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
        let alice = Wallet::create(&agent, wallet_id);
        let bob = Wallet::create(&agent, create_wallet_canister(&agent).await?);

        let result = alice
            .wallet_send(&bob, 1_000_000)
            .call_and_wait(create_waiter())
            .await;

        assert_eq!(
            result,
            Err(AgentError::ReplicaError {
                reject_code: 3,
                reject_message: "method does not exist: wallet_send".to_string()
            })
        );

        Ok(())
    });
}

#[ignore]
#[test]
fn wallet_canister_forward() {
    with_wallet_canister(|agent, wallet_id| async move {
        let wallet = Wallet::create(&agent, wallet_id);

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
fn wallet_canister_create_and_install() {
    with_wallet_canister(|agent, wallet_id| async move {
        let wallet = Wallet::create(&agent, wallet_id);

        let (create_result,) = wallet
            .wallet_create_canister(1_000_000, None)
            .call_and_wait(create_waiter())
            .await?;

        let ic00 = Canister::builder()
            .with_agent(&agent)
            .with_canister_id(Principal::management_canister())
            .build()?;

        #[derive(candid::CandidType)]
        struct CanisterInstall {
            mode: InstallMode,
            canister_id: Principal,
            wasm_module: Vec<u8>,
            arg: Vec<u8>,
            compute_allocation: Option<candid::Nat>,
            memory_allocation: Option<candid::Nat>,
        }

        let install_config = CanisterInstall {
            mode: InstallMode::Install,
            canister_id: create_result.canister_id,
            wasm_module: b"\0asm\x01\0\0\0".to_vec(),
            arg: Argument::default().serialize()?,
            compute_allocation: None,
            memory_allocation: None,
        };

        let mut args = Argument::default();
        args.push_idl_arg(install_config);

        wallet
            .call(&ic00, "install_code", args, 0)
            .call_and_wait(create_waiter())
            .await?;

        Ok(())
    });
}

#[ignore]
#[test]
fn wallet_canister_funds() {
    with_wallet_canister(|agent, wallet_id| async move {
        let alice = Wallet::create(&agent, wallet_id);
        let bob = Wallet::create(&agent, create_wallet_canister(&agent).await?);

        let (alice_previous_balance,) = alice.wallet_balance().call().await?;
        let (bob_previous_balance,) = bob.wallet_balance().call().await?;

        alice
            .wallet_send(&bob, 1_000_000)
            .call_and_wait(create_waiter())
            .await?;

        let (bob_balance,) = bob.wallet_balance().call().await?;

        let (alice_balance,) = alice.wallet_balance().call().await?;
        eprintln!(
            "Alice previous: {}\n      current:  {}",
            alice_previous_balance.amount, alice_balance.amount
        );
        eprintln!(
            "Bob   previous: {}\n      current:  {}",
            bob_previous_balance.amount, bob_balance.amount
        );
        assert!(
            bob_balance.amount > bob_previous_balance.amount + 500_000,
            "Wrong: {} > {}",
            bob_balance.amount,
            bob_previous_balance.amount + 500_000
        );
        assert!(alice_balance.amount < alice_previous_balance.amount - 500_000);

        Ok(())
    });
}

#[ignore]
#[test]
fn wallet_helper_functions() {
    with_wallet_canister(|agent, wallet_id| async move {
        // name
        let wallet = Wallet::create(&agent, wallet_id);
        let (name,) = wallet.name().call().await?;
        assert!(name.is_none(), "Name should be none.");

        let wallet_name = "Alice".to_string();

        wallet
            .set_name(wallet_name.clone())
            .call_and_wait(create_waiter())
            .await?;
        let (name,) = wallet.name().call().await?;
        assert_eq!(name, Some(wallet_name));

        // controller
        let other_agent_identity = create_basic_identity().await?;
        let other_agent_principal = other_agent_identity.sender()?;
        let other_agent = create_agent(other_agent_identity).await?;
        other_agent.fetch_root_key().await?;

        let (controller_list,) = wallet.get_controllers().call().await?;
        assert_eq!(controller_list.len(), 1);
        assert_ne!(&controller_list[0], &other_agent_principal);

        wallet
            .add_controller(other_agent_principal.clone())
            .call_and_wait(create_waiter())
            .await?;

        let (controller_list,) = wallet.get_controllers().call().await?;
        assert_eq!(controller_list.len(), 2);
        let added = if controller_list[0] == other_agent_principal {
            true
        } else {
            controller_list[1] == other_agent_principal
        };
        assert!(added);

        wallet
            .remove_controller(other_agent_principal.clone())
            .call_and_wait(create_waiter())
            .await?;

        let (controller_list,) = wallet.get_controllers().call().await?;
        assert_eq!(controller_list.len(), 1);
        assert_ne!(&controller_list[0], &other_agent_principal);

        Ok(())
    });
}
