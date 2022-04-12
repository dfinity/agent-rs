//! In this file, please mark all tests that require a running ic-ref as ignored.
//!
//! These tests are a Rust-like version using the Agent to cover the same tests
//! as the IC Ref repo itself.
//!
//! The tests can be found in the Spec.hs file in the IC Ref repo.
//!   https://github.com/dfinity/ic-hs/blob/master/src/IC/Test/Spec.hs
//!
//! Try to keep these tests as close to 1-to-1 to the IC Ref test use cases. For
//! every spec in the IC Ref tests, there should be a matching spec here. Some
//! tests (like invalid CBOR or special Headers) might not be translatable, in
//! which case they should still be added here but do nothing (just keep the
//! use case being tested).
use ref_tests::{universal_canister, with_agent};

const EXPECTED_IC_API_VERSION: &str = "0.18.0";

#[ignore]
#[test]
fn status_endpoint() {
    with_agent(|agent| async move {
        agent.status().await?;
        Ok(())
    })
}

#[ignore]
#[test]
fn spec_compliance_claimed() {
    with_agent(|agent| async move {
        let status = agent.status().await?;

        assert_eq!(status.ic_api_version, EXPECTED_IC_API_VERSION);

        Ok(())
    });
}

mod management_canister {
    use candid::CandidType;
    use ic_agent::{export::Principal, AgentError};
    use ic_utils::{
        call::AsyncCall,
        interfaces::{
            management_canister::{
                builders::{CanisterSettings, InstallMode},
                CanisterStatus, StatusCallResult,
            },
            wallet::CreateResult,
            ManagementCanister, WalletCanister,
        },
        Argument,
    };
    use openssl::sha::Sha256;
    use ref_tests::{
        create_agent, create_basic_identity, create_secp256k1_identity, create_waiter, with_agent,
        with_wallet_canister,
    };
    use std::collections::HashSet;

    mod create_canister {
        use super::{create_waiter, with_agent};
        use ic_agent::{export::Principal, AgentError};
        use ic_utils::interfaces::ManagementCanister;
        use std::str::FromStr;

        #[ignore]
        #[test]
        fn no_id_given() {
            with_agent(|agent| async move {
                let ic00 = ManagementCanister::create(&agent);

                let _ = ic00
                    .create_canister()
                    .as_provisional_create_with_amount(None)
                    .call_and_wait(create_waiter())
                    .await?;

                Ok(())
            })
        }

        #[ignore]
        #[test]
        fn create_canister_necessary() {
            with_agent(|agent| async move {
                let ic00 = ManagementCanister::create(&agent);
                let canister_wasm = b"\0asm\x01\0\0\0".to_vec();

                let result = ic00
                    .install_code(
                        &Principal::from_str("75hes-oqbaa-aaaaa-aaaaa-aaaaa-aaaaa-aaaaa-q")
                            .unwrap(),
                        &canister_wasm,
                    )
                    .call_and_wait(create_waiter())
                    .await;

                let payload_content =
                    "canister does not exist: 75hes-oqbaa-aaaaa-aaaaa-aaaaa-aaaaa-aaaaa-q"
                        .to_string();

                assert!(matches!(result,
                    Err(AgentError::HttpError(payload))
                        if String::from_utf8(payload.content.clone()).expect("Expected utf8") == payload_content));
                Ok(())
            })
        }
    }

    #[ignore]
    #[test]
    fn management() {
        with_agent(|agent| async move {
            let ic00 = ManagementCanister::create(&agent);

            let (canister_id,) = ic00
                .create_canister()
                .as_provisional_create_with_amount(None)
                .call_and_wait(create_waiter())
                .await?;
            let canister_wasm = b"\0asm\x01\0\0\0".to_vec();

            // Install once.
            ic00.install_code(&canister_id, &canister_wasm)
                .with_mode(InstallMode::Install)
                .call_and_wait(create_waiter())
                .await?;

            // Re-install should fail.
            let result = ic00
                .install_code(&canister_id, &canister_wasm)
                .with_mode(InstallMode::Install)
                .call_and_wait(create_waiter())
                .await;

            assert!(matches!(result, Err(AgentError::ReplicaError { .. })));

            // Reinstall should succeed.
            ic00.install_code(&canister_id, &canister_wasm)
                .with_mode(InstallMode::Reinstall)
                .call_and_wait(create_waiter())
                .await?;

            // Each agent has their own identity.
            let other_agent_identity = create_basic_identity().await?;
            let other_agent_principal = other_agent_identity.sender()?;
            let other_agent = create_agent(other_agent_identity).await?;
            other_agent.fetch_root_key().await?;
            let other_ic00 = ManagementCanister::create(&other_agent);

            // Reinstall with another agent should fail.
            let result = other_ic00
                .install_code(&canister_id, &canister_wasm)
                .with_mode(InstallMode::Reinstall)
                .call_and_wait(create_waiter())
                .await;
            assert!(matches!(result, Err(AgentError::HttpError(..))));

            // Upgrade should succeed.
            ic00.install_code(&canister_id, &canister_wasm)
                .with_mode(InstallMode::Upgrade)
                .call_and_wait(create_waiter())
                .await?;

            // Upgrade with another agent should fail.
            let result = other_ic00
                .install_code(&canister_id, &canister_wasm)
                .with_mode(InstallMode::Upgrade)
                .call_and_wait(create_waiter())
                .await;
            assert!(matches!(result, Err(AgentError::HttpError(..))));

            // Change controller.
            ic00.update_settings(&canister_id)
                .with_controller(other_agent_principal)
                .call_and_wait(create_waiter())
                .await?;

            // Change controller with wrong controller should fail
            let result = ic00
                .update_settings(&canister_id)
                .with_controller(other_agent_principal)
                .call_and_wait(create_waiter())
                .await;
            assert!(matches!(result, Err(AgentError::HttpError(payload))
                if String::from_utf8(payload.content.clone()).expect("Expected utf8")
                    == *"Wrong sender"));

            // Reinstall as new controller
            other_ic00
                .install_code(&canister_id, &canister_wasm)
                .with_mode(InstallMode::Reinstall)
                .call_and_wait(create_waiter())
                .await?;

            // Reinstall on empty should succeed.
            let (canister_id_2,) = ic00
                .create_canister()
                .as_provisional_create_with_amount(None)
                .call_and_wait(create_waiter())
                .await?;

            // Reinstall over empty canister
            ic00.install_code(&canister_id_2, &canister_wasm)
                .with_mode(InstallMode::Reinstall)
                .call_and_wait(create_waiter())
                .await?;

            // Create an empty canister
            let (canister_id_3,) = other_ic00
                .create_canister()
                .as_provisional_create_with_amount(None)
                .call_and_wait(create_waiter())
                .await?;

            // Check status for empty canister
            let result = other_ic00
                .canister_status(&canister_id_3)
                .call_and_wait(create_waiter())
                .await?;
            assert_eq!(result.0.status, CanisterStatus::Running);
            assert_eq!(result.0.settings.controllers.len(), 1);
            assert_eq!(result.0.settings.controllers[0], other_agent_principal);
            assert_eq!(result.0.module_hash, None);

            // Install wasm.
            other_ic00
                .install_code(&canister_id_3, &canister_wasm)
                .with_mode(InstallMode::Install)
                .call_and_wait(create_waiter())
                .await?;

            // Check status after installing wasm and validate module_hash
            let result = other_ic00
                .canister_status(&canister_id_3)
                .call_and_wait(create_waiter())
                .await?;
            let mut hasher = Sha256::new();
            hasher.update(&canister_wasm);
            let sha256_digest = hasher.finish();
            assert_eq!(result.0.module_hash, Some(sha256_digest.into()));

            Ok(())
        })
    }

    #[ignore]
    #[test]
    fn multiple_canisters_aaaaa_aa_but_really_provisional() {
        with_agent(|agent| async move {
            let agent_principal = agent.get_principal()?;
            // Each agent has their own identity.
            let other_agent_identity = create_basic_identity().await?;
            let other_agent_principal = other_agent_identity.sender()?;
            let other_agent = create_agent(other_agent_identity).await?;
            other_agent.fetch_root_key().await?;
            let other_ic00 = ManagementCanister::create(&other_agent);

            let secp256k1_identity = create_secp256k1_identity()?;
            let secp256k1_principal = secp256k1_identity.sender()?;
            let secp256k1_agent = create_agent(secp256k1_identity).await?;
            secp256k1_agent.fetch_root_key().await?;
            let secp256k1_ic00 = ManagementCanister::create(&secp256k1_agent);

            let ic00 = ManagementCanister::create(&agent);

            let (canister_id,) = ic00
                .create_canister()
                .as_provisional_create_with_amount(None) // ok
                //.with_canister_id("aaaaa-aa")
                .with_controller(agent_principal)
                .with_controller(other_agent_principal)
                .call_and_wait(create_waiter())
                .await?;

            // Controllers should be able to fetch the canister status.
            let result = ic00
                .canister_status(&canister_id)
                .call_and_wait(create_waiter())
                .await?;
            assert_eq!(result.0.settings.controllers.len(), 2);
            let actual = result
                .0
                .settings
                .controllers
                .iter()
                .cloned()
                .collect::<HashSet<_>>();
            let expected = vec![agent_principal, other_agent_principal]
                .iter()
                .cloned()
                .collect::<HashSet<_>>();
            assert_eq!(actual, expected);

            let result = other_ic00
                .canister_status(&canister_id)
                .call_and_wait(create_waiter())
                .await?;
            assert_eq!(result.0.settings.controllers.len(), 2);
            let actual = result
                .0
                .settings
                .controllers
                .iter()
                .cloned()
                .collect::<HashSet<_>>();
            let expected = vec![agent_principal, other_agent_principal]
                .iter()
                .cloned()
                .collect::<HashSet<_>>();
            assert_eq!(actual, expected);

            // Set new controller
            ic00.update_settings(&canister_id)
                .with_controller(secp256k1_principal)
                .call_and_wait(create_waiter())
                .await?;

            // Only that controller can get canister status
            let result = ic00
                .canister_status(&canister_id)
                .call_and_wait(create_waiter())
                .await;
            assert_err_or_reject(result, vec![3, 5]);
            let result = other_ic00
                .canister_status(&canister_id)
                .call_and_wait(create_waiter())
                .await;
            assert_err_or_reject(result, vec![3, 5]);

            let result = secp256k1_ic00
                .canister_status(&canister_id)
                .call_and_wait(create_waiter())
                .await?;
            assert_eq!(result.0.settings.controllers.len(), 1);
            assert_eq!(result.0.settings.controllers[0], secp256k1_principal);

            Ok(())
        })
    }

    fn assert_err_or_reject<S>(result: Result<S, AgentError>, allowed_reject_codes: Vec<u64>) {
        for expected_rc in &allowed_reject_codes {
            if matches!(result, Err(AgentError::ReplicaError {
                    reject_code: actual_rc,
                    reject_message: _,
                }) if actual_rc == *expected_rc)
            {
                return;
            }
        }
        assert!(
            matches!(result, Err(AgentError::HttpError(_))),
            "expect an HttpError, or a ReplicaError with reject_code in {:?}",
            allowed_reject_codes
        );
    }

    #[ignore]
    #[test]
    fn canister_lifecycle_and_delete() {
        with_agent(|agent| async move {
            let ic00 = ManagementCanister::create(&agent);
            let (canister_id,) = ic00
                .create_canister()
                .as_provisional_create_with_amount(None)
                .call_and_wait(create_waiter())
                .await?;
            let canister_wasm = b"\0asm\x01\0\0\0".to_vec();

            // Install once.
            ic00.install_code(&canister_id, &canister_wasm)
                .with_mode(InstallMode::Install)
                .call_and_wait(create_waiter())
                .await?;

            // A newly installed canister should be running
            let result = ic00
                .canister_status(&canister_id)
                .call_and_wait(create_waiter())
                .await;
            assert_eq!(result?.0.status, CanisterStatus::Running);

            // Stop should succeed.
            ic00.stop_canister(&canister_id)
                .call_and_wait(create_waiter())
                .await?;

            // Canister should be stopped
            let result = ic00
                .canister_status(&canister_id)
                .call_and_wait(create_waiter())
                .await;
            assert_eq!(result?.0.status, CanisterStatus::Stopped);

            // Another stop is a noop
            ic00.stop_canister(&canister_id)
                .call_and_wait(create_waiter())
                .await?;

            // Can't call update on a stopped canister
            let result = agent
                .update(&canister_id, "update")
                .call_and_wait(create_waiter())
                .await;
            assert!(matches!(result, Err(AgentError::HttpError(payload))
                if String::from_utf8(payload.content.clone()).expect("Expected utf8") == *"canister is stopped"));

            // Can't call query on a stopped canister
            let result = agent
                .query(&canister_id, "query")
                .with_arg(&[])
                .call()
                .await;
            assert!(matches!(result, Err(AgentError::ReplicaError {
                    reject_code: 5,
                    reject_message,
                }) if reject_message == "canister is stopped"));

            // Upgrade should succeed
            ic00.install_code(&canister_id, &canister_wasm)
                .with_mode(InstallMode::Upgrade)
                .call_and_wait(create_waiter())
                .await?;

            // Start should succeed.
            ic00.start_canister(&canister_id)
                .call_and_wait(create_waiter())
                .await?;

            // Canister should be running
            let result = ic00
                .canister_status(&canister_id)
                .call_and_wait(create_waiter())
                .await;
            assert_eq!(result?.0.status, CanisterStatus::Running);

            // Can call update
            let result = agent
                .update(&canister_id, "update")
                .call_and_wait(create_waiter())
                .await;
            assert!(matches!(result, Err(AgentError::ReplicaError {
                    reject_code: 3,
                    reject_message,
                }) if reject_message == "method does not exist: update"));

            // Can call query
            let result = agent
                .query(&canister_id, "query")
                .with_arg(&[])
                .call()
                .await;
            assert!(matches!(result, Err(AgentError::ReplicaError {
                    reject_code: 3,
                    reject_message,
                }) if reject_message == "query method does not exist"));

            // Another start is a noop
            ic00.start_canister(&canister_id)
                .call_and_wait(create_waiter())
                .await?;

            // Delete a running canister should fail.
            let result = ic00
                .delete_canister(&canister_id)
                .call_and_wait(create_waiter())
                .await;
            assert!(matches!(result, Err(AgentError::ReplicaError { .. })));

            // Stop should succeed.
            ic00.stop_canister(&canister_id)
                .call_and_wait(create_waiter())
                .await?;

            // Delete a stopped canister succeeds.
            ic00.delete_canister(&canister_id)
                .call_and_wait(create_waiter())
                .await?;

            // Cannot call update
            let result = agent
                .update(&canister_id, "update")
                .call_and_wait(create_waiter())
                .await;
            assert!(matches!(result, Err(AgentError::HttpError(payload))
                if String::from_utf8(payload.content.clone()).expect("Expected utf8")
                    == format!("canister no longer exists: {}", canister_id.to_text())));

            // Cannot call query
            let result = agent
                .query(&canister_id, "query")
                .with_arg(&[])
                .call()
                .await;
            assert!(matches!(result, Err(AgentError::ReplicaError {
                    reject_code: 3,
                    reject_message,
                }) if reject_message
                    == format!("canister no longer exists: {}", canister_id.to_text())));

            // Cannot query canister status
            let result = ic00
                .canister_status(&canister_id)
                .call_and_wait(create_waiter())
                .await;
            assert!(match result {
                Err(AgentError::HttpError(payload))
                    if String::from_utf8(payload.content.clone()).expect("Expected utf8")
                        == format!("canister no longer exists: {}", canister_id.to_text()) =>
                    true,
                Ok((_status_call_result,)) => false,
                _ => false,
            });

            // Delete a deleted canister should fail.
            let result = ic00
                .delete_canister(&canister_id)
                .call_and_wait(create_waiter())
                .await;
            assert!(matches!(result, Err(AgentError::HttpError(payload))
                if String::from_utf8(payload.content.clone()).expect("Expected utf8")
                    == format!("canister no longer exists: {}", canister_id.to_text())));
            Ok(())
        })
    }

    #[ignore]
    #[test]
    fn canister_lifecycle_as_wrong_controller() {
        with_agent(|agent| async move {
            let ic00 = ManagementCanister::create(&agent);
            let (canister_id,) = ic00
                .create_canister()
                .as_provisional_create_with_amount(None)
                .call_and_wait(create_waiter())
                .await?;
            let canister_wasm = b"\0asm\x01\0\0\0".to_vec();

            // Install once.
            ic00.install_code(&canister_id, &canister_wasm)
                .with_mode(InstallMode::Install)
                .call_and_wait(create_waiter())
                .await?;

            // Create another agent with different identity.
            let other_agent_identity = create_basic_identity().await?;
            let other_agent = create_agent(other_agent_identity).await?;
            other_agent.fetch_root_key().await?;
            let other_ic00 = ManagementCanister::create(&other_agent);

            // Start as a wrong controller should fail.
            let result = other_ic00
                .start_canister(&canister_id)
                .call_and_wait(create_waiter())
                .await;
            assert!(matches!(result, Err(AgentError::HttpError(payload))
                if String::from_utf8(payload.content.clone()).expect("Expected utf8")
                    == *"Wrong sender"));

            // Stop as a wrong controller should fail.
            let result = other_ic00
                .stop_canister(&canister_id)
                .call_and_wait(create_waiter())
                .await;
            assert!(matches!(result, Err(AgentError::HttpError(payload))
                if String::from_utf8(payload.content.clone()).expect("Expected utf8")
                    == *"Wrong sender"));

            // Get canister status as a wrong controller should fail.
            let result = other_ic00
                .canister_status(&canister_id)
                .call_and_wait(create_waiter())
                .await;
            assert!(matches!(result, Err(AgentError::HttpError(payload))
                if String::from_utf8(payload.content.clone()).expect("Expected utf8")
                    == *"Wrong sender"));

            // Delete as a wrong controller should fail.
            let result = other_ic00
                .delete_canister(&canister_id)
                .call_and_wait(create_waiter())
                .await;
            assert!(matches!(result, Err(AgentError::HttpError(payload))
                if String::from_utf8(payload.content.clone()).expect("Expected utf8")
                    == *"Wrong sender"));

            Ok(())
        })
    }

    #[ignore]
    #[test]
    fn provisional_create_canister_with_cycles() {
        with_wallet_canister(None, |agent, wallet_id| async move {
            let default_canister_balance: u128 = 100_000_000_000_000;

            // empty cycle balance on create
            let wallet = WalletCanister::create(&agent, wallet_id).await?;

            #[derive(CandidType)]
            struct InCreate {
                cycles: u64,
                settings: CanisterSettings,
            }
            let create_args = InCreate {
                cycles: 0_u64,
                settings: CanisterSettings {
                    controllers: None,
                    compute_allocation: None,
                    memory_allocation: None,
                    freezing_threshold: None,
                },
            };

            let mut args = Argument::default();
            args.push_idl_arg(create_args);

            let (create_result,): (CreateResult,) = wallet
                .call(Principal::management_canister(), "create_canister", args, 0)
                .call_and_wait(create_waiter())
                .await?;
            let canister_id = create_result.canister_id;

            #[derive(CandidType)]
            struct In {
                canister_id: Principal,
            }
            let status_args = In { canister_id };
            let mut args = Argument::default();
            args.push_idl_arg(status_args);

            let (result,): (StatusCallResult,) = wallet
                .call(Principal::management_canister(), "canister_status", args, 0)
                .call_and_wait(create_waiter())
                .await?;

            assert_eq!(result.cycles, 0_u64);

            let ic00 = ManagementCanister::create(&agent);
            // cycle balance is default_canister_balance when creating with
            // provisional_create_canister_with_cycles(None)
            let (canister_id_1,) = ic00
                .create_canister()
                .as_provisional_create_with_amount(None)
                .call_and_wait(create_waiter())
                .await?;
            let result = ic00
                .canister_status(&canister_id_1)
                .call_and_wait(create_waiter())
                .await?;
            assert_eq!(result.0.cycles, default_canister_balance);

            // cycle balance should be amount specified to
            // provisional_create_canister_with_cycles call
            let amount: u128 = 1 << 40; // 1099511627776
            let (canister_id_2,) = ic00
                .create_canister()
                .as_provisional_create_with_amount(Some(amount))
                .call_and_wait(create_waiter())
                .await?;
            let result = ic00
                .canister_status(&canister_id_2)
                .call_and_wait(create_waiter())
                .await?;
            assert_eq!(result.0.cycles, amount);

            Ok(())
        })
    }

    #[ignore]
    #[test]
    fn randomness() {
        with_wallet_canister(None, |agent, wallet_id| async move {
            let wallet = WalletCanister::create(&agent, wallet_id).await?;
            let (rand_1,): (Vec<u8>,) = wallet
                .call(
                    Principal::management_canister(),
                    "raw_rand",
                    Argument::default(),
                    0,
                )
                .call_and_wait(create_waiter())
                .await?;
            let (rand_2,): (Vec<u8>,) = wallet
                .call(
                    Principal::management_canister(),
                    "raw_rand",
                    Argument::default(),
                    0,
                )
                .call_and_wait(create_waiter())
                .await?;
            let (rand_3,): (Vec<u8>,) = wallet
                .call(
                    Principal::management_canister(),
                    "raw_rand",
                    Argument::default(),
                    0,
                )
                .call_and_wait(create_waiter())
                .await?;

            assert_eq!(rand_1.len(), 32);
            assert_eq!(rand_2.len(), 32);
            assert_eq!(rand_3.len(), 32);

            assert_ne!(rand_1, rand_2);
            assert_ne!(rand_1, rand_3);
            assert_ne!(rand_2, rand_3);

            Ok(())
        })
    }

    #[ignore]
    #[test]
    // makes sure that calling fetch_root_key twice by accident does not break
    fn multi_fetch_root_key() {
        with_agent(|agent| async move {
            agent.fetch_root_key().await?;
            agent.fetch_root_key().await?;

            Ok(())
        })
    }
}

mod simple_calls {
    use crate::universal_canister::payload;
    use ic_agent::AgentError;
    use ref_tests::{create_waiter, with_universal_canister};

    #[ignore]
    #[test]
    fn call() {
        with_universal_canister(|agent, canister_id| async move {
            let arg = payload().reply_data(b"hello").build();
            let result = agent
                .update(&canister_id, "update")
                .with_arg(&arg)
                .call_and_wait(create_waiter())
                .await?;

            assert_eq!(result.as_slice(), b"hello");
            Ok(())
        })
    }

    #[ignore]
    #[test]
    fn query() {
        with_universal_canister(|agent, canister_id| async move {
            let arg = payload().reply_data(b"hello").build();
            let result = agent
                .query(&canister_id, "query")
                .with_arg(arg)
                .call()
                .await?;

            assert_eq!(result, b"hello");
            Ok(())
        })
    }

    #[ignore]
    #[test]
    fn non_existant_call() {
        with_universal_canister(|agent, canister_id| async move {
            let arg = payload().reply_data(b"hello").build();
            let result = agent
                .update(&canister_id, "non_existent_method")
                .with_arg(&arg)
                .call_and_wait(create_waiter())
                .await;

            assert!(matches!(
                result,
                Err(AgentError::ReplicaError { reject_code: 3, .. })
            ));
            Ok(())
        })
    }

    #[ignore]
    #[test]
    fn non_existant_query() {
        with_universal_canister(|agent, canister_id| async move {
            let arg = payload().reply_data(b"hello").build();
            let result = agent
                .query(&canister_id, "non_existent_method")
                .with_arg(&arg)
                .call()
                .await;

            assert!(matches!(
                result,
                Err(AgentError::ReplicaError { reject_code: 3, .. })
            ));
            Ok(())
        })
    }
}

mod extras {
    use candid::Nat;
    use ic_utils::{
        call::AsyncCall,
        interfaces::{management_canister::builders::ComputeAllocation, ManagementCanister},
    };
    use ref_tests::{create_waiter, with_agent};

    #[ignore]
    #[test]
    fn valid_allocations() {
        with_agent(|agent| async move {
            let ic00 = ManagementCanister::create(&agent);

            let (canister_id,) = ic00
                .create_canister()
                .as_provisional_create_with_amount(Some(20_000_000_000_000_u128))
                .with_compute_allocation(1_u64)
                .with_memory_allocation(1024 * 1024_u64)
                .with_freezing_threshold(1_000_000_u64)
                .call_and_wait(create_waiter())
                .await?;

            let result = ic00
                .canister_status(&canister_id)
                .call_and_wait(create_waiter())
                .await?;
            assert_eq!(result.0.settings.compute_allocation, Nat::from(1_u64));
            assert_eq!(
                result.0.settings.memory_allocation,
                Nat::from(1024 * 1024_u64)
            );
            assert_eq!(
                result.0.settings.freezing_threshold,
                Nat::from(1_000_000_u64)
            );

            Ok(())
        })
    }

    #[ignore]
    #[test]
    fn memory_allocation() {
        with_agent(|agent| async move {
            let ic00 = ManagementCanister::create(&agent);
            // Prevent creating with over 1 << 48. This does not contact the server.
            assert!(ic00
                .create_canister()
                .as_provisional_create_with_amount(None)
                .with_memory_allocation(1u64 << 50)
                .call_and_wait(create_waiter())
                .await
                .is_err());

            let (_,) = ic00
                .create_canister()
                .as_provisional_create_with_amount(None)
                .with_memory_allocation(10 * 1024 * 1024u64)
                .call_and_wait(create_waiter())
                .await?;

            Ok(())
        })
    }

    #[ignore]
    #[test]
    fn compute_allocation() {
        use std::convert::TryFrom;

        with_agent(|agent| async move {
            let ic00 = ManagementCanister::create(&agent);
            let ca = ComputeAllocation::try_from(10).unwrap();

            let (_,) = ic00
                .create_canister()
                .as_provisional_create_with_amount(None)
                .with_compute_allocation(ca)
                .call_and_wait(create_waiter())
                .await?;

            Ok(())
        })
    }

    #[ignore]
    #[test]
    fn freezing_threshold() {
        with_agent(|agent| async move {
            let ic00 = ManagementCanister::create(&agent);

            assert!(ic00
                .create_canister()
                .as_provisional_create_with_amount(None)
                .with_freezing_threshold(2u128.pow(70))
                .call_and_wait(create_waiter())
                .await
                .is_err());

            Ok(())
        })
    }
}
