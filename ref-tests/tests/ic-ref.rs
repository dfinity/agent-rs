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

#[ignore]
#[test]
fn status_endpoint() {
    with_agent(|agent| async move {
        agent.status().await?;
        Ok(())
    })
}

mod management_canister {
    use candid::CandidType;
    use ic_agent::{
        agent::{RejectCode, RejectResponse},
        export::Principal,
        AgentError, Identity,
    };
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
    use ref_tests::{
        create_agent, create_basic_identity, create_prime256v1_identity, create_secp256k1_identity,
        with_agent, with_wallet_canister,
    };
    use ref_tests::{get_effective_canister_id, with_universal_canister};
    use sha2::{Digest, Sha256};
    use std::collections::HashSet;
    use std::convert::TryInto;

    mod create_canister {
        use super::with_agent;
        use ic_agent::{
            agent::{RejectCode, RejectResponse},
            export::Principal,
            AgentError,
        };

        use ic_utils::interfaces::ManagementCanister;
        use ref_tests::get_effective_canister_id;
        use std::str::FromStr;

        #[ignore]
        #[test]
        fn no_id_given() {
            with_agent(|agent| async move {
                let ic00 = ManagementCanister::create(&agent);

                let _ = ic00
                    .create_canister()
                    .as_provisional_create_with_amount(None)
                    .with_effective_canister_id(get_effective_canister_id())
                    .call_and_wait()
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
                    .call_and_wait()
                    .await;

                assert!(matches!(result,
                    Err(AgentError::UncertifiedReject(RejectResponse {
                    reject_code: RejectCode::DestinationInvalid,
                    reject_message,
                    error_code: Some(ref error_code)
                })) if reject_message == "Canister 75hes-oqbaa-aaaaa-aaaaa-aaaaa-aaaaa-aaaaa-q not found" &&
                        error_code == "IC0301"));

                Ok(())
            })
        }
    }

    #[ignore]
    #[test]
    fn management() {
        use ref_tests::get_effective_canister_id;
        with_agent(|agent| async move {
            let ic00 = ManagementCanister::create(&agent);

            let (canister_id,) = ic00
                .create_canister()
                .as_provisional_create_with_amount(None)
                .with_effective_canister_id(get_effective_canister_id())
                .call_and_wait()
                .await?;
            let canister_wasm = b"\0asm\x01\0\0\0".to_vec();

            // Install once.
            ic00.install_code(&canister_id, &canister_wasm)
                .with_mode(InstallMode::Install)
                .call_and_wait()
                .await?;

            // Re-install should fail.
            let result = ic00
                .install_code(&canister_id, &canister_wasm)
                .with_mode(InstallMode::Install)
                .call_and_wait()
                .await;

            assert!(matches!(result, Err(AgentError::CertifiedReject { .. })));

            // Reinstall should succeed.
            ic00.install_code(&canister_id, &canister_wasm)
                .with_mode(InstallMode::Reinstall)
                .call_and_wait()
                .await?;

            // Each agent has their own identity.
            let other_agent_identity = create_basic_identity()?;
            let other_agent_principal = other_agent_identity.sender()?;
            let other_agent = create_agent(other_agent_identity).await?;
            other_agent.fetch_root_key().await?;
            let other_ic00 = ManagementCanister::create(&other_agent);

            // Reinstall with another agent should fail.
            let result = other_ic00
                .install_code(&canister_id, &canister_wasm)
                .with_mode(InstallMode::Reinstall)
                .call_and_wait()
                .await;
            assert!(matches!(result, Err(AgentError::UncertifiedReject(..))));

            // Upgrade should succeed.
            ic00.install_code(&canister_id, &canister_wasm)
                .with_mode(InstallMode::Upgrade {
                    skip_pre_upgrade: None,
                })
                .call_and_wait()
                .await?;

            // Upgrade with another agent should fail.
            let result = other_ic00
                .install_code(&canister_id, &canister_wasm)
                .with_mode(InstallMode::Upgrade {
                    skip_pre_upgrade: None,
                })
                .call_and_wait()
                .await;
            assert!(matches!(result, Err(AgentError::UncertifiedReject(..))));

            // Change controller.
            ic00.update_settings(&canister_id)
                .with_controller(other_agent_principal)
                .call_and_wait()
                .await?;

            // Change controller with wrong controller should fail
            let result = ic00
                .update_settings(&canister_id)
                .with_controller(other_agent_principal)
                .call_and_wait()
                .await;
            assert!(
                matches!(result, Err(AgentError::UncertifiedReject(RejectResponse{
                reject_code: RejectCode::CanisterError,
                reject_message,
                error_code: Some(ref error_code),
            })) if reject_message == format!("Only controllers of canister {} can call ic00 method update_settings", canister_id) &&
                    error_code == "IC0512")
            );

            // Reinstall as new controller
            other_ic00
                .install_code(&canister_id, &canister_wasm)
                .with_mode(InstallMode::Reinstall)
                .call_and_wait()
                .await?;

            // Reinstall on empty should succeed.
            let (canister_id_2,) = ic00
                .create_canister()
                .as_provisional_create_with_amount(None)
                .with_effective_canister_id(get_effective_canister_id())
                .call_and_wait()
                .await?;

            // Reinstall over empty canister
            ic00.install_code(&canister_id_2, &canister_wasm)
                .with_mode(InstallMode::Reinstall)
                .call_and_wait()
                .await?;

            // Create an empty canister
            let (canister_id_3,) = other_ic00
                .create_canister()
                .as_provisional_create_with_amount(None)
                .with_effective_canister_id(get_effective_canister_id())
                .call_and_wait()
                .await?;

            // Check status for empty canister
            let result = other_ic00
                .canister_status(&canister_id_3)
                .call_and_wait()
                .await?;
            assert_eq!(result.0.status, CanisterStatus::Running);
            assert_eq!(result.0.settings.controllers.len(), 1);
            assert_eq!(result.0.settings.controllers[0], other_agent_principal);
            assert_eq!(result.0.module_hash, None);

            // Install wasm.
            other_ic00
                .install_code(&canister_id_3, &canister_wasm)
                .with_mode(InstallMode::Install)
                .call_and_wait()
                .await?;

            // Check status after installing wasm and validate module_hash
            let result = other_ic00
                .canister_status(&canister_id_3)
                .call_and_wait()
                .await?;
            let sha256_digest = Sha256::digest(&canister_wasm);
            assert_eq!(result.0.module_hash, Some(sha256_digest.to_vec()));

            Ok(())
        })
    }

    #[ignore]
    #[test]
    fn multiple_canisters_aaaaa_aa_but_really_provisional() {
        with_agent(|agent| async move {
            let agent_principal = agent.get_principal()?;
            // Each agent has their own identity.
            let other_agent_identity = create_basic_identity()?;
            let other_agent_principal = other_agent_identity.sender()?;
            let other_agent = create_agent(other_agent_identity).await?;
            other_agent.fetch_root_key().await?;
            let other_ic00 = ManagementCanister::create(&other_agent);

            let secp256k1_identity = create_secp256k1_identity()?;
            let secp256k1_principal = secp256k1_identity.sender()?;
            let secp256k1_agent = create_agent(secp256k1_identity).await?;
            secp256k1_agent.fetch_root_key().await?;
            let secp256k1_ic00 = ManagementCanister::create(&secp256k1_agent);

            let prime256v1_identity = create_prime256v1_identity()?;
            let prime256v1_principal = prime256v1_identity.sender()?;
            let prime256v1_agent = create_agent(prime256v1_identity).await?;
            prime256v1_agent.fetch_root_key().await?;
            let prime256v1_ic00 = ManagementCanister::create(&prime256v1_agent);

            let ic00 = ManagementCanister::create(&agent);

            let (canister_id,) = ic00
                .create_canister()
                .as_provisional_create_with_amount(None) // ok
                .with_effective_canister_id(get_effective_canister_id())
                //.with_canister_id("aaaaa-aa")
                .with_controller(agent_principal)
                .with_controller(other_agent_principal)
                .call_and_wait()
                .await?;

            // Controllers should be able to fetch the canister status.
            let result = ic00.canister_status(&canister_id).call_and_wait().await?;
            assert_eq!(result.0.settings.controllers.len(), 2);
            let actual = result
                .0
                .settings
                .controllers
                .iter()
                .cloned()
                .collect::<HashSet<_>>();
            let expected = [agent_principal, other_agent_principal]
                .iter()
                .cloned()
                .collect::<HashSet<_>>();
            assert_eq!(actual, expected);

            let result = other_ic00
                .canister_status(&canister_id)
                .call_and_wait()
                .await?;
            assert_eq!(result.0.settings.controllers.len(), 2);
            let actual = result
                .0
                .settings
                .controllers
                .iter()
                .cloned()
                .collect::<HashSet<_>>();
            let expected = [agent_principal, other_agent_principal]
                .iter()
                .cloned()
                .collect::<HashSet<_>>();
            assert_eq!(actual, expected);

            // Set new controller
            ic00.update_settings(&canister_id)
                .with_controller(secp256k1_principal)
                .call_and_wait()
                .await?;

            // Only that controller can get canister status
            let result = ic00.canister_status(&canister_id).call_and_wait().await;
            assert_err_or_reject(
                result,
                vec![RejectCode::DestinationInvalid, RejectCode::CanisterError],
            );
            let result = other_ic00
                .canister_status(&canister_id)
                .call_and_wait()
                .await;
            assert_err_or_reject(
                result,
                vec![RejectCode::DestinationInvalid, RejectCode::CanisterError],
            );

            let result = secp256k1_ic00
                .canister_status(&canister_id)
                .call_and_wait()
                .await?;
            assert_eq!(result.0.settings.controllers.len(), 1);
            assert_eq!(result.0.settings.controllers[0], secp256k1_principal);

            // Only that controller can change the controller again
            let result = ic00
                .update_settings(&canister_id)
                .with_controller(prime256v1_principal)
                .call_and_wait()
                .await;
            assert_err_or_reject(
                result,
                vec![RejectCode::DestinationInvalid, RejectCode::CanisterError],
            );
            let result = other_ic00
                .update_settings(&canister_id)
                .with_controller(prime256v1_principal)
                .call_and_wait()
                .await;
            assert_err_or_reject(
                result,
                vec![RejectCode::DestinationInvalid, RejectCode::CanisterError],
            );

            secp256k1_ic00
                .update_settings(&canister_id)
                .with_controller(prime256v1_principal)
                .call_and_wait()
                .await?;
            let result = secp256k1_ic00
                .canister_status(&canister_id)
                .call_and_wait()
                .await;
            assert_err_or_reject(
                result,
                vec![RejectCode::DestinationInvalid, RejectCode::CanisterError],
            );
            let result = prime256v1_ic00
                .canister_status(&canister_id)
                .call_and_wait()
                .await?;
            assert_eq!(result.0.settings.controllers.len(), 1);
            assert_eq!(result.0.settings.controllers[0], prime256v1_principal);

            Ok(())
        })
    }

    fn assert_err_or_reject<S>(
        result: Result<S, AgentError>,
        allowed_reject_codes: Vec<RejectCode>,
    ) {
        for expected_rc in &allowed_reject_codes {
            if matches!(result,
                Err(AgentError::UncertifiedReject(RejectResponse {
                reject_code,
                ..
            })) if reject_code == *expected_rc)
            {
                return;
            }
        }

        assert!(
            matches!(result, Err(AgentError::HttpError(_))),
            "expect an HttpError, or a CertifiedReject with reject_code in {:?}",
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
                .with_effective_canister_id(get_effective_canister_id())
                .call_and_wait()
                .await?;
            let canister_wasm = b"\0asm\x01\0\0\0".to_vec();

            // Install once.
            ic00.install_code(&canister_id, &canister_wasm)
                .with_mode(InstallMode::Install)
                .call_and_wait()
                .await?;

            // A newly installed canister should be running
            let result = ic00.canister_status(&canister_id).call_and_wait().await;
            assert_eq!(result?.0.status, CanisterStatus::Running);

            // Stop should succeed.
            ic00.stop_canister(&canister_id).call_and_wait().await?;

            // Canister should be stopped
            let result = ic00.canister_status(&canister_id).call_and_wait().await;
            assert_eq!(result?.0.status, CanisterStatus::Stopped);

            // Another stop is a noop
            ic00.stop_canister(&canister_id).call_and_wait().await?;

            // Can't call update on a stopped canister
            let result = agent.update(&canister_id, "update").call_and_wait().await;
            assert!(
                matches!(
                    &result,
                    Err(AgentError::UncertifiedReject(RejectResponse {
                        reject_code: RejectCode::CanisterError,
                        reject_message,
                        error_code: Some(error_code),
                    })) if *reject_message == format!("Canister {canister_id} is stopped")
                        && error_code == "IC0508"
                ),
                "wrong error: {result:?}"
            );

            // Can't call query on a stopped canister
            let result = agent.query(&canister_id, "query").with_arg([]).call().await;
            assert!(
                matches!(
                    &result,
                    Err(AgentError::UncertifiedReject(RejectResponse {
                        reject_code: RejectCode::CanisterError,
                        reject_message,
                        error_code: Some(error_code),
                    })) if *reject_message == format!("IC0508: Canister {canister_id} is stopped and therefore does not have a CallContextManager")
                        && error_code == "IC0508"
                ),
                "wrong error: {result:?}"
            );

            // Upgrade should succeed
            ic00.install_code(&canister_id, &canister_wasm)
                .with_mode(InstallMode::Upgrade {
                    skip_pre_upgrade: None,
                })
                .call_and_wait()
                .await?;

            // Start should succeed.
            ic00.start_canister(&canister_id).call_and_wait().await?;

            // Canister should be running
            let result = ic00.canister_status(&canister_id).call_and_wait().await;
            assert_eq!(result?.0.status, CanisterStatus::Running);

            // Can call update
            let result = agent.update(&canister_id, "update").call_and_wait().await;
            assert!(
                matches!(
                    &result,
                    Err(AgentError::CertifiedReject(RejectResponse {
                        reject_code: RejectCode::CanisterError,
                        reject_message,
                        error_code: None,
                    })) if *reject_message == format!("Canister {canister_id} has no update method 'update'")
                ),
                "wrong error: {result:?}"
            );

            // Can call query
            let result = agent.query(&canister_id, "query").with_arg([]).call().await;
            assert!(
                matches!(
                    &result,
                    Err(AgentError::UncertifiedReject(RejectResponse {
                        reject_code: RejectCode::CanisterError,
                        reject_message,
                        error_code: Some(error_code),
                    })) if *reject_message == format!("IC0536: Canister {} has no query method 'query'", canister_id)
                        && error_code == "IC0536",
                ),
                "wrong error: {result:?}"
            );

            // Another start is a noop
            ic00.start_canister(&canister_id).call_and_wait().await?;

            // Stop should succeed.
            ic00.stop_canister(&canister_id).call_and_wait().await?;

            // Delete a stopped canister succeeds.
            ic00.delete_canister(&canister_id).call_and_wait().await?;

            // Cannot call update
            let result = agent.update(&canister_id, "update").call_and_wait().await;
            assert!(
                matches!(
                    &result,
                    Err(AgentError::UncertifiedReject(RejectResponse {
                        reject_code: RejectCode::DestinationInvalid,
                        reject_message,
                        error_code: Some(error_code),
                    })) if *reject_message == format!("Canister {} not found", canister_id)
                        && error_code == "IC0301"
                ),
                "wrong error: {result:?}"
            );

            // Cannot call query
            let result = agent.query(&canister_id, "query").with_arg([]).call().await;
            assert!(
                matches!(
                    &result,
                    Err(AgentError::UncertifiedReject(RejectResponse {
                        reject_code: RejectCode::DestinationInvalid,
                        reject_message,
                        error_code: Some(error_code),
                    })) if *reject_message == format!("IC0301: Canister {} not found", canister_id)
                        && error_code == "IC0301"
                ),
                "wrong error: {result:?}"
            );

            // Cannot query canister status
            let result = ic00.canister_status(&canister_id).call_and_wait().await;
            assert!(
                match &result {
                    Err(AgentError::UncertifiedReject(RejectResponse {
                        reject_code: RejectCode::DestinationInvalid,
                        reject_message,
                        error_code: Some(error_code),
                    })) if *reject_message == format!("Canister {} not found", canister_id)
                        && error_code == "IC0301" =>
                    {
                        true
                    }
                    Ok((_status_call_result,)) => false,
                    _ => false,
                },
                "wrong error: {result:?}"
            );

            // Delete a deleted canister should fail.
            let result = ic00.delete_canister(&canister_id).call_and_wait().await;
            assert!(
                matches!(
                    &result,
                    Err(AgentError::UncertifiedReject(RejectResponse{
                        reject_code: RejectCode::DestinationInvalid,
                        reject_message,
                        error_code: Some(error_code),
                    })) if *reject_message == format!("Canister {} not found", canister_id)
                        && error_code == "IC0301"
                ),
                "wrong error: {result:?}"
            );
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
                .with_effective_canister_id(get_effective_canister_id())
                .call_and_wait()
                .await?;
            let canister_wasm = b"\0asm\x01\0\0\0".to_vec();

            // Install once.
            ic00.install_code(&canister_id, &canister_wasm)
                .with_mode(InstallMode::Install)
                .call_and_wait()
                .await?;

            // Create another agent with different identity.
            let other_agent_identity = create_basic_identity()?;
            let other_agent = create_agent(other_agent_identity).await?;
            other_agent.fetch_root_key().await?;
            let other_ic00 = ManagementCanister::create(&other_agent);

            // Start as a wrong controller should fail.
            let result = other_ic00
                .start_canister(&canister_id)
                .call_and_wait()
                .await;
            assert!(
                matches!(
                    &result,
                    Err(AgentError::UncertifiedReject(RejectResponse {
                        reject_code: RejectCode::CanisterError,
                        reject_message,
                        error_code: Some(error_code),
                    })) if *reject_message == format!("Only controllers of canister {} can call ic00 method start_canister", canister_id)
                        && error_code == "IC0512"
                ),
                "wrong error: {result:?}"
            );

            // Stop as a wrong controller should fail.
            let result = other_ic00.stop_canister(&canister_id).call_and_wait().await;
            assert!(
                matches!(
                    &result,
                    Err(AgentError::UncertifiedReject(RejectResponse {
                        reject_code: RejectCode::CanisterError,
                        reject_message,
                        error_code: Some(error_code),
                    })) if *reject_message == format!("Only controllers of canister {} can call ic00 method stop_canister", canister_id)
                        && error_code == "IC0512"
                ),
                "wrong error: {result:?}"
            );

            // Get canister status as a wrong controller should fail.
            let result = other_ic00
                .canister_status(&canister_id)
                .call_and_wait()
                .await;
            assert!(
                matches!(
                    &result,
                    Err(AgentError::UncertifiedReject(RejectResponse {
                        reject_code: RejectCode::CanisterError,
                        reject_message,
                        error_code: Some(error_code),
                    })) if *reject_message == format!("Only controllers of canister {canister_id} can call ic00 method canister_status")
                        && error_code == "IC0512"
                ),
                "wrong error: {result:?}"
            );

            // Delete as a wrong controller should fail.
            let result = other_ic00
                .delete_canister(&canister_id)
                .call_and_wait()
                .await;
            assert!(
                matches!(
                    &result,
                    Err(AgentError::UncertifiedReject(RejectResponse {
                        reject_code: RejectCode::CanisterError,
                        reject_message,
                        error_code: Some(error_code),
                    })) if *reject_message == format!("Only controllers of canister {canister_id} can call ic00 method delete_canister")
                        && error_code == "IC0512"
                ),
                "wrong error: {result:?}"
            );

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
                    reserved_cycles_limit: None,
                    wasm_memory_limit: None,
                },
            };

            let args = Argument::from_candid((create_args,));

            let creation_fee = 8000000000;
            let (create_result,): (CreateResult,) = wallet
                .call(
                    Principal::management_canister(),
                    "create_canister",
                    args,
                    creation_fee,
                )
                .call_and_wait()
                .await?;
            let canister_id = create_result.canister_id;

            #[derive(CandidType)]
            struct In {
                canister_id: Principal,
            }
            let status_args = In { canister_id };
            let args = Argument::from_candid((status_args,));

            let (result,): (StatusCallResult,) = wallet
                .call(Principal::management_canister(), "canister_status", args, 0)
                .call_and_wait()
                .await?;

            assert!(
                result.cycles > 0_u64 && result.cycles < creation_fee,
                "expected 0..{creation_fee}, got {}",
                result.cycles
            );

            let ic00 = ManagementCanister::create(&agent);
            // cycle balance is default_canister_balance when creating with
            // provisional_create_canister_with_cycles(None)
            let (canister_id_1,) = ic00
                .create_canister()
                .as_provisional_create_with_amount(None)
                .with_effective_canister_id(get_effective_canister_id())
                .call_and_wait()
                .await?;
            let result = ic00.canister_status(&canister_id_1).call_and_wait().await?;
            // assume some cycles are already burned
            let cycles: i128 = result.0.cycles.0.try_into().unwrap();
            let burned = default_canister_balance as i128 - cycles;
            assert!(burned > 0 && burned < 100_000_000);

            // cycle balance should be amount specified to
            // provisional_create_canister_with_cycles call
            let amount: u128 = 1 << 40; // 1099511627776
            let (canister_id_2,) = ic00
                .create_canister()
                .as_provisional_create_with_amount(Some(amount))
                .with_effective_canister_id(get_effective_canister_id())
                .call_and_wait()
                .await?;
            let result = ic00.canister_status(&canister_id_2).call_and_wait().await?;
            let cycles: i128 = result.0.cycles.0.try_into().unwrap();
            let burned = amount as i128 - cycles;
            assert!(
                burned > 0 && burned < 100_000_000,
                "expected 0..100_000_000, got {burned}"
            );

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
                .call_and_wait()
                .await?;
            let (rand_2,): (Vec<u8>,) = wallet
                .call(
                    Principal::management_canister(),
                    "raw_rand",
                    Argument::default(),
                    0,
                )
                .call_and_wait()
                .await?;
            let (rand_3,): (Vec<u8>,) = wallet
                .call(
                    Principal::management_canister(),
                    "raw_rand",
                    Argument::default(),
                    0,
                )
                .call_and_wait()
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
    fn chunked_wasm() {
        with_agent(|agent| async move {
            let wasm = b"\0asm\x01\0\0\0";
            let wasm_hash = Sha256::digest(wasm).to_vec();
            let mgmt = ManagementCanister::create(&agent);
            let (canister_id,) = mgmt
                .create_canister()
                .as_provisional_create_with_amount(None)
                .with_effective_canister_id(get_effective_canister_id())
                .call_and_wait()
                .await?;
            let (pt1,) = mgmt
                .upload_chunk(&canister_id, &wasm[0..4])
                .call_and_wait()
                .await?;
            let (pt2,) = mgmt
                .upload_chunk(&canister_id, &wasm[4..8])
                .call_and_wait()
                .await?;
            mgmt.install_chunked_code(&canister_id, &wasm_hash)
                .with_chunk_hashes(vec![pt1, pt2])
                .call_and_wait()
                .await?;
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

    #[ignore]
    #[test]
    fn subnet_metrics() {
        with_universal_canister(|agent, _| async move {
            let metrics = agent
                .read_state_subnet_metrics(Principal::self_authenticating(&agent.read_root_key()))
                .await?;
            assert!(
                metrics.num_canisters >= 1,
                "expected universal canister in num_canisters"
            );
            Ok(())
        })
    }
}

mod simple_calls {
    use crate::universal_canister::payload;
    use ic_agent::{
        agent::{RejectCode, RejectResponse},
        AgentError,
    };
    use ref_tests::with_universal_canister;

    #[ignore]
    #[test]
    fn call() {
        with_universal_canister(|agent, canister_id| async move {
            let arg = payload().reply_data(b"hello").build();
            let result = agent
                .update(&canister_id, "update")
                .with_arg(arg)
                .call_and_wait()
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
                .with_arg(arg.clone())
                .call()
                .await?;

            assert_eq!(result, b"hello");

            let result = agent
                .query(&canister_id, "query")
                .with_arg(arg)
                .with_nonce_generation()
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
                .with_arg(arg)
                .call_and_wait()
                .await;

            assert!(
                matches!(
                    &result,
                    Err(AgentError::CertifiedReject(RejectResponse {
                        reject_code: RejectCode::CanisterError,
                        ..
                    })),
                ),
                "wrong error: {result:?}"
            );
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
                .with_arg(arg)
                .call()
                .await;

            assert!(
                matches!(
                    &result,
                    Err(AgentError::UncertifiedReject(RejectResponse {
                        reject_code: RejectCode::CanisterError,
                        ..
                    }))
                ),
                "wrong error: {result:?}"
            );
            Ok(())
        })
    }
}

mod extras {
    use candid::Nat;
    use ic_agent::{
        agent::{RejectCode, RejectResponse},
        export::Principal,
        AgentError,
    };
    use ic_utils::{
        call::AsyncCall,
        interfaces::{management_canister::builders::ComputeAllocation, ManagementCanister},
    };
    use ref_tests::get_effective_canister_id;
    use ref_tests::with_agent;

    #[ignore]
    #[test]
    fn valid_allocations() {
        with_agent(|agent| async move {
            let ic00 = ManagementCanister::create(&agent);

            let (canister_id,) = ic00
                .create_canister()
                .as_provisional_create_with_amount(Some(20_000_000_000_000_u128))
                .with_effective_canister_id(get_effective_canister_id())
                .with_compute_allocation(1_u64)
                .with_memory_allocation(1024 * 1024_u64)
                .with_freezing_threshold(1_000_000_u64)
                .with_reserved_cycles_limit(2_500_800_000_000u128)
                .call_and_wait()
                .await?;

            let result = ic00.canister_status(&canister_id).call_and_wait().await?;
            assert_eq!(result.0.settings.compute_allocation, Nat::from(1_u64));
            assert_eq!(
                result.0.settings.memory_allocation,
                Nat::from(1024 * 1024_u64)
            );
            assert_eq!(
                result.0.settings.freezing_threshold,
                Nat::from(1_000_000_u64)
            );
            assert_eq!(
                result.0.settings.reserved_cycles_limit,
                Some(Nat::from(2_500_800_000_000u128))
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
            let result = ic00
                .create_canister()
                .as_provisional_create_with_amount(None)
                .with_effective_canister_id(get_effective_canister_id())
                .with_memory_allocation(1u64 << 50)
                .call_and_wait()
                .await;
            assert!(
                result.is_err(),
                "unexpected successful response: {result:?}"
            );

            let (_,) = ic00
                .create_canister()
                .as_provisional_create_with_amount(None)
                .with_effective_canister_id(get_effective_canister_id())
                .with_memory_allocation(10 * 1024 * 1024u64)
                .call_and_wait()
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
                .with_effective_canister_id(get_effective_canister_id())
                .with_compute_allocation(ca)
                .call_and_wait()
                .await?;

            Ok(())
        })
    }

    #[ignore]
    #[test]
    fn freezing_threshold() {
        with_agent(|agent| async move {
            let ic00 = ManagementCanister::create(&agent);
            let result = ic00
                .create_canister()
                .as_provisional_create_with_amount(None)
                .with_effective_canister_id(get_effective_canister_id())
                .with_freezing_threshold(2u128.pow(70))
                .call_and_wait()
                .await;
            assert!(
                result.is_err(),
                "unexpected successful response: {result:?}"
            );

            Ok(())
        })
    }

    #[ignore]
    #[test]
    fn create_with_reserved_cycles_limit() {
        with_agent(|agent| async move {
            let ic00 = ManagementCanister::create(&agent);

            let (canister_id,) = ic00
                .create_canister()
                .as_provisional_create_with_amount(None)
                .with_effective_canister_id(get_effective_canister_id())
                .with_reserved_cycles_limit(2u128.pow(70))
                .call_and_wait()
                .await
                .unwrap();

            let result = ic00.canister_status(&canister_id).call_and_wait().await?;
            assert_eq!(
                result.0.settings.reserved_cycles_limit,
                Some(Nat::from(2u128.pow(70)))
            );

            Ok(())
        })
    }

    #[ignore]
    #[test]
    fn update_reserved_cycles_limit() {
        with_agent(|agent| async move {
            let ic00 = ManagementCanister::create(&agent);

            let (canister_id,) = ic00
                .create_canister()
                .as_provisional_create_with_amount(Some(20_000_000_000_000_u128))
                .with_effective_canister_id(get_effective_canister_id())
                .with_reserved_cycles_limit(2_500_800_000_000u128)
                .call_and_wait()
                .await?;

            let result = ic00.canister_status(&canister_id).call_and_wait().await?;
            assert_eq!(
                result.0.settings.reserved_cycles_limit,
                Some(Nat::from(2_500_800_000_000u128))
            );

            ic00.update_settings(&canister_id)
                .with_reserved_cycles_limit(3_400_200_000_000u128)
                .call_and_wait()
                .await?;

            let result = ic00.canister_status(&canister_id).call_and_wait().await?;
            assert_eq!(
                result.0.settings.reserved_cycles_limit,
                Some(Nat::from(3_400_200_000_000u128))
            );

            let no_change: Option<u128> = None;
            ic00.update_settings(&canister_id)
                .with_optional_reserved_cycles_limit(no_change)
                .call_and_wait()
                .await?;

            let result = ic00.canister_status(&canister_id).call_and_wait().await?;
            assert_eq!(
                result.0.settings.reserved_cycles_limit,
                Some(Nat::from(3_400_200_000_000u128))
            );

            Ok(())
        })
    }

    #[ignore]
    #[test]
    fn specified_id() {
        with_agent(|agent| async move {
            let ic00 = ManagementCanister::create(&agent);
            let specified_id = Principal::from_text("iimsn-6yaaa-aaaaa-afiaa-cai").unwrap(); // [42, 0] should be large enough
            assert_eq!(
                ic00.create_canister()
                    .as_provisional_create_with_specified_id(specified_id)
                    .with_effective_canister_id(get_effective_canister_id())
                    .call_and_wait()
                    .await
                    .unwrap()
                    .0,
                specified_id
            );

            // create again with the same id should error
            let result = ic00
                .create_canister()
                .as_provisional_create_with_specified_id(specified_id)
                .with_effective_canister_id(get_effective_canister_id())
                .call_and_wait()
                .await;

            assert!(
                matches!(
                    &result,
                    Err(AgentError::CertifiedReject(RejectResponse {
                        reject_code: RejectCode::CanisterError,
                        reject_message,
                        error_code: None,
                    })) if reject_message == "Canister iimsn-6yaaa-aaaaa-afiaa-cai is already installed"
                ),
                "wrong error: {result:?}"
            );

            ic00.stop_canister(&specified_id)
                .call_and_wait()
                .await
                .unwrap();
            ic00.delete_canister(&specified_id)
                .call_and_wait()
                .await
                .unwrap();

            Ok(())
        })
    }

    #[ignore]
    #[test]
    fn create_with_wasm_memory_limit() {
        with_agent(|agent| async move {
            let ic00 = ManagementCanister::create(&agent);

            let (canister_id,) = ic00
                .create_canister()
                .as_provisional_create_with_amount(None)
                .with_effective_canister_id(get_effective_canister_id())
                .with_wasm_memory_limit(1_000_000_000)
                .call_and_wait()
                .await
                .unwrap();

            let result = ic00.canister_status(&canister_id).call_and_wait().await?;
            assert_eq!(
                result.0.settings.wasm_memory_limit,
                Some(Nat::from(1_000_000_000_u64))
            );

            Ok(())
        })
    }

    #[ignore]
    #[test]
    fn update_wasm_memory_limit() {
        with_agent(|agent| async move {
            let ic00 = ManagementCanister::create(&agent);

            let (canister_id,) = ic00
                .create_canister()
                .as_provisional_create_with_amount(Some(20_000_000_000_000_u128))
                .with_effective_canister_id(get_effective_canister_id())
                .with_wasm_memory_limit(1_000_000_000)
                .call_and_wait()
                .await?;

            let result = ic00.canister_status(&canister_id).call_and_wait().await?;
            assert_eq!(
                result.0.settings.wasm_memory_limit,
                Some(Nat::from(1_000_000_000_u64))
            );

            ic00.update_settings(&canister_id)
                .with_wasm_memory_limit(3_000_000_000_u64)
                .call_and_wait()
                .await?;

            let result = ic00.canister_status(&canister_id).call_and_wait().await?;
            assert_eq!(
                result.0.settings.wasm_memory_limit,
                Some(Nat::from(3_000_000_000_u64))
            );

            let no_change: Option<u64> = None;
            ic00.update_settings(&canister_id)
                .with_optional_wasm_memory_limit(no_change)
                .call_and_wait()
                .await?;

            let result = ic00.canister_status(&canister_id).call_and_wait().await?;
            assert_eq!(
                result.0.settings.wasm_memory_limit,
                Some(Nat::from(3_000_000_000_u64))
            );

            Ok(())
        })
    }
}
