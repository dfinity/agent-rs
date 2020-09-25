//! In this file, please mark all tests that require a running ic-ref as ignored.
//!
//! These tests are a Rust-like version using the Agent to cover the same tests
//! as the IC Ref repo itself.
//!
//! The tests can be found in the Spec.hs file in the IC Ref repo.
//!
//! Try to keep these tests as close to 1-to-1 to the IC Ref test use cases. For
//! every spec in the IC Ref tests, there should be a matching spec here. Some
//! tests (like invalid CBOR or special Headers) might not be translatable, in
//! which case they should still be added here but do nothing (just keep the
//! use case being tested).
use ref_tests::universal_canister;
use ref_tests::with_agent;

const EXPECTED_IC_API_VERSION: &str = "0.10.3";

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
    use ic_agent::AgentError;
    use ic_agent::Identity;
    use ic_utils::call::AsyncCall;
    use ic_utils::interfaces::management_canister::{CanisterStatus, InstallMode};
    use ic_utils::interfaces::ManagementCanister;
    use ref_tests::{create_agent, create_identity, create_waiter, with_agent};

    mod create_canister {
        use super::{create_waiter, with_agent};
        use ic_agent::export::Principal;
        use ic_agent::AgentError;
        use ic_utils::call::AsyncCall;
        use ic_utils::interfaces::ManagementCanister;
        use std::str::FromStr;

        #[ignore]
        #[test]
        fn no_id_given() {
            with_agent(|agent| async move {
                let ic00 = ManagementCanister::create(&agent);

                let _ = ic00
                    .create_canister()
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

                assert!(match result {
                    Err(AgentError::ReplicaError { reject_code: c, .. }) if c == 3 || c == 5 =>
                        true,
                    _ => false,
                });

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

            assert!(match result {
                Err(AgentError::ReplicaError { .. }) => true,
                _ => false,
            });

            // Reinstall should succeed.
            ic00.install_code(&canister_id, &canister_wasm)
                .with_mode(InstallMode::Reinstall)
                .call_and_wait(create_waiter())
                .await?;

            // Each agent has their own identity.
            let other_agent_identity = create_identity().await?;
            let other_agent_principal = other_agent_identity.sender()?;
            let other_agent = create_agent(other_agent_identity).await?;
            let other_ic00 = ManagementCanister::create(&other_agent);

            // Reinstall with another agent should fail.
            let result = other_ic00
                .install_code(&canister_id, &canister_wasm)
                .with_mode(InstallMode::Reinstall)
                .call_and_wait(create_waiter())
                .await;
            assert!(match result {
                Err(AgentError::ReplicaError { .. }) => true,
                _ => false,
            });

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
            assert!(match result {
                Err(AgentError::ReplicaError { .. }) => true,
                _ => false,
            });

            // Change controller.
            ic00.set_controller(&canister_id, &other_agent_principal)
                .call_and_wait(create_waiter())
                .await?;

            // Change controller with wrong controller should fail
            let result = ic00
                .set_controller(&canister_id, &other_agent_principal)
                .call_and_wait(create_waiter())
                .await;
            assert!(match result {
                Err(AgentError::ReplicaError {
                    reject_code: 5,
                    reject_message,
                }) if reject_message.contains("is not authorized to manage canister") => true,
                _ => false,
            });

            // Reinstall as new controller
            other_ic00
                .install_code(&canister_id, &canister_wasm)
                .with_mode(InstallMode::Reinstall)
                .call_and_wait(create_waiter())
                .await?;

            // Reinstall on empty should succeed.
            let (canister_id_2,) = ic00
                .create_canister()
                .call_and_wait(create_waiter())
                .await?;

            ic00.install_code(&canister_id_2, &canister_wasm)
                .with_mode(InstallMode::Reinstall)
                .call_and_wait(create_waiter())
                .await?;

            Ok(())
        })
    }

    #[ignore]
    #[test]
    fn canister_lifecycle_and_delete() {
        with_agent(|agent| async move {
            let ic00 = ManagementCanister::create(&agent);
            let (canister_id,) = ic00
                .create_canister()
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
            assert_eq!(result?.0, CanisterStatus::Running);

            // Stop should succeed.
            ic00.stop_canister(&canister_id)
                .call_and_wait(create_waiter())
                .await?;

            // Canister should be stopped
            let result = ic00
                .canister_status(&canister_id)
                .call_and_wait(create_waiter())
                .await;
            assert_eq!(result?.0, CanisterStatus::Stopped);

            // Another stop is a noop
            ic00.stop_canister(&canister_id)
                .call_and_wait(create_waiter())
                .await?;

            // Can't call update on a stopped canister
            let result = agent
                .update(&canister_id, "update")
                .call_and_wait(create_waiter())
                .await;
            assert!(match result {
                Err(AgentError::ReplicaError {
                    reject_code: 5,
                    reject_message,
                }) if reject_message == "canister is stopped" => true,
                _ => false,
            });

            // Can't call query on a stopped canister
            let result = agent
                .query(&canister_id, "query")
                .with_arg(&[])
                .call()
                .await;
            assert!(match result {
                Err(AgentError::ReplicaError {
                    reject_code: 5,
                    reject_message,
                }) if reject_message == "canister is stopped" => true,
                _ => false,
            });

            // Start should succeed.
            ic00.start_canister(&canister_id)
                .call_and_wait(create_waiter())
                .await?;

            // Canister should be running
            let result = ic00
                .canister_status(&canister_id)
                .call_and_wait(create_waiter())
                .await;
            assert_eq!(result?.0, CanisterStatus::Running);

            // Can call update
            let result = agent
                .update(&canister_id, "update")
                .call_and_wait(create_waiter())
                .await;
            assert!(match result {
                Err(AgentError::ReplicaError {
                    reject_code: 3,
                    reject_message,
                }) if reject_message == "method does not exist: update" => true,
                _ => false,
            });

            // Can call query
            let result = agent
                .query(&canister_id, "query")
                .with_arg(&[])
                .call()
                .await;
            assert!(match result {
                Err(AgentError::ReplicaError {
                    reject_code: 3,
                    reject_message,
                }) if reject_message == "query method does not exist" => true,
                _ => false,
            });

            // Another start is a noop
            ic00.start_canister(&canister_id)
                .call_and_wait(create_waiter())
                .await?;

            // Delete a running canister should fail.
            let result = ic00
                .delete_canister(&canister_id)
                .call_and_wait(create_waiter())
                .await;
            assert!(match result {
                Err(AgentError::ReplicaError { .. }) => true,
                _ => false,
            });

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
            assert!(match result {
                Err(AgentError::ReplicaError {
                    reject_code: 3,
                    reject_message,
                }) if reject_message
                    == format!("canister no longer exists: {}", canister_id.to_text()) =>
                    true,
                _ => false,
            });

            // Cannot call query
            let result = agent
                .query(&canister_id, "query")
                .with_arg(&[])
                .call()
                .await;
            assert!(match result {
                Err(AgentError::ReplicaError {
                    reject_code: 3,
                    reject_message,
                }) if reject_message
                    == format!("canister no longer exists: {}", canister_id.to_text()) =>
                    true,
                _ => false,
            });

            // Cannot query canister status
            let result = ic00
                .canister_status(&canister_id)
                .call_and_wait(create_waiter())
                .await;
            assert!(match result {
                Err(AgentError::ReplicaError {
                    reject_code: 5,
                    reject_message,
                }) if reject_message
                    == format!("canister no longer exists: {}", canister_id.to_text()) =>
                    true,
                Ok((CanisterStatus::Stopped,)) => false,
                Ok((CanisterStatus::Stopping,)) => false,
                Ok((CanisterStatus::Running,)) => false,
                _ => false,
            });

            // Delete a running canister should fail.
            let result = ic00
                .delete_canister(&canister_id)
                .call_and_wait(create_waiter())
                .await;
            assert!(match result {
                Err(AgentError::ReplicaError {
                    reject_code: 5,
                    reject_message,
                }) if reject_message
                    == format!("canister no longer exists: {}", canister_id.to_text()) =>
                    true,
                _ => false,
            });

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
                .call_and_wait(create_waiter())
                .await?;
            let canister_wasm = b"\0asm\x01\0\0\0".to_vec();

            // Install once.
            ic00.install_code(&canister_id, &canister_wasm)
                .with_mode(InstallMode::Install)
                .call_and_wait(create_waiter())
                .await?;

            // Create another agent with different identity.
            let other_agent_identity = create_identity().await?;
            let other_agent = create_agent(other_agent_identity).await?;
            let other_ic00 = ManagementCanister::create(&other_agent);

            // Start as a wrong controller should fail.
            let result = other_ic00
                .start_canister(&canister_id)
                .call_and_wait(create_waiter())
                .await;
            assert!(match result {
                Err(AgentError::ReplicaError {
                    reject_code: 5,
                    reject_message,
                }) if reject_message.contains("is not authorized to manage canister") => true,
                _ => false,
            });

            // Stop as a wrong controller should fail.
            let result = other_ic00
                .stop_canister(&canister_id)
                .call_and_wait(create_waiter())
                .await;
            assert!(match result {
                Err(AgentError::ReplicaError {
                    reject_code: 5,
                    reject_message,
                }) if reject_message.contains("is not authorized to manage canister") => true,
                _ => false,
            });

            // Get canister status as a wrong controller should fail.
            let result = other_ic00
                .canister_status(&canister_id)
                .call_and_wait(create_waiter())
                .await;
            assert!(match result {
                Err(AgentError::ReplicaError {
                    reject_code: 5,
                    reject_message,
                }) if reject_message.contains("is not authorized to manage canister") => true,
                _ => false,
            });

            // Delete as a wrong controller should fail.
            let result = other_ic00
                .delete_canister(&canister_id)
                .call_and_wait(create_waiter())
                .await;
            assert!(match result {
                Err(AgentError::ReplicaError {
                    reject_code: 5,
                    reject_message,
                }) if reject_message.contains("is not authorized to manage canister") => true,
                _ => false,
            });

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

            assert!(match result {
                Err(AgentError::ReplicaError { reject_code: 3, .. }) => true,
                _ => false,
            });
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

            assert!(match result {
                Err(AgentError::ReplicaError { reject_code: 3, .. }) => true,
                _ => false,
            });
            Ok(())
        })
    }
}

mod extras {
    use ic_utils::call::AsyncCall;
    use ic_utils::interfaces::ManagementCanister;
    use ref_tests::{create_waiter, with_agent};

    #[ignore]
    #[test]
    fn memory_allocation() {
        with_agent(|agent| async move {
            let ic00 = ManagementCanister::create(&agent);
            let (canister_id,) = ic00
                .create_canister()
                .call_and_wait(create_waiter())
                .await?;
            let canister_wasm = b"\0asm\x01\0\0\0".to_vec();

            // Prevent installing with over 1 << 48. This does not contact the server.
            assert!(ic00
                .install_code(&canister_id, &canister_wasm)
                .with_memory_allocation(1u64 << 50)
                .call_and_wait(create_waiter())
                .await
                .is_err());

            ic00.install_code(&canister_id, &canister_wasm)
                .with_memory_allocation(10 * 1024 * 1024u64)
                .call_and_wait(create_waiter())
                .await?;

            Ok(())
        })
    }

    #[ignore]
    #[test]
    fn compute_allocation() {
        with_agent(|agent| async move {
            let ic00 = ManagementCanister::create(&agent);
            let (canister_id,) = ic00
                .create_canister()
                .call_and_wait(create_waiter())
                .await?;
            let canister_wasm = b"\0asm\x01\0\0\0".to_vec();

            ic00.install_code(&canister_id, &canister_wasm)
                .with_compute_allocation(10)
                .call_and_wait(create_waiter())
                .await?;

            Ok(())
        })
    }
}
