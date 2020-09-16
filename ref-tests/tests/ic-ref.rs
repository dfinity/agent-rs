//! In this file, please mark all tests that require a running ic-ref as ignored.
use delay::Delay;
use ic_agent::{
    Agent, AgentConfig, BasicIdentity, CanisterAttributes, Identity, InstallMode, Principal,
};
use ref_tests::universal_canister;
use ring::signature::Ed25519KeyPair;
use std::future::Future;

const EXPECTED_IC_API_VERSION: &str = "0.10.2";

fn create_waiter() -> Delay {
    Delay::builder()
        .throttle(std::time::Duration::from_millis(5))
        .timeout(std::time::Duration::from_secs(60 * 5))
        .build()
}

async fn create_identity() -> Result<Box<dyn Identity + Sync + Send>, String> {
    let rng = ring::rand::SystemRandom::new();
    let key_pair = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
        .expect("Could not generate a key pair.");

    Ok(Box::new(BasicIdentity::from_key_pair(
        Ed25519KeyPair::from_pkcs8(key_pair.as_ref()).expect("Could not read the key pair."),
    )))
}

async fn create_agent() -> Result<Agent, String> {
    let port_env = std::env::var("IC_REF_PORT")
        .expect("Need to specify the IC_REF_PORT environment variable.");
    let port = port_env
        .parse::<u32>()
        .expect("Could not parse the IC_REF_PORT environment variable as an integer.");

    Ok(ic_agent::Agent::new(AgentConfig {
        url: format!("http://127.0.0.1:{}", port),
        identity: create_identity().await?,
        ..AgentConfig::default()
    })
    .map_err(|e| format!("{}", e))?)
}

fn with_agent<F, R>(f: F)
where
    R: Future<Output = Result<(), Box<dyn std::error::Error>>>,
    F: FnOnce(Agent) -> R,
{
    let mut runtime = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    runtime.block_on(async {
        let agent = create_agent().await.expect("Could not create an agent.");
        match f(agent).await {
            Ok(_) => {}
            Err(e) => assert!(false, "{:?}", e),
        };
    })
}

fn with_universal_canister<F, R>(f: F)
where
    R: Future<Output = Result<(), Box<dyn std::error::Error>>>,
    F: FnOnce(Agent, Principal) -> R,
{
    let mut runtime = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    match runtime.block_on(async {
        let canister_wasm = universal_canister::wasm();

        let agent = create_agent().await.expect("Could not create an agent.");
        let ic00 = ic_agent::ManagementCanister::new(&agent);

        let canister_id = ic00.create_canister(create_waiter()).await?;
        ic00.install_code(
            create_waiter(),
            &canister_id,
            InstallMode::Install,
            &canister_wasm,
            &[],
            &CanisterAttributes::default(),
        )
        .await?;

        f(agent, canister_id).await
    }) {
        Ok(_) => {}
        Err(e) => assert!(false, "{:?}", e),
    };
}

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
    use super::{create_agent, create_waiter, with_agent};
    use ic_agent::{AgentError, CanisterAttributes, InstallMode};

    mod create_canister {
        use super::{create_waiter, with_agent};
        use ic_agent::{AgentError, CanisterAttributes, InstallMode, Principal};
        use std::str::FromStr;

        #[ignore]
        #[test]
        fn no_id_given() {
            with_agent(|agent| async move {
                let ic00 = ic_agent::ManagementCanister::new(&agent);
                let _ = ic00.create_canister(create_waiter()).await?;

                Ok(())
            })
        }

        #[ignore]
        #[test]
        fn create_canister_necessary() {
            with_agent(|agent| async move {
                let ic00 = ic_agent::ManagementCanister::new(&agent);

                let result = ic00
                    .install_code(
                        create_waiter(),
                        &Principal::from_str("75hes-oqbaa-aaaaa-aaaaa-aaaaa-aaaaa-aaaaa-q")
                            .unwrap(),
                        InstallMode::Install,
                        &[],
                        &[],
                        &CanisterAttributes::default(),
                    )
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
            let ic00 = ic_agent::ManagementCanister::new(&agent);
            let canister_id = ic00.create_canister(create_waiter()).await?;
            let canister_wasm = b"\0asm\x01\0\0\0".to_vec();

            // Install once.
            ic00.install_code(
                create_waiter(),
                &canister_id,
                InstallMode::Install,
                &canister_wasm,
                &[],
                &CanisterAttributes::default(),
            )
            .await?;

            // Re-install should fail.
            let result = ic00
                .install_code(
                    create_waiter(),
                    &canister_id,
                    InstallMode::Install,
                    &canister_wasm,
                    &[],
                    &CanisterAttributes::default(),
                )
                .await;
            assert!(match result {
                Err(AgentError::ReplicaError { .. }) => true,
                _ => false,
            });

            // Reinstall should succeed.
            ic00.install_code(
                create_waiter(),
                &canister_id,
                InstallMode::Reinstall,
                &canister_wasm,
                &[],
                &CanisterAttributes::default(),
            )
            .await?;

            // Each agent has their own identity.
            let other_agent = create_agent().await?;
            let other_ic00 = ic_agent::ManagementCanister::new(&other_agent);

            // Reinstall with another agent should fail.
            let result = other_ic00
                .install_code(
                    create_waiter(),
                    &canister_id,
                    InstallMode::Reinstall,
                    &canister_wasm,
                    &[],
                    &CanisterAttributes::default(),
                )
                .await;
            assert!(match result {
                Err(AgentError::ReplicaError { .. }) => true,
                _ => false,
            });

            // Upgrade should succeed.
            ic00.install_code(
                create_waiter(),
                &canister_id,
                InstallMode::Upgrade,
                &canister_wasm,
                &[],
                &CanisterAttributes::default(),
            )
            .await?;

            // Upgrade with another agent should fail.
            let result = other_ic00
                .install_code(
                    create_waiter(),
                    &canister_id,
                    InstallMode::Upgrade,
                    &canister_wasm,
                    &[],
                    &CanisterAttributes::default(),
                )
                .await;
            assert!(match result {
                Err(AgentError::ReplicaError { .. }) => true,
                _ => false,
            });

            // Change controller.
            // TODO: set controller tests.

            // Reinstall on empty should succeed.
            let canister_id_2 = ic00.create_canister(create_waiter()).await?;
            ic00.install_code(
                create_waiter(),
                &canister_id_2,
                InstallMode::Reinstall,
                &canister_wasm,
                &[],
                &CanisterAttributes::default(),
            )
            .await?;

            Ok(())
        })
    }

    #[ignore]
    #[test]
    fn canister_lifecycle_and_delete() {
        with_agent(|agent| async move {
            let ic00 = ic_agent::ManagementCanister::new(&agent);
            let canister_id = ic00.create_canister(create_waiter()).await?;
            let canister_wasm = b"\0asm\x01\0\0\0".to_vec();

            // Install once.
            ic00.install_code(
                create_waiter(),
                &canister_id,
                InstallMode::Install,
                &canister_wasm,
                &[],
                &CanisterAttributes::default(),
            )
            .await?;

            // A newly installed canister should be running
            let result = ic00.canister_status(create_waiter(), &canister_id).await;
            assert_eq!(result?, ic_agent::CanisterStatus::Running);

            // Stop should succeed.
            ic00.stop_canister(create_waiter(), &canister_id).await?;

            // Canister should be stopped
            let result = ic00.canister_status(create_waiter(), &canister_id).await;
            assert_eq!(result?, ic_agent::CanisterStatus::Stopped);

            // Another stop is a noop
            ic00.stop_canister(create_waiter(), &canister_id).await?;

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
            let result = agent.query_raw(&canister_id, "query", &[], None).await;
            assert!(match result {
                Err(AgentError::ReplicaError {
                    reject_code: 5,
                    reject_message,
                }) if reject_message == "canister is stopped" => true,
                _ => false,
            });

            // Start should succeed.
            ic00.start_canister(create_waiter(), &canister_id).await?;

            // Canister should be running
            let result = ic00.canister_status(create_waiter(), &canister_id).await;
            assert_eq!(result?, ic_agent::CanisterStatus::Running);

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
            let result = agent.query_raw(&canister_id, "query", &[], None).await;
            assert!(match result {
                Err(AgentError::ReplicaError {
                    reject_code: 3,
                    reject_message,
                }) if reject_message == "query method does not exist" => true,
                _ => false,
            });

            // Another start is a noop
            ic00.start_canister(create_waiter(), &canister_id).await?;

            // Delete a running canister should fail.
            let result = ic00.delete_canister(create_waiter(), &canister_id).await;
            assert!(match result {
                Err(AgentError::ReplicaError { .. }) => true,
                _ => false,
            });

            // Stop should succeed.
            ic00.stop_canister(create_waiter(), &canister_id).await?;

            // Delete a stopped canister succeeds.
            ic00.delete_canister(create_waiter(), &canister_id).await?;

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
            let result = agent.query_raw(&canister_id, "query", &[], None).await;
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
            let result = ic00.canister_status(create_waiter(), &canister_id).await;
            assert!(match result {
                Err(AgentError::ReplicaError {
                    reject_code: 5,
                    reject_message,
                }) if reject_message
                    == format!("canister no longer exists: {}", canister_id.to_text()) =>
                    true,
                Ok(ic_agent::CanisterStatus::Stopped) => false,
                Ok(ic_agent::CanisterStatus::Stopping) => false,
                Ok(ic_agent::CanisterStatus::Running) => false,
                _ => false,
            });

            // Delete a running canister should fail.
            let result = ic00.delete_canister(create_waiter(), &canister_id).await;
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
}

mod simple_calls {
    use super::{create_waiter, with_universal_canister};
    use crate::universal_canister::payload;
    use ic_agent::AgentError;

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
            let result = agent.query_raw(&canister_id, "query", &arg, None).await?;

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
}
