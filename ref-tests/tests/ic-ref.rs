//! In this file, please mark all tests that require a running ic-ref as ignored.
use delay::Delay;
use ic_agent::{
    Agent, AgentConfig, BasicIdentity, Blob, CanisterAttributes, Identity, InstallMode, Principal,
};
use ref_tests::universal_canister;
use ring::signature::Ed25519KeyPair;
use std::future::Future;

const EXPECTED_IC_API_VERSION: &str = "0.9.2";

fn create_waiter() -> Delay {
    Delay::builder()
        .throttle(std::time::Duration::from_millis(5))
        .timeout(std::time::Duration::from_millis(100))
        .build()
}

async fn create_identity() -> Result<Box<dyn Identity>, String> {
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
            &Blob::empty(),
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
    use ic_agent::{AgentError, Blob, CanisterAttributes, InstallMode};

    mod create_canister {
        use super::{create_waiter, with_agent};
        use ic_agent::{AgentError, Blob, CanisterAttributes, InstallMode, Principal};
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
                        &Blob::empty(),
                        &Blob::empty(),
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
            let canister_wasm = Blob::from(b"\0asm\x01\0\0\0");

            // Install once.
            ic00.install_code(
                create_waiter(),
                &canister_id,
                InstallMode::Install,
                &canister_wasm,
                &Blob::empty(),
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
                    &Blob::empty(),
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
                &Blob::empty(),
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
                    &Blob::empty(),
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
                &Blob::empty(),
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
                    &Blob::empty(),
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
                &Blob::empty(),
                &CanisterAttributes::default(),
            )
            .await?;

            // Canister Start, Stop, Status, and Delete tests.
            let canister_id_3 = ic00.create_canister(create_waiter()).await?;
            let canister_wasm = Blob::from(b"\0asm\x01\0\0\0");

            // Install once.
            ic00.install_code(
                create_waiter(),
                &canister_id_3,
                InstallMode::Install,
                &canister_wasm,
                &Blob::empty(),
                &CanisterAttributes::default(),
            )
            .await?;

            // A newly installed canister should be running
            let result = ic00.canister_status(create_waiter(), &canister_id_3).await;
            assert!(match result {
                Ok(ic_agent::CanisterStatus::Running) => true,
                Ok(ic_agent::CanisterStatus::Stopped) => false,
                Ok(ic_agent::CanisterStatus::Stopping) => false,
                Err(AgentError::ReplicaError { .. }) => false,
                _ => false,
            });

            // Stop should succeed.
            ic00.stop_canister(create_waiter(), &canister_id_3).await?;

            // Canister should be stopped
            let result = ic00.canister_status(create_waiter(), &canister_id_3).await;
            assert!(match result {
                Ok(ic_agent::CanisterStatus::Stopped) => true,
                Ok(ic_agent::CanisterStatus::Stopping) => false,
                Ok(ic_agent::CanisterStatus::Running) => false,
                Err(AgentError::ReplicaError { .. }) => false,
                _ => false,
            });

            // Start should succeed.
            ic00.start_canister(create_waiter(), &canister_id_3).await?;

            // Canister should be running
            let result = ic00.canister_status(create_waiter(), &canister_id_3).await;
            assert!(match result {
                Ok(ic_agent::CanisterStatus::Running) => true,
                Ok(ic_agent::CanisterStatus::Stopped) => false,
                Ok(ic_agent::CanisterStatus::Stopping) => false,
                Err(AgentError::ReplicaError { .. }) => false,
                _ => false,
            });

            // Delete a running canister should fail.
            let result = ic00.delete_canister(create_waiter(), &canister_id_3).await;
            assert!(match result {
                Err(AgentError::ReplicaError { .. }) => true,
                _ => false,
            });

            // Stop should succeed.
            ic00.stop_canister(create_waiter(), &canister_id_3).await?;

            // Delete a stopped canister succeeds.
            ic00.delete_canister(create_waiter(), &canister_id_3)
                .await?;

            Ok(())
        })
    }
}

mod simple_calls {
    use super::with_universal_canister;
    use crate::universal_canister::payload;
    use ic_agent::{AgentError, Blob};

    #[ignore]
    #[test]
    fn call() {
        with_universal_canister(|agent, canister_id| async move {
            let arg = payload().reply_data(b"hello").build();
            let result = agent.update(&canister_id, "update", &arg).await?;

            assert_eq!(result, Blob::from(b"hello"));
            Ok(())
        })
    }

    #[ignore]
    #[test]
    fn query() {
        with_universal_canister(|agent, canister_id| async move {
            let arg = payload().reply_data(b"hello").build();
            let result = agent.query(&canister_id, "query", &arg).await?;

            assert_eq!(result, Blob::from(b"hello"));
            Ok(())
        })
    }

    #[ignore]
    #[test]
    fn non_existant_call() {
        with_universal_canister(|agent, canister_id| async move {
            let arg = payload().reply_data(b"hello").build();
            let result = agent
                .update(&canister_id, "non_existent_method", &arg)
                .await;

            assert!(match result {
                Err(AgentError::ReplicaError { reject_code: 3, .. }) => true,
                _ => false,
            });
            Ok(())
        })
    }
}
