use crate::universal_canister;
use delay::Delay;
use ic_agent::{Agent, BasicIdentity, Principal};
use ic_utils::call::AsyncCall;
use ic_utils::interfaces::ManagementCanister;
use ring::signature::Ed25519KeyPair;
use std::future::Future;

pub fn create_waiter() -> Delay {
    Delay::builder()
        .throttle(std::time::Duration::from_millis(5))
        .timeout(std::time::Duration::from_secs(60 * 5))
        .build()
}

pub async fn create_identity() -> Result<BasicIdentity, String> {
    let rng = ring::rand::SystemRandom::new();
    let key_pair = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
        .expect("Could not generate a key pair.");

    Ok(BasicIdentity::from_key_pair(
        Ed25519KeyPair::from_pkcs8(key_pair.as_ref()).expect("Could not read the key pair."),
    ))
}

pub async fn create_agent() -> Result<Agent, String> {
    let port_env = std::env::var("IC_REF_PORT")
        .expect("Need to specify the IC_REF_PORT environment variable.");
    let port = port_env
        .parse::<u32>()
        .expect("Could not parse the IC_REF_PORT environment variable as an integer.");

    Agent::builder()
        .with_url(format!("http://127.0.0.1:{}", port))
        .with_identity(create_identity().await?)
        .build()
        .map_err(|e| format!("{:?}", e))
}

pub fn with_agent<F, R>(f: F)
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

pub fn with_universal_canister<F, R>(f: F)
where
    R: Future<Output = Result<(), Box<dyn std::error::Error>>>,
    F: FnOnce(Agent, Principal) -> R,
{
    let mut runtime = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    match runtime.block_on(async {
        let canister_wasm = universal_canister::wasm();

        let agent = create_agent().await.expect("Could not create an agent.");
        let ic00 = ManagementCanister::create(&agent);

        let (canister_id,) = ic00
            .create_canister()
            .call_and_wait(create_waiter())
            .await?;

        ic00.install_code(&canister_id, &canister_wasm)
            .with_raw_arg(vec![])
            .call_and_wait(create_waiter())
            .await?;

        f(agent, canister_id).await
    }) {
        Ok(_) => {}
        Err(e) => assert!(false, "{:?}", e),
    };
}
