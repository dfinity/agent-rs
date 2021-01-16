use delay::Delay;
use ic_agent::export::Principal;
use ic_agent::identity::BasicIdentity;
use ic_agent::{Agent, Identity};
use ic_identity_hsm::HardwareIdentity;
use ic_utils::call::AsyncCall;
use ic_utils::interfaces::ManagementCanister;
use ring::signature::Ed25519KeyPair;
use std::error::Error;
use std::future::Future;
use std::path::Path;

pub fn create_waiter() -> Delay {
    Delay::builder()
        .throttle(std::time::Duration::from_millis(5))
        .timeout(std::time::Duration::from_secs(60 * 5))
        .build()
}

pub async fn create_identity() -> Result<Box<dyn Identity + Send + Sync>, String> {
    if std::env::var("HSM_PKCS11_LIBRARY_PATH").is_ok() {
        let hsm = create_hsm_identity().await?;
        Ok(Box::new(hsm))
    } else {
        let basic = create_basic_identity().await?;
        Ok(Box::new(basic))
    }
}

pub async fn create_hsm_identity() -> Result<HardwareIdentity, String> {
    let path = std::env::var("HSM_PKCS11_LIBRARY_PATH")
        .expect("Need to specify the HSM_PKCS11_LIBRARY_PATH environment variable");
    let slot_index = std::env::var("HSM_SLOT_INDEX")
        .expect("Need to specify the HSM_SLOT_INDEX environment variable");
    let slot_index = slot_index.into();
    let key =
        std::env::var("HSM_KEY_ID").expect("Need to specify the HSM_KEY_ID environment variable");
    HardwareIdentity::new(path, slot_index, &key, get_hsm_pin)
        //.map_err(|_| "unable to create hw identity".into())
        .map_err(|e| format!("Unable to create hw identity: {}", e))
}

fn get_hsm_pin() -> Result<String, String> {
    std::env::var("HSM_PIN").map_err(|_| "There is no HSM_PIN environment variable.".to_string())
}

pub async fn create_basic_identity() -> Result<BasicIdentity, String> {
    let rng = ring::rand::SystemRandom::new();
    let key_pair = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
        .expect("Could not generate a key pair.");

    Ok(BasicIdentity::from_key_pair(
        Ed25519KeyPair::from_pkcs8(key_pair.as_ref()).expect("Could not read the key pair."),
    ))
}

pub async fn create_agent(identity: Box<dyn Identity + Send + Sync>) -> Result<Agent, String> {
    let port_env = std::env::var("IC_REF_PORT")
        .expect("Need to specify the IC_REF_PORT environment variable.");
    let port = port_env
        .parse::<u32>()
        .expect("Could not parse the IC_REF_PORT environment variable as an integer.");

    Agent::builder()
        .with_url(format!("http://127.0.0.1:{}", port))
        .with_boxed_identity(identity)
        .build()
        .map_err(|e| format!("{:?}", e))
}

pub fn with_agent<F, R>(f: F)
where
    R: Future<Output = Result<(), Box<dyn Error>>>,
    F: FnOnce(Agent) -> R,
{
    let mut runtime = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    runtime.block_on(async {
        let agent_identity = create_identity()
            .await
            .expect("Could not create an identity.");
        let agent = create_agent(agent_identity)
            .await
            .expect("Could not create an agent.");
        agent
            .fetch_root_key()
            .await
            .expect("could not fetch root key");
        match f(agent).await {
            Ok(_) => {}
            Err(e) => assert!(false, "{:?}", e),
        };
    })
}

pub async fn create_universal_canister(agent: &Agent) -> Result<Principal, Box<dyn Error>> {
    let canister_env = std::env::var("IC_UNIVERSAL_CANISTER_PATH")
        .expect("Need to specify the IC_UNIVERSAL_CANISTER_PATH environment variable.");

    let canister_path = Path::new(&canister_env);

    let canister_wasm = if !canister_path.exists() {
        panic!("Could not find the universal canister WASM file.");
    } else {
        std::fs::read(&canister_path).expect("Could not read file.")
    };

    let ic00 = ManagementCanister::create(&agent);

    let (canister_id,) = ic00
        .create_canister()
        .call_and_wait(create_waiter())
        .await?;

    ic00.install_code(&canister_id, &canister_wasm)
        .with_raw_arg(vec![])
        .call_and_wait(create_waiter())
        .await?;

    Ok(canister_id)
}

pub async fn create_wallet_canister(agent: &Agent) -> Result<Principal, Box<dyn Error>> {
    let canister_env = std::env::var("IC_WALLET_CANISTER_PATH")
        .expect("Need to specify the IC_WALLET_CANISTER_PATH environment variable.");

    let canister_path = Path::new(&canister_env);

    let canister_wasm = if !canister_path.exists() {
        panic!("Could not find the wallet canister WASM file.");
    } else {
        std::fs::read(&canister_path).expect("Could not read file.")
    };

    let ic00 = ManagementCanister::create(&agent);
    let provisional_amount = 1 << 40;
    let (canister_id,) = ic00
        .provisional_create_canister_with_cycles(Some(provisional_amount))
        .call_and_wait(create_waiter())
        .await?;

    ic00.install_code(&canister_id, &canister_wasm)
        .with_raw_arg(vec![])
        .call_and_wait(create_waiter())
        .await?;

    Ok(canister_id)
}

pub fn with_universal_canister<F, R>(f: F)
where
    R: Future<Output = Result<(), Box<dyn Error>>>,
    F: FnOnce(Agent, Principal) -> R,
{
    with_agent(|agent| async move {
        let canister_id = create_universal_canister(&agent).await?;
        f(agent, canister_id).await
    })
}

pub fn with_wallet_canister<F, R>(f: F)
where
    R: Future<Output = Result<(), Box<dyn Error>>>,
    F: FnOnce(Agent, Principal) -> R,
{
    with_agent(|agent| async move {
        let canister_id = create_wallet_canister(&agent).await?;
        f(agent, canister_id).await
    })
}
