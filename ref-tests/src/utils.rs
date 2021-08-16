use garcon::Delay;
use ic_agent::agent::http_transport::ReqwestHttpReplicaV2Transport;
use ic_agent::{export::Principal, identity::BasicIdentity, Agent, Identity};
use ic_identity_hsm::HardwareIdentity;
use ic_utils::interfaces::{management_canister::builders::MemoryAllocation, ManagementCanister};
use ring::signature::Ed25519KeyPair;
use std::{convert::TryFrom, error::Error, future::Future, path::Path};

const HSM_PKCS11_LIBRARY_PATH: &str = "HSM_PKCS11_LIBRARY_PATH";
const HSM_SLOT_INDEX: &str = "HSM_SLOT_INDEX";
const HSM_KEY_ID: &str = "HSM_KEY_ID";
const HSM_PIN: &str = "HSM_PIN";

pub fn create_waiter() -> Delay {
    Delay::builder()
        .throttle(std::time::Duration::from_secs(5))
        .build()
}

pub async fn create_identity() -> Result<Box<dyn Identity + Send + Sync>, String> {
    if std::env::var(HSM_PKCS11_LIBRARY_PATH).is_ok() {
        create_hsm_identity().await
    } else {
        create_basic_identity().await
    }
}

fn expect_env_var(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("Need to specify the {} environment variable", name))
}

pub async fn create_hsm_identity() -> Result<Box<dyn Identity + Send + Sync>, String> {
    let path = expect_env_var(HSM_PKCS11_LIBRARY_PATH)?;
    let slot_index = expect_env_var(HSM_SLOT_INDEX)?
        .parse::<usize>()
        .map_err(|e| format!("Unable to parse {} value: {}", HSM_SLOT_INDEX, e))?;
    let key = expect_env_var(HSM_KEY_ID)?;
    let id = HardwareIdentity::new(path, slot_index, &key, get_hsm_pin)
        .map_err(|e| format!("Unable to create hw identity: {}", e))?;
    Ok(Box::new(id))
}

fn get_hsm_pin() -> Result<String, String> {
    expect_env_var(HSM_PIN)
}

// The SoftHSM library doesn't like to have two contexts created/initialized at once.
// Trying to create two HardwareIdentity instances at the same time results in this error:
//    Unable to create hw identity: PKCS#11: CKR_CRYPTOKI_ALREADY_INITIALIZED (0x191)
//
// To avoid this, we use a basic identity for any second identity in tests.
//
// A shared container of Ctx objects might be possible instead, but my rust-fu is inadequate.
pub async fn create_basic_identity() -> Result<Box<dyn Identity + Send + Sync>, String> {
    let rng = ring::rand::SystemRandom::new();
    let key_pair = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
        .expect("Could not generate a key pair.");

    Ok(Box::new(BasicIdentity::from_key_pair(
        Ed25519KeyPair::from_pkcs8(key_pair.as_ref()).expect("Could not read the key pair."),
    )))
}

pub async fn create_agent(identity: Box<dyn Identity + Send + Sync>) -> Result<Agent, String> {
    let port_env = std::env::var("IC_REF_PORT")
        .expect("Need to specify the IC_REF_PORT environment variable.");
    let port = port_env
        .parse::<u32>()
        .expect("Could not parse the IC_REF_PORT environment variable as an integer.");

    Agent::builder()
        .with_transport(
            ReqwestHttpReplicaV2Transport::create(format!("http://127.0.0.1:{}", port)).unwrap(),
        )
        .with_boxed_identity(identity)
        .build()
        .map_err(|e| format!("{:?}", e))
}

pub fn with_agent<F, R>(f: F)
where
    R: Future<Output = Result<(), Box<dyn Error>>>,
    F: FnOnce(Agent) -> R,
{
    let runtime = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
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
            Err(e) => panic!("{:?}", e),
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
        .as_provisional_create_with_amount(None)
        .call_and_wait(create_waiter())
        .await?;

    ic00.install_code(&canister_id, &canister_wasm)
        .with_raw_arg(vec![])
        .call_and_wait(create_waiter())
        .await?;

    Ok(canister_id)
}

pub fn get_wallet_wasm_from_env() -> Vec<u8> {
    let canister_env = std::env::var("IC_WALLET_CANISTER_PATH")
        .expect("Need to specify the IC_WALLET_CANISTER_PATH environment variable.");

    let canister_path = Path::new(&canister_env);

    if !canister_path.exists() {
        panic!("Could not find the wallet canister WASM file.");
    } else {
        std::fs::read(&canister_path).expect("Could not read file.")
    }
}

pub async fn create_wallet_canister(
    agent: &Agent,
    cycles: Option<u64>,
) -> Result<Principal, Box<dyn Error>> {
    let canister_wasm = get_wallet_wasm_from_env();

    let ic00 = ManagementCanister::create(&agent);

    let (canister_id,) = ic00
        .create_canister()
        .as_provisional_create_with_amount(cycles)
        .with_memory_allocation(
            MemoryAllocation::try_from(8000000000_u64)
                .expect("Memory allocation must be between 0 and 2^48 (i.e 256TB), inclusively."),
        )
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

pub fn with_wallet_canister<F, R>(cycles: Option<u64>, f: F)
where
    R: Future<Output = Result<(), Box<dyn Error>>>,
    F: FnOnce(Agent, Principal) -> R,
{
    with_agent(|agent| async move {
        let canister_id = create_wallet_canister(&agent, cycles).await?;
        f(agent, canister_id).await
    })
}
