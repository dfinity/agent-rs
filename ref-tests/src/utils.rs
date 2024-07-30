use ic_agent::agent::http_transport::ReqwestTransport;
use ic_agent::identity::{Prime256v1Identity, Secp256k1Identity};
use ic_agent::{export::Principal, identity::BasicIdentity, Agent, Identity};
use ic_identity_hsm::HardwareIdentity;
use ic_utils::interfaces::{management_canister::builders::MemoryAllocation, ManagementCanister};
use ring::signature::Ed25519KeyPair;
use std::{convert::TryFrom, error::Error, future::Future, path::Path};

const HSM_PKCS11_LIBRARY_PATH: &str = "HSM_PKCS11_LIBRARY_PATH";
const HSM_SLOT_INDEX: &str = "HSM_SLOT_INDEX";
const HSM_KEY_ID: &str = "HSM_KEY_ID";
const HSM_PIN: &str = "HSM_PIN";

pub fn get_effective_canister_id() -> Principal {
    Principal::from_text("rwlgt-iiaaa-aaaaa-aaaaa-cai").unwrap()
}

pub fn create_identity() -> Result<Box<dyn Identity>, String> {
    if std::env::var(HSM_PKCS11_LIBRARY_PATH).is_ok() {
        create_hsm_identity().map(|x| Box::new(x) as _)
    } else {
        create_basic_identity().map(|x| Box::new(x) as _)
    }
}

fn expect_env_var(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("Need to specify the {} environment variable", name))
}

pub fn create_hsm_identity() -> Result<HardwareIdentity, String> {
    let path = expect_env_var(HSM_PKCS11_LIBRARY_PATH)?;
    let slot_index = expect_env_var(HSM_SLOT_INDEX)?
        .parse::<usize>()
        .map_err(|e| format!("Unable to parse {} value: {}", HSM_SLOT_INDEX, e))?;
    let key = expect_env_var(HSM_KEY_ID)?;
    let id = HardwareIdentity::new(path, slot_index, &key, get_hsm_pin)
        .map_err(|e| format!("Unable to create hw identity: {}", e))?;
    Ok(id)
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
pub fn create_basic_identity() -> Result<BasicIdentity, String> {
    let rng = ring::rand::SystemRandom::new();
    let key_pair = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
        .expect("Could not generate a key pair.");

    Ok(BasicIdentity::from_key_pair(
        Ed25519KeyPair::from_pkcs8(key_pair.as_ref()).expect("Could not read the key pair."),
    ))
}

/// Create a secp256k1identity, which unfortunately will always be the same one
/// (So can only use one per test)
pub fn create_secp256k1_identity() -> Result<Secp256k1Identity, String> {
    // generated from the the following commands:
    // $ openssl ecparam -name secp256k1 -genkey -noout -out identity.pem
    // $ cat identity.pem
    let identity_file = "
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIJb2C89BvmJERgnT/vJLKpdHZb/hqTiC8EY2QtBRWZScoAcGBSuBBAAK
oUQDQgAEDMl7g3vGKLsiLDA3fBRxDE9ZkM3GezZFa5HlKM/gYzNZfU3w8Tijjd73
yeMC60IsMNxDjLqElV7+T7dkb5Ki7Q==
-----END EC PRIVATE KEY-----";

    let identity = Secp256k1Identity::from_pem(identity_file.as_bytes())
        .expect("Cannot create secp256k1 identity from PEM file.");
    Ok(identity)
}

pub fn create_prime256v1_identity() -> Result<Prime256v1Identity, String> {
    // generated from the following command:
    // $ openssl ecparam -name prime256v1 -genkey -noout -out identity.pem
    // $ cat identity.pem
    let identity_file = "\
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIL1ybmbwx+uKYsscOZcv71MmKhrNqfPP0ke1unET5AY4oAoGCCqGSM49
AwEHoUQDQgAEUbbZV4NerZTPWfbQ749/GNLu8TaH8BUS/I7/+ipsu+MPywfnBFIZ
Sks4xGbA/ZbazsrMl4v446U5UIVxCGGaKw==
-----END EC PRIVATE KEY-----";

    let identity = Prime256v1Identity::from_pem(identity_file.as_bytes())
        .expect("Cannot create prime256v1 identity from PEM file.");
    Ok(identity)
}

pub async fn create_agent(identity: impl Identity + 'static) -> Result<Agent, String> {
    let port_env = std::env::var("IC_REF_PORT").unwrap_or_else(|_| "4943".into());
    let port = port_env
        .parse::<u32>()
        .expect("Could not parse the IC_REF_PORT environment variable as an integer.");

    let transport = ReqwestTransport::create(format!("http://127.0.0.1:{}", port)).unwrap();
    let transport = {
        #[cfg(feature = "experimental_sync_call")]
        {
            transport.with_use_call_v3_endpoint()
        }
        #[cfg(not(feature = "experimental_sync_call"))]
        {
            transport
        }
    };

    Agent::builder()
        .with_transport(transport)
        .with_identity(identity)
        .build()
        .map_err(|e| format!("{:?}", e))
}

pub fn with_agent<F, R>(f: F)
where
    R: Future<Output = Result<(), Box<dyn Error>>>,
    F: FnOnce(Agent) -> R,
{
    let agent_identity = create_identity().expect("Could not create an identity.");
    with_agent_as(agent_identity, f)
}

pub fn with_agent_as<I, F, R>(agent_identity: I, f: F)
where
    I: Identity + 'static,
    R: Future<Output = Result<(), Box<dyn Error>>>,
    F: FnOnce(Agent) -> R,
{
    let runtime = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    runtime.block_on(async {
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
        std::fs::read(canister_path).expect("Could not read file.")
    };

    let ic00 = ManagementCanister::create(agent);

    let (canister_id,) = ic00
        .create_canister()
        .as_provisional_create_with_amount(None)
        .with_effective_canister_id(get_effective_canister_id())
        .call_and_wait()
        .await?;

    ic00.install_code(&canister_id, &canister_wasm)
        .with_raw_arg(vec![])
        .call_and_wait()
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
        std::fs::read(canister_path).expect("Could not read file.")
    }
}

pub async fn create_wallet_canister(
    agent: &Agent,
    cycles: Option<u128>,
) -> Result<Principal, Box<dyn Error>> {
    let canister_wasm = get_wallet_wasm_from_env();

    let ic00 = ManagementCanister::create(agent);

    let (canister_id,) = ic00
        .create_canister()
        .as_provisional_create_with_amount(cycles)
        .with_effective_canister_id(get_effective_canister_id())
        .with_memory_allocation(
            MemoryAllocation::try_from(8000000000_u64)
                .expect("Memory allocation must be between 0 and 2^48 (i.e 256TB), inclusively."),
        )
        .call_and_wait()
        .await?;

    ic00.install_code(&canister_id, &canister_wasm)
        .with_raw_arg(vec![])
        .call_and_wait()
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

pub fn with_universal_canister_as<I, F, R>(identity: I, f: F)
where
    I: Identity + 'static,
    R: Future<Output = Result<(), Box<dyn Error>>>,
    F: FnOnce(Agent, Principal) -> R,
{
    with_agent_as(identity, |agent| async move {
        let canister_id = create_universal_canister(&agent).await?;
        f(agent, canister_id).await
    })
}

pub fn with_wallet_canister<F, R>(cycles: Option<u128>, f: F)
where
    R: Future<Output = Result<(), Box<dyn Error>>>,
    F: FnOnce(Agent, Principal) -> R,
{
    with_agent(|agent| async move {
        let canister_id = create_wallet_canister(&agent, cycles).await?;
        f(agent, canister_id).await
    })
}
