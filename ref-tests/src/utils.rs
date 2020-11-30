use candid::CandidType;
use delay::Delay;
use ic_agent::export::Principal;
use ic_agent::identity::BasicIdentity;
use ic_agent::Agent;
use ic_utils::call::AsyncCall;
use ic_utils::interfaces::ManagementCanister;
use ring::signature::Ed25519KeyPair;
use serde::Deserialize;
use std::error::Error;
use std::future::Future;
use std::path::Path;

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

pub async fn create_agent(identity: BasicIdentity) -> Result<Agent, String> {
    let port_env = std::env::var("IC_REF_PORT")
        .expect("Need to specify the IC_REF_PORT environment variable.");
    let port = port_env
        .parse::<u32>()
        .expect("Could not parse the IC_REF_PORT environment variable as an integer.");

    Agent::builder()
        .with_url(format!("http://127.0.0.1:{}", port))
        .with_identity(identity)
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

    #[derive(CandidType)]
    struct Input {
        amount: Option<candid::Nat>,
    }

    #[derive(Deserialize)]
    struct Output {
        canister_id: Principal,
    }

    // Specifying None for num_cycles will cause the canister to be created with
    // sufficiently large number of cycles that should allow it to exist without
    // needing to be refilled for a couple of months.
    let (Output { canister_id },) = ic00
        .update_("provisional_create_canister_with_cycles")
        .with_arg(Input { amount: None })
        .build()
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
