use candid::CandidType;
use delay::Delay;
use ic_agent::export::Principal;
use ic_agent::identity::BasicIdentity;
use ic_agent::{Agent, AgentError};
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
        if let Err(e) = f(agent).await {
            match e.downcast_ref::<AgentError>() {
                Some(AgentError::HttpError {
                    status,
                    content,
                    content_type,
                }) if is_plain_text_utf8(content_type) => assert!(
                    false,
                    "Agent Error: Http Error: status: {}, content type: {}, content: {}",
                    status,
                    content_type.as_ref().unwrap(),
                    String::from_utf8(content.to_vec()).unwrap_or_else(|from_utf8_err| format!(
                        "(unable to decode content: {:#?})",
                        from_utf8_err
                    ))
                ),
                _ => assert!(false, "{:?}", e),
            }
        };
    })
}

fn is_plain_text_utf8(content_type: &Option<String>) -> bool {
    // text/plain is also sometimes returned by the replica (or ic-ref),
    // depending on where in the stack the error happens.
    matches!(
        content_type.as_ref().and_then(|s|s.parse::<mime::Mime>().ok()),
        Some(mt) if mt == mime::TEXT_PLAIN || mt == mime::TEXT_PLAIN_UTF_8
    )
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
        num_cycles: candid::Nat,
        num_icpt: candid::Nat,
    }

    #[derive(Deserialize)]
    struct Output {
        canister_id: Principal,
    }

    let (Output { canister_id },) = ic00
        .update_("dev_create_canister_with_funds")
        .with_arg(Input {
            num_cycles: candid::Nat::from(1_000_000_000_000u64),
            num_icpt: candid::Nat::from(1_000u64),
        })
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
