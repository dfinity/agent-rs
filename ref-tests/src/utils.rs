use ic_agent::export::reqwest::Url;
use ic_agent::identity::{Prime256v1Identity, Secp256k1Identity};
use ic_agent::{export::Principal, identity::BasicIdentity, Agent, Identity};
use ic_identity_hsm::HardwareIdentity;
use ic_utils::interfaces::{management_canister::builders::MemoryAllocation, ManagementCanister};
use pocket_ic::nonblocking::PocketIc;
use pocket_ic::PocketIcBuilder;
use std::time::Duration;
use std::{convert::TryFrom, error::Error};

const HSM_PKCS11_LIBRARY_PATH: &str = "HSM_PKCS11_LIBRARY_PATH";
const HSM_SLOT_INDEX: &str = "HSM_SLOT_INDEX";
const HSM_KEY_ID: &str = "HSM_KEY_ID";
const HSM_PIN: &str = "HSM_PIN";

pub async fn get_effective_canister_id(pic: &PocketIc) -> Principal {
    pocket_ic::nonblocking::get_default_effective_canister_id(get_pic_url(pic).to_string())
        .await
        .unwrap()
}

pub fn create_identity() -> Result<Box<dyn Identity>, String> {
    if std::env::var(HSM_PKCS11_LIBRARY_PATH).is_ok() {
        create_hsm_identity().map(|x| Box::new(x) as _)
    } else {
        Ok(Box::new(create_basic_identity()))
    }
}

fn expect_env_var(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("Need to specify the {name} environment variable"))
}

pub fn create_hsm_identity() -> Result<HardwareIdentity, String> {
    let path = expect_env_var(HSM_PKCS11_LIBRARY_PATH)?;
    let slot_index = expect_env_var(HSM_SLOT_INDEX)?
        .parse::<usize>()
        .map_err(|e| format!("Unable to parse {HSM_SLOT_INDEX} value: {e}"))?;
    let key = expect_env_var(HSM_KEY_ID)?;
    let id = HardwareIdentity::new(path, slot_index, &key, get_hsm_pin)
        .map_err(|e| format!("Unable to create hw identity: {e}"))?;
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
pub fn create_basic_identity() -> BasicIdentity {
    BasicIdentity::from_raw_key(&ic_ed25519::PrivateKey::generate().serialize_raw())
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

pub async fn create_agent(
    pic: &PocketIc,
    identity: impl Identity + 'static,
) -> Result<Agent, String> {
    let url = get_pic_url(pic);
    let agent = Agent::builder()
        .with_url(url)
        .with_identity(identity)
        .with_max_polling_time(Duration::from_secs(15))
        .build()
        .map_err(|e| format!("{e:?}"))?;
    agent.fetch_root_key().await.unwrap();
    Ok(agent)
}

pub async fn with_agent<F, R>(f: F) -> R
where
    F: AsyncFnOnce(&PocketIc, Agent) -> Result<R, Box<dyn Error>>,
{
    let agent_identity = create_identity().expect("Could not create an identity.");
    with_agent_as(agent_identity, f).await
}

pub async fn with_agent_as<I, F, R>(agent_identity: I, f: F) -> R
where
    I: Identity + 'static,
    F: AsyncFnOnce(&PocketIc, Agent) -> Result<R, Box<dyn Error>>,
{
    with_pic(async move |pic| {
        let agent = create_agent(pic, agent_identity)
            .await
            .expect("Could not create an agent.");
        f(pic, agent).await
    })
    .await
}

fn check_assets_uptodate() -> bool {
    let repo_dir = std::fs::canonicalize(format!("{}/..", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let assets_dir = repo_dir.join("ref-tests/assets");
    let checked_paths = [
        ".",
        "pocket-ic",
        "cycles-wallet.wasm",
        "universal-canister.wasm.gz",
    ]
    .map(|p| assets_dir.join(p));
    for path in &checked_paths {
        if !path.exists() {
            return false;
        }
    }
    let last_asset_update = repo_dir
        .join("scripts/download_reftest_assets.sh")
        .metadata()
        .expect("failed to get metadata for update script")
        .modified()
        .expect("failed to get modification time for update script");
    for path in &checked_paths {
        let metadata = path
            .metadata()
            .expect("failed to get metadata for asset file");
        let modified = metadata
            .modified()
            .expect("failed to get modification time for asset file");
        if modified < last_asset_update {
            return false;
        }
    }
    true
}

pub async fn with_pic<F, R>(f: F) -> R
where
    F: AsyncFnOnce(&PocketIc) -> Result<R, Box<dyn Error>>,
{
    if !check_assets_uptodate() {
        panic!("Test assets are out of date. Please run `scripts/download_reftest_assets.sh` to update them.");
    }
    let pic = PocketIcBuilder::new()
        .with_server_binary(format!("{}/assets/pocket-ic", env!("CARGO_MANIFEST_DIR")).into())
        .with_nns_subnet()
        .with_application_subnet()
        .with_auto_progress()
        .build_async()
        .await;
    match f(&pic).await {
        Ok(r) => r,
        Err(e) => panic!("{e:?}"),
    }
}

pub fn get_pic_url(pic: &PocketIc) -> Url {
    pic.get_server_url()
        .join(&format!("instances/{}/", pic.instance_id))
        .unwrap()
}

pub async fn create_universal_canister(
    pic: &PocketIc,
    agent: &Agent,
) -> Result<Principal, Box<dyn Error>> {
    let canister_wasm = std::fs::read(format!(
        "{}/assets/universal-canister.wasm.gz",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();

    let ic00 = ManagementCanister::create(agent);

    let (canister_id,) = ic00
        .create_canister()
        .as_provisional_create_with_amount(None)
        .with_effective_canister_id(get_effective_canister_id(pic).await)
        .call_and_wait()
        .await?;

    ic00.install(&canister_id, &canister_wasm)
        .with_raw_arg(vec![])
        .call_and_wait()
        .await?;

    Ok(canister_id)
}

pub fn get_wallet_wasm() -> Vec<u8> {
    std::fs::read(format!(
        "{}/assets/cycles-wallet.wasm",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

pub async fn create_wallet_canister(
    pic: &PocketIc,
    agent: &Agent,
    cycles: Option<u128>,
) -> Result<Principal, Box<dyn Error>> {
    let canister_wasm = get_wallet_wasm();

    let ic00 = ManagementCanister::create(agent);

    let (canister_id,) = ic00
        .create_canister()
        .as_provisional_create_with_amount(cycles)
        .with_effective_canister_id(get_effective_canister_id(pic).await)
        .with_memory_allocation(
            MemoryAllocation::try_from(8000000000_u64)
                .expect("Memory allocation must be between 0 and 2^48 (i.e 256TB), inclusively."),
        )
        .call_and_wait()
        .await?;

    ic00.install(&canister_id, &canister_wasm)
        .with_raw_arg(vec![])
        .call_and_wait()
        .await?;

    Ok(canister_id)
}

pub async fn with_universal_canister<F, R>(f: F) -> R
where
    F: AsyncFnOnce(&PocketIc, Agent, Principal) -> Result<R, Box<dyn Error>>,
{
    with_agent(async move |pic, agent| {
        let canister_id = create_universal_canister(pic, &agent).await?;
        f(pic, agent, canister_id).await
    })
    .await
}

pub async fn with_universal_canister_as<I, F, R>(identity: I, f: F) -> R
where
    I: Identity + 'static,
    F: AsyncFnOnce(&PocketIc, Agent, Principal) -> Result<R, Box<dyn Error>>,
{
    with_agent_as(identity, async move |pic, agent| {
        let canister_id = create_universal_canister(pic, &agent).await?;
        f(pic, agent, canister_id).await
    })
    .await
}

pub async fn with_wallet_canister<F, R>(cycles: Option<u128>, f: F) -> R
where
    F: AsyncFnOnce(&PocketIc, Agent, Principal) -> Result<R, Box<dyn Error>>,
{
    with_agent(async move |pic, agent| {
        let canister_id = create_wallet_canister(pic, &agent, cycles).await?;
        f(pic, agent, canister_id).await
    })
    .await
}
