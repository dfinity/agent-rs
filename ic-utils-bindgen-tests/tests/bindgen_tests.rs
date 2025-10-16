#![cfg(unix)]
use std::{fs, sync::Arc};

use candid::{Encode, Principal};
use ic_agent::{identity::Secp256k1Identity, Agent, Identity};
use ic_utils_bindgen_tests::{icrc_runtime, icrc_static, icrc_types};
use pocket_ic::{nonblocking::PocketIc, PocketIcBuilder};

async fn setup() -> (PocketIc, Principal, Agent, Arc<dyn Identity>) {
    let identity = Secp256k1Identity::from_pem_file(format!(
        "{}/test_identity.pem",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let identity = Arc::new(identity);
    let mut pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_nns_subnet()
        .build_async()
        .await;
    let canister = pic
        .create_canister_with_id(None, None, "ryjl3-tyaaa-aaaaa-aaaba-cai".parse().unwrap())
        .await
        .unwrap();
    pic.add_cycles(canister, 100_000_000_000_000).await;
    let init_args = icrc_types::Init {
        decimals: 8,
        minting_account: icrc_types::InitMintingAccount {
            owner: "aaaaa-aa".parse().unwrap(),
            subaccount: None,
        },
        initial_mints: vec![icrc_types::InitInitialMintsItem {
            account: icrc_types::InitInitialMintsItemAccount {
                owner: identity.sender().unwrap(),
                subaccount: None,
            },
            amount: 1_000_000_000_u128.into(),
        }],
        token_name: "TestToken".to_string(),
        token_symbol: "TT".to_string(),
        transfer_fee: 0_u128.into(),
    };
    pic.install_canister(
        canister,
        fs::read(format!("{}/icrc1_ref.wasm", env!("CARGO_MANIFEST_DIR"))).unwrap(),
        Encode!(&init_args).unwrap(),
        None,
    )
    .await;
    pic.make_live(None).await;
    let agent = Agent::builder()
        .with_url(pic.url().unwrap())
        .with_arc_identity(identity.clone())
        .build()
        .unwrap();
    agent.fetch_root_key().await.unwrap();
    (pic, canister, agent, identity)
}

#[tokio::test]
async fn test_runtime_principal() {
    let (_pic, canister, agent, identity) = setup().await;
    let canister = icrc_runtime::Icrc1Ledger::new(&agent, canister);
    let (balance,) = canister
        .icrc1_balance_of(&icrc_runtime::Account {
            owner: identity.sender().unwrap(),
            subaccount: None,
        })
        .await
        .unwrap();
    assert_eq!(balance, 1_000_000_000_u128);
    let (res,) = canister
        .icrc1_transfer(&icrc_runtime::LedgerIcrc1TransferArg {
            to: icrc_runtime::Account {
                owner: Principal::anonymous(),
                subaccount: None,
            },
            amount: 100_000_000_u128.into(),
            fee: None,
            memo: None,
            from_subaccount: None,
            created_at_time: None,
        })
        .await
        .unwrap();
    let _idx = res.unwrap();
    let (rx_bal,) = canister
        .icrc1_balance_of(&icrc_runtime::Account {
            owner: Principal::anonymous(),
            subaccount: None,
        })
        .await
        .unwrap();
    assert_eq!(rx_bal, 100_000_000_u128);
    let (tx_bal,) = canister
        .icrc1_balance_of(&icrc_runtime::Account {
            owner: identity.sender().unwrap(),
            subaccount: None,
        })
        .await
        .unwrap();
    assert_eq!(tx_bal, 900_000_000_u128);
}

#[tokio::test]
async fn test_static_principal() {
    let (_pic, _canister, agent, identity) = setup().await;
    let canister = icrc_static::Icrc1Ledger::new(&agent);
    let (balance,) = canister
        .icrc1_balance_of(&icrc_static::Account {
            owner: identity.sender().unwrap(),
            subaccount: None,
        })
        .await
        .unwrap();
    assert_eq!(balance, 1_000_000_000_u128);
    let (res,) = canister
        .icrc1_transfer(&icrc_static::LedgerIcrc1TransferArg {
            to: icrc_static::Account {
                owner: Principal::anonymous(),
                subaccount: None,
            },
            amount: 100_000_000_u128.into(),
            fee: None,
            memo: None,
            from_subaccount: None,
            created_at_time: None,
        })
        .await
        .unwrap();
    let _idx = res.unwrap();
    let (rx_bal,) = canister
        .icrc1_balance_of(&icrc_static::Account {
            owner: Principal::anonymous(),
            subaccount: None,
        })
        .await
        .unwrap();
    assert_eq!(rx_bal, 100_000_000_u128);
    let (tx_bal,) = canister
        .icrc1_balance_of(&icrc_static::Account {
            owner: identity.sender().unwrap(),
            subaccount: None,
        })
        .await
        .unwrap();
    assert_eq!(tx_bal, 900_000_000_u128);
}
