//! In this file, please mark all tests that require a running ic-ref as ignored.
//!
//! Contrary to ic-ref.rs, these tests are not meant to match any other tests. They're
//! integration tests with a running IC-Ref.
use candid::CandidType;
use ic_agent::{
    agent::{agent_error::HttpErrorPayload, Envelope, EnvelopeContent, RejectCode, RejectResponse},
    export::Principal,
    AgentError, Identity,
};
use ic_certification::Label;
use ic_utils::{
    call::{AsyncCall, SyncCall},
    interfaces::{
        management_canister::builders::{CanisterSettings, InstallMode},
        WalletCanister,
    },
    Argument, Canister,
};
use ref_tests::{
    create_agent, create_basic_identity, create_universal_canister, create_wallet_canister,
    get_wallet_wasm_from_env, universal_canister::payload, with_agent, with_universal_canister,
    with_wallet_canister,
};
use serde::Serialize;
use std::{
    borrow::Cow,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[ignore]
#[test]
fn basic_expiry() {
    with_universal_canister(|agent, canister_id| async move {
        let arg = payload().reply_data(b"hello").build();

        // Verify this works first.
        let result = agent
            .update(&canister_id, "update")
            .with_arg(arg.clone())
            .expire_after(std::time::Duration::from_secs(120))
            .call_and_wait()
            .await?;

        assert_eq!(result.as_slice(), b"hello");

        // Verify a zero expiry will fail with the proper code.
        let result = agent
            .update(&canister_id, "update")
            .with_arg(arg.clone())
            .expire_after(std::time::Duration::from_secs(0))
            .call_and_wait()
            .await;

        match result.unwrap_err() {
            AgentError::HttpError(HttpErrorPayload { status, .. }) => assert_eq!(status, 400),
            x => panic!("Was expecting an error, got {:?}", x),
        }

        let result = agent
            .update(&canister_id, "update")
            .with_arg(arg.clone())
            .expire_after(std::time::Duration::from_secs(120))
            .call_and_wait()
            .await?;

        assert_eq!(result.as_slice(), b"hello");

        Ok(())
    })
}

#[ignore]
#[test]
fn wait_signed() {
    with_universal_canister(|mut agent, canister_id| async move {
        fn serialized_bytes(envelope: Envelope) -> Vec<u8> {
            let mut serialized_bytes = Vec::new();
            let mut serializer = serde_cbor::Serializer::new(&mut serialized_bytes);
            serializer.self_describe().unwrap();
            envelope.serialize(&mut serializer).unwrap();
            serialized_bytes
        }

        let arg = payload().reply_data(b"hello").build();
        let ingress_expiry = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
            + Duration::from_secs(120))
        .as_nanos() as u64;

        let agent_identity = Arc::new(create_basic_identity().unwrap());
        agent.set_arc_identity(agent_identity.clone());

        let call_envelope_content = EnvelopeContent::Call {
            sender: agent.get_principal().unwrap(),
            arg: arg.clone(),
            ingress_expiry,
            nonce: None,
            canister_id,
            method_name: "update".to_string(),
        };

        let call_request_id = call_envelope_content.to_request_id();
        let call_signature = agent_identity.sign(&call_envelope_content).unwrap();

        let call_envelope = Envelope {
            content: Cow::Borrowed(&call_envelope_content),
            sender_pubkey: call_signature.public_key,
            sender_sig: call_signature.signature,
            sender_delegation: call_signature.delegations,
        };

        let call_envelope_serialized = serialized_bytes(call_envelope);

        agent
            .update_signed(canister_id, call_envelope_serialized)
            .await
            .unwrap();

        let paths: Vec<Vec<Label>> = vec![vec![
            "request_status".into(),
            call_request_id.to_vec().into(),
        ]];
        let read_state_envelope_content = EnvelopeContent::ReadState {
            sender: agent.get_principal().unwrap(),
            paths,
            ingress_expiry,
        };

        let read_signature = agent_identity.sign(&read_state_envelope_content).unwrap();

        let read_state_envelope = Envelope {
            content: Cow::Borrowed(&read_state_envelope_content),
            sender_pubkey: read_signature.public_key,
            sender_sig: read_signature.signature,
            sender_delegation: read_signature.delegations,
        };

        let read_envelope_serialized = serialized_bytes(read_state_envelope);

        let result = agent
            .wait_signed(&call_request_id, canister_id, read_envelope_serialized)
            .await
            .unwrap();

        assert_eq!(result.as_slice(), b"hello");

        Ok(())
    })
}

#[ignore]
#[test]
fn canister_query() {
    with_universal_canister(|agent, canister_id| async move {
        let universal = Canister::builder()
            .with_canister_id(canister_id)
            .with_agent(&agent)
            .build()?;

        let arg = payload().reply_data(b"hello").build();

        let out = universal
            .query("query")
            .with_arg_raw(arg)
            .build::<()>()
            .call_raw()
            .await?;

        assert_eq!(out, b"hello");

        Ok(())
    })
}

#[ignore]
#[test]
fn canister_reject_call() {
    // try to call a wallet method, but on the universal canister.
    // this lets us look up the reject code and reject message in the certificate.
    with_universal_canister(|agent, wallet_id| async move {
        let alice = WalletCanister::create(&agent, wallet_id).await?;
        let bob =
            WalletCanister::create(&agent, create_wallet_canister(&agent, None).await?).await?;

        let result = alice.wallet_send(*bob.canister_id(), 1_000_000).await;

        assert!(
            matches!(
                &result,
                Err(AgentError::CertifiedReject(RejectResponse {
                    reject_code: RejectCode::CanisterError,
                    reject_message,
                    error_code: None,
                    ..
                })) if reject_message.contains(&format!(
                    "Canister {}: Canister has no update method 'wallet_send'",
                    alice.canister_id()
                ))
            ),
            "wrong error: {result:?}"
        );

        Ok(())
    });
}

#[ignore]
#[test]
fn wallet_canister_forward() {
    with_wallet_canister(None, |agent, wallet_id| async move {
        let wallet = WalletCanister::create(&agent, wallet_id).await?;

        let universal_id = create_universal_canister(&agent).await?;

        // Perform an "echo" call through the wallet canister.
        // We encode the result in DIDL to decode it on the other side (would normally get
        // a Vec<u8>).
        let arg = payload()
            .reply_data(b"DIDL\0\x01\x71\x0bHello World")
            .build();

        let args = Argument::from_raw(arg);

        let (result,): (String,) = wallet
            .call(universal_id, "update", args, 0)
            .call_and_wait()
            .await
            .unwrap();

        assert_eq!(result, "Hello World");
        Ok(())
    });
}

#[ignore]
#[test]
fn wallet_canister_create_and_install() {
    with_wallet_canister(Some(1_000_000_000_000_000), |agent, wallet_id| async move {
        let wallet = WalletCanister::create(&agent, wallet_id).await?;

        let create_result = wallet
            .wallet_create_canister(200_000_000_000_000, None, None, None, None)
            .await?;

        #[derive(CandidType)]
        struct CanisterInstall {
            mode: InstallMode,
            canister_id: Principal,
            wasm_module: Vec<u8>,
            arg: Vec<u8>,
        }

        let install_config = CanisterInstall {
            mode: InstallMode::Install,
            canister_id: create_result.canister_id,
            wasm_module: b"\0asm\x01\0\0\0".to_vec(),
            arg: Argument::default().serialize()?,
        };

        let args = Argument::from_candid((install_config,));

        wallet
            .call64(Principal::management_canister(), "install_code", args, 0)
            .call_and_wait()
            .await?;

        Ok(())
    });
}

#[ignore]
#[test]
fn wallet_create_and_set_controller() {
    with_wallet_canister(None, |agent, wallet_id| async move {
        eprintln!("Parent wallet canister id: {:?}", wallet_id.to_text());
        let wallet = WalletCanister::create(&agent, wallet_id).await?;
        // get the wallet wasm from the environment
        let wallet_wasm = get_wallet_wasm_from_env();
        // store the wasm into the wallet
        wallet
            .wallet_store_wallet_wasm(wallet_wasm)
            .call_and_wait()
            .await?;

        // controller
        let other_agent_identity = create_basic_identity()?;
        let other_agent_principal = other_agent_identity.sender()?;
        let other_agent = create_agent(other_agent_identity).await?;
        other_agent.fetch_root_key().await?;

        eprintln!("Agent id: {:?}", other_agent_principal.to_text());

        let create_result = wallet
            .wallet_create_wallet(
                1_000_000_000_000_u128,
                Some(vec![other_agent_principal]),
                None,
                None,
                None,
            )
            .await?;

        eprintln!(
            "Child wallet canister id: {:?}",
            create_result.canister_id.clone().to_text()
        );

        eprintln!("...build child_wallet");
        let child_wallet = WalletCanister::from_canister(
            Canister::builder()
                .with_agent(&other_agent)
                .with_canister_id(create_result.canister_id)
                .build()?,
        )
        .await?;

        eprintln!("...child_wallet.get_controllers");
        let (controller_list,) = child_wallet.get_controllers().call().await?;
        assert!(controller_list.len() == 1);
        assert_eq!(controller_list[0], other_agent_principal);

        eprintln!("...child_wallet.list_addresses");
        let (address_entries,): (Vec<ic_utils::interfaces::wallet::AddressEntry>,) =
            child_wallet.list_addresses().call().await?;
        for address in address_entries.iter() {
            eprintln!("id {:?} is a {:?}", address.id.to_text(), address.role);
        }

        Ok(())
    });
}

#[ignore]
#[test]
fn wallet_create_wallet() {
    with_wallet_canister(None, |agent, wallet_id| async move {
        eprintln!("Parent wallet canister id: {:?}", wallet_id.to_text());
        let wallet = WalletCanister::create(&agent, wallet_id).await?;
        let wallet_initial_balance = wallet.wallet_balance().await?;

        // get the wallet wasm from the environment
        let wallet_wasm = get_wallet_wasm_from_env();

        // store the wasm into the wallet
        wallet
            .wallet_store_wallet_wasm(wallet_wasm)
            .call_and_wait()
            .await?;

        // create a child wallet
        let child_create_res = wallet
            .wallet_create_wallet(1_000_000_000_000_u128, None, None, None, None)
            .await?;

        eprintln!(
            "Created child wallet one.\nChild wallet one canister id: {:?}",
            child_create_res.canister_id.to_text()
        );

        let (child_wallet_balance,): (ic_utils::interfaces::wallet::BalanceResult<u64>,) = wallet
            .call64(
                child_create_res.canister_id,
                "wallet_balance",
                Argument::default(),
                0,
            )
            .call_and_wait()
            .await?;

        eprintln!(
            "Child wallet one cycle balance: {}",
            child_wallet_balance.amount
        );

        //
        // create a second child wallet
        //
        let child_two_create_res = wallet
            .wallet_create_wallet(2_100_000_000_000_u128, None, None, None, None)
            .await?;

        eprintln!(
            "Created child wallet two.\nChild wallet two canister id: {:?}",
            child_two_create_res.canister_id.to_text()
        );
        let (child_wallet_two_balance,): (ic_utils::interfaces::wallet::BalanceResult<u64>,) =
            wallet
                .call64(
                    child_two_create_res.canister_id,
                    "wallet_balance",
                    Argument::default(),
                    0,
                )
                .call_and_wait()
                .await?;
        eprintln!(
            "Child wallet two cycle balance: {}",
            child_wallet_two_balance.amount
        );

        //
        // Get wallet intermediate balance
        //
        let (wallet_intermediate_balance,) = wallet.wallet_balance64().call().await?;
        eprintln!(
            "Parent wallet initial balance: {}\n      intermediate balance:  {}",
            wallet_initial_balance.amount, wallet_intermediate_balance.amount
        );

        //
        // Create a grandchild wallet from second child wallet
        //
        #[derive(CandidType)]
        struct In {
            cycles: u64,
            settings: CanisterSettings,
        }
        let create_args = In {
            cycles: 1_000_000_000_000_u64,
            settings: CanisterSettings {
                controllers: None,
                compute_allocation: None,
                memory_allocation: None,
                freezing_threshold: None,
                reserved_cycles_limit: None,
                wasm_memory_limit: None,
                log_visibility: None,
            },
        };
        let args = Argument::from_candid((create_args,));

        let (grandchild_create_res,): (Result<ic_utils::interfaces::wallet::CreateResult, String>,) =
            wallet
                .call64(
                    child_two_create_res.canister_id,
                    "wallet_create_wallet",
                    args,
                    0,
                )
                .call_and_wait()
                .await?;
        let grandchild_create_res = grandchild_create_res?;

        eprintln!(
            "Created grandchild wallet from child wallet two.\nGrandchild wallet canister id: {:?}",
            grandchild_create_res.canister_id.to_text()
        );

        let (wallet_final_balance,) = wallet.wallet_balance64().call().await?;
        eprintln!(
            "Parent wallet initial balance: {}\n      final balance:  {}",
            wallet_initial_balance.amount, wallet_final_balance.amount
        );

        Ok(())
    });
}

#[ignore]
#[test]
fn wallet_canister_funds() {
    let provisional_amount = 1_000_000_000_000_000;
    with_wallet_canister(Some(provisional_amount), |agent, wallet_id| async move {
        let alice = WalletCanister::create(&agent, wallet_id).await?;
        let bob = WalletCanister::create(
            &agent,
            create_wallet_canister(&agent, Some(provisional_amount)).await?,
        )
        .await?;

        let alice_previous_balance = alice.wallet_balance().await?;
        let bob_previous_balance = bob.wallet_balance().await?;

        alice.wallet_send(*bob.canister_id(), 1_000_000).await?;

        let bob_balance = bob.wallet_balance().await?;

        let alice_balance = alice.wallet_balance().await?;
        eprintln!(
            "Alice previous: {}\n      current:  {}",
            alice_previous_balance.amount, alice_balance.amount
        );
        eprintln!(
            "Bob   previous: {}\n      current:  {}",
            bob_previous_balance.amount, bob_balance.amount
        );
        assert!(
            bob_balance.amount > bob_previous_balance.amount + 500_000,
            "Wrong: {} > {}",
            bob_balance.amount,
            bob_previous_balance.amount + 500_000
        );
        assert!(alice_balance.amount < alice_previous_balance.amount - 500_000);

        Ok(())
    });
}

#[ignore]
#[test]
fn wallet_helper_functions() {
    with_wallet_canister(None, |agent, wallet_id| async move {
        // name
        let wallet = WalletCanister::create(&agent, wallet_id).await?;
        let (name,) = wallet.name().call().await?;
        assert!(name.is_none(), "Name should be none.");

        let wallet_name = "Alice".to_string();

        wallet.set_name(wallet_name.clone()).call_and_wait().await?;
        let (name,) = wallet.name().call().await?;
        assert_eq!(name, Some(wallet_name));

        // controller
        let other_agent_identity = create_basic_identity()?;
        let other_agent_principal = other_agent_identity.sender()?;
        let other_agent = create_agent(other_agent_identity).await?;
        other_agent.fetch_root_key().await?;

        let (controller_list,) = wallet.get_controllers().call().await?;
        assert_eq!(controller_list.len(), 1);
        assert_ne!(&controller_list[0], &other_agent_principal);

        wallet
            .add_controller(other_agent_principal)
            .call_and_wait()
            .await?;

        let (controller_list,) = wallet.get_controllers().call().await?;
        assert_eq!(controller_list.len(), 2);
        let added = if controller_list[0] == other_agent_principal {
            true
        } else {
            controller_list[1] == other_agent_principal
        };
        assert!(added);

        wallet
            .remove_controller(other_agent_principal)
            .call_and_wait()
            .await?;

        let (controller_list,) = wallet.get_controllers().call().await?;
        assert_eq!(controller_list.len(), 1);
        assert_ne!(&controller_list[0], &other_agent_principal);

        Ok(())
    });
}

mod sign_send {
    use ic_agent::{
        agent::{
            signed_query_inspect, signed_request_status_inspect, signed_update_inspect,
            ReplyResponse, RequestStatusResponse,
        },
        AgentError,
    };
    use ref_tests::{universal_canister::payload, with_universal_canister};
    use std::{thread, time};

    #[ignore]
    #[test]
    fn query() {
        with_universal_canister(|agent, canister_id| async move {
            let arg = payload().reply_data(b"hello").build();
            let signed_query = agent.query(&canister_id, "query").with_arg(arg).sign()?;

            assert!(signed_query_inspect(
                signed_query.sender,
                signed_query.canister_id,
                &signed_query.method_name,
                &signed_query.arg,
                signed_query.ingress_expiry,
                signed_query.signed_query.clone()
            )
            .is_ok());

            let result = agent
                .query_signed(
                    signed_query.effective_canister_id,
                    signed_query.signed_query,
                )
                .await?;

            assert_eq!(result, b"hello");
            Ok(())
        })
    }

    #[ignore]
    #[test]
    fn update_then_request_status() {
        with_universal_canister(|agent, canister_id| async move {
            let arg = payload().reply_data(b"hello").build();
            let signed_update = agent.update(&canister_id, "update").with_arg(arg).sign()?;

            assert!(signed_update_inspect(
                signed_update.sender,
                signed_update.canister_id,
                &signed_update.method_name,
                &signed_update.arg,
                signed_update.ingress_expiry,
                signed_update.signed_update.clone()
            )
            .is_ok());

            let signed_request_status = agent.sign_request_status(
                signed_update.effective_canister_id,
                signed_update.request_id,
            )?;

            assert!(signed_request_status_inspect(
                signed_request_status.sender,
                &signed_request_status.request_id,
                signed_request_status.ingress_expiry,
                signed_request_status.signed_request_status.clone()
            )
            .is_ok());

            let _request_id = agent
                .update_signed(
                    signed_update.effective_canister_id,
                    signed_update.signed_update,
                )
                .await?;

            let ten_secs = time::Duration::from_secs(10);
            thread::sleep(ten_secs);

            let response = agent
                .request_status_signed(
                    &signed_request_status.request_id,
                    signed_request_status.effective_canister_id,
                    signed_request_status.signed_request_status.clone(),
                )
                .await?;

            assert!(
                matches!(response, RequestStatusResponse::Replied(ReplyResponse { arg: result, .. }) if result == b"hello")
            );
            Ok(())
        })
    }

    #[ignore]
    #[test]
    fn forged_query() {
        with_universal_canister(|agent, canister_id| async move {
            let arg = payload().reply_data(b"hello").build();
            let mut signed_query = agent.query(&canister_id, "query").with_arg(arg).sign()?;

            signed_query.method_name = "non_query".to_string();

            let result = signed_query_inspect(
                signed_query.sender,
                signed_query.canister_id,
                &signed_query.method_name,
                &signed_query.arg,
                signed_query.ingress_expiry,
                signed_query.signed_query.clone(),
            );

            assert!(matches!(result,
                    Err(AgentError::CallDataMismatch{field, value_arg, value_cbor})
                    if field == *"method_name" && value_arg == *"non_query" && value_cbor == *"query"));

            Ok(())
        })
    }
}

mod identity {
    use candid::Principal;
    use ed25519_consensus::SigningKey;
    use ic_agent::{
        identity::{
            BasicIdentity, DelegatedIdentity, Delegation, Prime256v1Identity, Secp256k1Identity,
            SignedDelegation,
        },
        Identity,
    };
    use rand::thread_rng;
    use ref_tests::{universal_canister::payload, with_universal_canister_as};

    #[ignore]
    #[test]
    fn delegated_eddsa_identity() {
        let mut random = thread_rng();
        let sending_identity = BasicIdentity::from_signing_key(SigningKey::new(&mut random));
        let signing_identity = BasicIdentity::from_signing_key(SigningKey::new(&mut random));
        let delegation = Delegation {
            expiration: i64::MAX as u64,
            pubkey: signing_identity.public_key().unwrap(),
            targets: None,
        };
        let signature = sending_identity.sign_delegation(&delegation).unwrap();
        let delegated_identity = DelegatedIdentity::new(
            signature.public_key.unwrap(),
            Box::new(signing_identity),
            vec![SignedDelegation {
                delegation,
                signature: signature.signature.unwrap(),
            }],
        )
        .unwrap();
        with_universal_canister_as(delegated_identity, |agent, canister| async move {
            let payload = payload().caller().append_and_reply().build();
            let caller_resp = agent
                .query(&canister, "query")
                .with_arg(payload)
                .call()
                .await
                .unwrap();
            let caller = Principal::from_slice(&caller_resp);
            assert_eq!(caller, sending_identity.sender().unwrap());
            Ok(())
        })
    }

    #[ignore]
    #[test]
    fn delegated_ecdsa_identity() {
        let mut random = thread_rng();
        let sending_identity =
            Secp256k1Identity::from_private_key(k256::SecretKey::random(&mut random));
        let signing_identity =
            Prime256v1Identity::from_private_key(p256::SecretKey::random(&mut random));
        let delegation = Delegation {
            expiration: i64::MAX as u64,
            pubkey: signing_identity.public_key().unwrap(),
            targets: None,
        };
        let signature = sending_identity.sign_delegation(&delegation).unwrap();
        let delegated_identity = DelegatedIdentity::new(
            signature.public_key.unwrap(),
            Box::new(signing_identity),
            vec![SignedDelegation {
                delegation,
                signature: signature.signature.unwrap(),
            }],
        )
        .unwrap();
        with_universal_canister_as(delegated_identity, |agent, canister| async move {
            let payload = payload().caller().append_and_reply().build();
            let caller_resp = agent
                .query(&canister, "query")
                .with_arg(payload)
                .call()
                .await
                .unwrap();
            let caller = Principal::from_slice(&caller_resp);
            assert_eq!(caller, sending_identity.sender().unwrap());
            Ok(())
        })
    }
}

#[ignore]
#[test]
fn topology() {
    with_agent(|agent| async move {
        let is_pocketic = std::env::var("POCKET_IC").is_ok();
        match agent.fetch_pocketic_topology().await {
            Ok(_) => assert!(is_pocketic),
            Err(_) => assert!(!is_pocketic),
        };
        Ok(())
    });
}
