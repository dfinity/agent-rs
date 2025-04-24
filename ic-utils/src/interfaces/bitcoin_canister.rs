//! The canister interface for the [Bitcoin canister](https://github.com/dfinity/bitcoin-canister).

use std::ops::Deref;

use candid::{CandidType, Principal};
use ic_agent::Agent;
use serde::Deserialize;
use thiserror::Error;

use crate::{
    call::{AsyncCall, SyncCall},
    error::BaseError,
    Canister,
};

/// The canister interface for the IC [Bitcoin canister](https://github.com/dfinity/bitcoin-canister).
#[derive(Debug)]
pub struct BitcoinCanister<'agent> {
    canister: Canister<'agent>,
    network: BitcoinNetwork,
}

/// An error that can occur when constructing a Bitcoin canister.
#[derive(Debug, Error)]
#[non_exhaustive]
#[error("No applicable canister ID for regtest")]
pub struct BitcoinCanisterAttachError;

impl<'agent> Deref for BitcoinCanister<'agent> {
    type Target = Canister<'agent>;
    fn deref(&self) -> &Self::Target {
        &self.canister
    }
}
const MAINNET_ID: Principal =
    Principal::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x01, 0xa0, 0x00, 0x04, 0x01, 0x01]);
const TESTNET_ID: Principal =
    Principal::from_slice(&[0x00, 0x00, 0x00, 0x00, 0x01, 0xa0, 0x00, 0x01, 0x01, 0x01]);

impl<'agent> BitcoinCanister<'agent> {
    /// Create a `BitcoinCanister` interface from an existing canister object.
    pub fn from_canister(canister: Canister<'agent>, network: BitcoinNetwork) -> Self {
        Self { canister, network }
    }
    /// Create a `BitcoinCanister` interface pointing to the specified canister ID.
    pub fn create(agent: &'agent Agent, canister_id: Principal, network: BitcoinNetwork) -> Self {
        Self::from_canister(
            Canister::builder()
                .with_agent(agent)
                .with_canister_id(canister_id)
                .build()
                .expect("all required fields should be set"),
            network,
        )
    }
    /// Create a `BitcoinCanister` interface for the Bitcoin mainnet canister on the IC mainnet.
    pub fn mainnet(agent: &'agent Agent) -> Self {
        Self::for_network(agent, BitcoinNetwork::Mainnet).expect("valid network")
    }
    /// Create a `BitcoinCanister` interface for the Bitcoin testnet canister on the IC mainnet.
    pub fn testnet(agent: &'agent Agent) -> Self {
        Self::for_network(agent, BitcoinNetwork::Testnet).expect("valid network")
    }
    /// Create a `BitcoinCanister` interface for the specified Bitcoin network on the IC mainnet. Errors if `Regtest` is specified.
    pub fn for_network(
        agent: &'agent Agent,
        network: BitcoinNetwork,
    ) -> Result<Self, BitcoinCanisterAttachError> {
        let canister_id = match network {
            BitcoinNetwork::Mainnet => MAINNET_ID,
            BitcoinNetwork::Testnet => TESTNET_ID,
            BitcoinNetwork::Regtest => return Err(BitcoinCanisterAttachError),
        };
        Ok(Self::create(agent, canister_id, network))
    }

    /// Gets the BTC balance (in satoshis) of a particular Bitcoin address, filtering by number of confirmations.
    /// Most applications should require 6 confirmations.
    pub fn get_balance(
        &self,
        address: &str,
        min_confirmations: Option<u32>,
    ) -> impl 'agent + AsyncCall<Value = (u64,), Error = BaseError> {
        #[derive(CandidType)]
        struct In<'a> {
            address: &'a str,
            network: BitcoinNetwork,
            min_confirmations: Option<u32>,
        }
        self.update("bitcoin_get_balance")
            .with_arg(GetBalance {
                address,
                network: self.network,
                min_confirmations,
            })
            .build()
    }

    /// Gets the BTC balance (in satoshis) of a particular Bitcoin address, filtering by number of confirmations.
    /// Most applications should require 6 confirmations.
    pub fn get_balance_query(
        &self,
        address: &str,
        min_confirmations: Option<u32>,
    ) -> impl 'agent + SyncCall<Value = (u64,), Error = BaseError> {
        self.query("bitcoin_get_balance_query")
            .with_arg(GetBalance {
                address,
                network: self.network,
                min_confirmations,
            })
            .build()
    }

    /// Fetch the list of [UTXOs](https://en.wikipedia.org/wiki/Unspent_transaction_output) for a Bitcoin address,
    /// filtering by number of confirmations. Most applications should require 6 confirmations.
    ///
    /// This method is paginated. If not all the results can be returned, then `next_page` will be set to `Some`,
    /// and its value can be passed to this method to get the next page.
    pub fn get_utxos(
        &self,
        address: &str,
        filter: Option<UtxosFilter>,
    ) -> impl 'agent + AsyncCall<Value = (GetUtxosResponse,), Error = BaseError> {
        self.update("bitcoin_get_utxos")
            .with_arg(GetUtxos {
                address,
                network: self.network,
                filter,
            })
            .build()
    }

    /// Fetch the list of [UTXOs](https://en.wikipedia.org/wiki/Unspent_transaction_output) for a Bitcoin address,
    /// filtering by number of confirmations. Most applications should require 6 confirmations.
    ///
    /// This method is paginated. If not all the results can be returned, then `next_page` will be set to `Some`,
    /// and its value can be passed to this method to get the next page.
    pub fn get_utxos_query(
        &self,
        address: &str,
        filter: Option<UtxosFilter>,
    ) -> impl 'agent + SyncCall<Value = (GetUtxosResponse,), Error = BaseError> {
        self.query("bitcoin_get_utxos_query")
            .with_arg(GetUtxos {
                address,
                network: self.network,
                filter,
            })
            .build()
    }

    /// Gets the transaction fee percentiles for the last 10,000 transactions. In the returned vector, `v[i]` is the `i`th percentile fee,
    /// measured in millisatoshis/vbyte, and `v[0]` is the smallest fee.
    pub fn get_current_fee_percentiles(
        &self,
    ) -> impl 'agent + AsyncCall<Value = (Vec<u64>,), Error = BaseError> {
        #[derive(CandidType)]
        struct In {
            network: BitcoinNetwork,
        }
        self.update("bitcoin_get_current_fee_percentiles")
            .with_arg(In {
                network: self.network,
            })
            .build()
    }
    /// Gets the block headers for the specified range of blocks. If `end_height` is `None`, the returned `tip_height` provides the tip at the moment
    /// the chain was queried.
    pub fn get_block_headers(
        &self,
        start_height: u32,
        end_height: Option<u32>,
    ) -> impl 'agent + AsyncCall<Value = (GetBlockHeadersResponse,), Error = BaseError> {
        #[derive(CandidType)]
        struct In {
            start_height: u32,
            end_height: Option<u32>,
        }
        self.update("bitcoin_get_block_headers")
            .with_arg(In {
                start_height,
                end_height,
            })
            .build()
    }
    /// Submits a new Bitcoin transaction. No guarantees are made about the outcome.
    pub fn send_transaction(
        &self,
        transaction: Vec<u8>,
    ) -> impl 'agent + AsyncCall<Value = (), Error = BaseError> {
        #[derive(CandidType, Deserialize)]
        struct In {
            network: BitcoinNetwork,
            #[serde(with = "serde_bytes")]
            transaction: Vec<u8>,
        }
        self.update("bitcoin_send_transaction")
            .with_arg(In {
                network: self.network,
                transaction,
            })
            .build()
    }
}

#[derive(Debug, CandidType)]
struct GetBalance<'a> {
    address: &'a str,
    network: BitcoinNetwork,
    min_confirmations: Option<u32>,
}

#[derive(Debug, CandidType)]
struct GetUtxos<'a> {
    address: &'a str,
    network: BitcoinNetwork,
    filter: Option<UtxosFilter>,
}

/// The Bitcoin network that a Bitcoin transaction is placed on.
#[derive(Clone, Copy, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub enum BitcoinNetwork {
    /// The BTC network.
    #[serde(rename = "mainnet")]
    Mainnet,
    /// The TESTBTC network.
    #[serde(rename = "testnet")]
    Testnet,
    /// The REGTEST network.
    ///
    /// This is only available when developing with local replica.
    #[serde(rename = "regtest")]
    Regtest,
}

/// Defines how to filter results from [`BitcoinCanister::get_utxos_query`].
#[derive(Debug, Clone, CandidType, Deserialize)]
pub enum UtxosFilter {
    /// Filter by the minimum number of UTXO confirmations. Most applications should set this to 6.
    #[serde(rename = "min_confirmations")]
    MinConfirmations(u32),
    /// When paginating results, use this page. Provided by [`GetUtxosResponse.next_page`](GetUtxosResponse).
    #[serde(rename = "page")]
    Page(#[serde(with = "serde_bytes")] Vec<u8>),
}

/// Unique output descriptor of a Bitcoin transaction.
#[derive(Debug, Clone, CandidType, Deserialize)]
pub struct UtxoOutpoint {
    /// The ID of the transaction. Not necessarily unique on its own.
    #[serde(with = "serde_bytes")]
    pub txid: Vec<u8>,
    /// The index of the outpoint within the transaction.
    pub vout: u32,
}

/// A Bitcoin [`UTXO`](https://en.wikipedia.org/wiki/Unspent_transaction_output), produced by a transaction.
#[derive(Debug, Clone, CandidType, Deserialize)]
pub struct Utxo {
    /// The transaction outpoint that produced this UTXO.
    pub outpoint: UtxoOutpoint,
    /// The BTC quantity, in satoshis.
    pub value: u64,
    /// The block index this transaction was placed at.
    pub height: u32,
}

/// Response type for the [`BitcoinCanister::get_utxos_query`] function.
#[derive(Debug, Clone, CandidType, Deserialize)]
pub struct GetUtxosResponse {
    /// A list of UTXOs available for the specified address.
    pub utxos: Vec<Utxo>,
    /// The hash of the tip.
    #[serde(with = "serde_bytes")]
    pub tip_block_hash: Vec<u8>,
    /// The block index of the tip of the chain known to the IC.
    pub tip_height: u32,
    /// If `Some`, then `utxos` does not contain the entire results of the query.
    /// Call `bitcoin_get_utxos_query` again using `UtxosFilter::Page` for the next page of results.
    pub next_page: Option<Vec<u8>>,
}

/// Response type for the [`BitcoinCanister::get_block_headers`] function.
#[derive(Debug, Clone, CandidType, Deserialize)]
pub struct GetBlockHeadersResponse {
    /// The tip of the chain, current to when the headers were fetched.
    pub tip_height: u32,
    /// The headers of the requested block range.
    pub block_headers: Vec<Vec<u8>>,
}
