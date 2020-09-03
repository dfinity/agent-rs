use crate::agent::agent_error::AgentError;
use crate::agent::Agent;
use crate::{CanisterAttributes, Principal};
use candid::{Decode, Encode};
use std::str::FromStr;

const CREATE_METHOD_NAME: &str = "create_canister";
const DELETE_METHOD_NAME: &str = "delete_canister";
const INSTALL_METHOD_NAME: &str = "install_code";
const START_METHOD_NAME: &str = "start_canister";
const STATUS_METHOD_NAME: &str = "canister_status";
const STOP_METHOD_NAME: &str = "stop_canister";

#[derive(Clone, Debug, candid::CandidType, candid::Deserialize, PartialEq)]
pub enum CanisterStatus {
    #[serde(rename = "running")]
    Running,
    #[serde(rename = "stopping")]
    Stopping,
    #[serde(rename = "stopped")]
    Stopped,
}

impl std::fmt::Display for CanisterStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

#[derive(candid::CandidType, candid::Deserialize)]
struct StatusReply {
    status: CanisterStatus,
}
#[derive(candid::CandidType, candid::Deserialize)]
struct CanisterRecord {
    canister_id: candid::Principal,
}

#[derive(Clone, candid::CandidType, candid::Deserialize)]
pub enum InstallMode {
    #[serde(rename = "install")]
    Install,
    #[serde(rename = "reinstall")]
    Reinstall,
    #[serde(rename = "upgrade")]
    Upgrade,
}

impl FromStr for InstallMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "install" => Ok(InstallMode::Install),
            "reinstall" => Ok(InstallMode::Reinstall),
            "upgrade" => Ok(InstallMode::Upgrade),
            &_ => Err(format!("Invalid install mode: {}", s)),
        }
    }
}

#[derive(candid::CandidType, candid::Deserialize)]
struct CanisterInstall {
    mode: InstallMode,
    canister_id: candid::Principal,
    wasm_module: Vec<u8>,
    arg: Vec<u8>,
    compute_allocation: Option<u8>,
    memory_allocation: Option<u64>,
}

pub struct ManagementCanister<'agent> {
    agent: &'agent Agent,
}

impl<'agent> ManagementCanister<'agent> {
    pub fn new(agent: &'agent Agent) -> Self {
        ManagementCanister { agent }
    }

    pub async fn canister_status<W: delay::Waiter>(
        &self,
        waiter: W,
        canister_id: &Principal,
    ) -> Result<CanisterStatus, AgentError> {
        let canister_to_install = CanisterRecord {
            canister_id: candid::Principal::from_text(canister_id.to_text())?,
        };
        let bytes: Vec<u8> = candid::Encode!(&canister_to_install).unwrap();
        let bytes_to_decode = self
            .agent
            .update(&Principal::management_canister(), STATUS_METHOD_NAME)
            .with_arg(&bytes)
            .call_and_wait(waiter)
            .await?;
        let reply = Decode!(&bytes_to_decode, StatusReply)?;
        Ok(reply.status)
    }

    pub async fn create_canister<W: delay::Waiter>(
        &self,
        waiter: W,
    ) -> Result<Principal, AgentError> {
        // candid encoding of () i.e. no arguments
        let bytes: Vec<u8> = candid::Encode!().unwrap();
        let bytes_to_decode = self
            .agent
            .update(&Principal::management_canister(), CREATE_METHOD_NAME)
            .with_arg(&bytes)
            .call_and_wait(waiter)
            .await?;

        let cid = Decode!(bytes_to_decode.as_slice(), CanisterRecord)?;
        Ok(Principal::from_text(cid.canister_id.to_text())?)
    }

    pub async fn delete_canister<W: delay::Waiter>(
        &self,
        waiter: W,
        canister_id: &Principal,
    ) -> Result<(), AgentError> {
        let canister_to_install = CanisterRecord {
            canister_id: candid::Principal::from_text(canister_id.to_text())?,
        };
        let bytes: Vec<u8> = candid::Encode!(&canister_to_install).unwrap();
        let bytes_to_decode = self
            .agent
            .update(&Principal::management_canister(), DELETE_METHOD_NAME)
            .with_arg(&bytes)
            .call_and_wait(waiter)
            .await?;
        // Candid type returned is () so validating the result.
        Decode!(&bytes_to_decode)?;
        Ok(())
    }

    pub async fn start_canister<W: delay::Waiter>(
        &self,
        waiter: W,
        canister_id: &Principal,
    ) -> Result<(), AgentError> {
        let canister_to_install = CanisterRecord {
            canister_id: candid::Principal::from_text(canister_id.to_text())?,
        };
        let bytes: Vec<u8> = candid::Encode!(&canister_to_install).unwrap();
        let bytes_to_decode = self
            .agent
            .update(&Principal::management_canister(), START_METHOD_NAME)
            .with_arg(&bytes)
            .call_and_wait(waiter)
            .await?;
        // Candid type returned is () so validating the result.
        Decode!(&bytes_to_decode)?;
        Ok(())
    }

    pub async fn stop_canister<W: delay::Waiter>(
        &self,
        waiter: W,
        canister_id: &Principal,
    ) -> Result<(), AgentError> {
        let canister_to_install = CanisterRecord {
            canister_id: candid::Principal::from_text(canister_id.to_text())?,
        };
        let bytes: Vec<u8> = candid::Encode!(&canister_to_install).unwrap();
        let bytes_to_decode = self
            .agent
            .update(&Principal::management_canister(), STOP_METHOD_NAME)
            .with_arg(&bytes)
            .call_and_wait(waiter)
            .await?;
        // Candid type returned is () so validating the result.
        Decode!(&bytes_to_decode)?;
        Ok(())
    }

    pub async fn install_code<W: delay::Waiter>(
        &self,
        waiter: W,
        canister_id: &Principal,
        mode: InstallMode,
        module: &[u8],
        arg: &[u8],
        attributes: &CanisterAttributes,
    ) -> Result<(), AgentError> {
        let canister_to_install = CanisterInstall {
            mode,
            canister_id: candid::Principal::from_text(canister_id.to_text())?,
            wasm_module: module.to_vec(),
            arg: arg.to_vec(),
            compute_allocation: attributes.compute_allocation.map(|x| x.into()),
            memory_allocation: None,
        };
        let bytes: Vec<u8> = candid::Encode!(&canister_to_install).unwrap();
        let bytes_to_decode = self
            .agent
            .update(&Principal::management_canister(), INSTALL_METHOD_NAME)
            .with_arg(&bytes)
            .call_and_wait(waiter)
            .await?;

        // Candid type returned is () so validating the result.
        Decode!(bytes_to_decode.as_slice())?;
        Ok(())
    }
}
