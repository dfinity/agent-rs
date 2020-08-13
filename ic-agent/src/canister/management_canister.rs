use crate::agent::agent_error::AgentError;
use crate::agent::response::Replied;
use crate::agent::Agent;
use crate::{Blob, CanisterAttributes, Principal};
use candid::{Decode, Encode};
use std::str::FromStr;

const CREATE_METHOD_NAME: &str = "create_canister";
const INSTALL_METHOD_NAME: &str = "install_code";

#[derive(candid::CandidType, candid::Deserialize)]
struct CreateResult {
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
}

pub struct ManagementCanister<'agent> {
    agent: &'agent Agent,
}

impl<'agent> ManagementCanister<'agent> {
    pub fn new(agent: &'agent Agent) -> Self {
        ManagementCanister { agent }
    }

    pub async fn create_canister<W: delay::Waiter>(
        &self,
        waiter: W,
    ) -> Result<Principal, AgentError> {
        // candid encoding of () i.e. no arguments
        let bytes: Vec<u8> = candid::Encode!().unwrap();
        let request_id = self
            .agent
            .update_raw(
                &Principal::management_canister(),
                CREATE_METHOD_NAME,
                &Blob::from(bytes),
            )
            .await?;
        match self
            .agent
            .request_status_and_wait(&request_id, waiter)
            .await?
        {
            Replied::CallReplied(blob) => {
                let cid = Decode!(blob.as_slice(), CreateResult)?;
                Ok(Principal::from_text(cid.canister_id.to_text())?)
            }
        }
    }

    pub async fn install_code<W: delay::Waiter>(
        &self,
        waiter: W,
        canister_id: &Principal,
        mode: InstallMode,
        module: &Blob,
        arg: &Blob,
        attributes: &CanisterAttributes,
    ) -> Result<(), AgentError> {
        let canister_to_install = CanisterInstall {
            mode,
            canister_id: candid::Principal::from_text(canister_id.to_text())?,
            wasm_module: module.as_slice().to_vec(),
            arg: arg.as_slice().to_vec(),
            compute_allocation: attributes.compute_allocation.map(|x| x.into()),
        };
        let bytes: Vec<u8> = candid::Encode!(&canister_to_install).unwrap();
        let request_id = self
            .agent
            .update_raw(
                &Principal::management_canister(),
                INSTALL_METHOD_NAME,
                &Blob::from(bytes),
            )
            .await?;
        match self
            .agent
            .request_status_and_wait(&request_id, waiter)
            .await?
        {
            // Candid type returned is () so validating the result.
            Replied::CallReplied(blob) => {
                Decode!(&blob.0)?;
                Ok(())
            }
        }
    }
}
