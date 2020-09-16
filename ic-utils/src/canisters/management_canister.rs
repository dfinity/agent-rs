use crate::call::AsyncCall;
use crate::Canister;
use async_trait::async_trait;
use candid::ser::IDLBuilder;
use candid::{CandidType, Deserialize};
use delay::Waiter;
use ic_agent::{AgentError, ComputeAllocation, RequestId};
use ic_types::Principal;
use std::fmt::Debug;
use std::str::FromStr;

pub struct ManagementCanister;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CanisterStatus {
    Running,
    Stopping,
    Stopped,
}

impl std::fmt::Display for CanisterStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

#[derive(Copy, Clone, CandidType, Deserialize, Eq, PartialEq)]
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

pub struct InstallCodeBuilder<'agent, 'canister: 'agent, T> {
    canister: &'canister Canister<'agent, T>,
    canister_id: Principal,
    wasm: &'canister [u8],
    arg: Result<IDLBuilder, candid::Error>,
    mode: Option<InstallMode>,
    compute_allocation: Option<ComputeAllocation>,
}

impl<'agent, 'canister: 'agent, T> InstallCodeBuilder<'agent, 'canister, T> {
    pub fn builder(
        canister: &'canister Canister<'agent, T>,
        canister_id: &Principal,
        wasm: &'canister [u8],
    ) -> Self {
        Self {
            canister,
            canister_id: canister_id.clone(),
            wasm,
            arg: Ok(IDLBuilder::new()),
            mode: None,
            compute_allocation: None,
        }
    }

    pub fn with_arg<Argument: CandidType + Sync + Send>(
        mut self,
        arg: Argument,
    ) -> InstallCodeBuilder<'agent, 'canister, T> {
        if let Ok(ref mut idl_builder) = self.arg {
            let result = idl_builder.arg(&arg);
            if let Err(e) = result {
                self.arg = Err(e)
            }
        }
        self
    }

    pub fn with_mode(self, mode: InstallMode) -> Self {
        Self {
            mode: Some(mode),
            ..self
        }
    }

    pub fn with_compute_allocation<C: Into<ComputeAllocation>>(
        self,
        compute_allocation: C,
    ) -> Self {
        Self {
            compute_allocation: Some(compute_allocation.into()),
            ..self
        }
    }

    pub fn build(self) -> Result<impl 'agent + AsyncCall<()>, AgentError> {
        #[derive(candid::CandidType)]
        struct CanisterInstall {
            mode: InstallMode,
            canister_id: Principal,
            wasm_module: Vec<u8>,
            arg: Vec<u8>,
            compute_allocation: Option<u8>,
            memory_allocation: Option<u8>,
        }

        Ok(self
            .canister
            .update_("install_code")
            .with_arg(CanisterInstall {
                mode: self.mode.unwrap_or(InstallMode::Install),
                canister_id: self.canister_id.clone(),
                wasm_module: self.wasm.to_owned(),
                arg: self
                    .arg
                    .and_then(|mut idl_builder| idl_builder.serialize_to_vec())?,
                compute_allocation: self.compute_allocation.map(|ca| ca.into()),
                memory_allocation: None,
            })
            .build())
    }

    pub async fn call(self) -> Result<RequestId, AgentError> {
        self.build()?.call().await
    }

    pub async fn call_and_wait<W>(self, waiter: W) -> Result<(), AgentError>
    where
        W: Waiter,
    {
        self.build()?.call_and_wait(waiter).await
    }
}

#[async_trait]
impl<'agent, 'canister: 'agent, T: Sync> AsyncCall<()>
    for InstallCodeBuilder<'agent, 'canister, T>
{
    async fn call(self) -> Result<RequestId, AgentError> {
        self.build()?.call().await
    }

    async fn call_and_wait<W>(self, waiter: W) -> Result<(), AgentError>
    where
        W: Waiter,
    {
        self.build()?.call_and_wait(waiter).await
    }
}

impl<'agent> Canister<'agent, ManagementCanister> {
    pub fn canister_status<'canister: 'agent>(
        &'canister self,
        canister_id: &Principal,
    ) -> impl 'agent + AsyncCall<(CanisterStatus,)> {
        #[derive(CandidType)]
        struct In {
            canister_id: Principal,
        }

        #[derive(Deserialize)]
        struct Out {
            status: CanisterStatus,
        }

        self.update_("canister_status")
            .with_arg(In {
                canister_id: canister_id.clone(),
            })
            .build()
            .map(|result: (Out,)| (result.0.status,))
    }

    /// Create a canister, returning a caller that returns a Canister Id.
    pub fn create_canister<'canister: 'agent>(
        &'canister self,
    ) -> impl 'agent + AsyncCall<(Principal,)> {
        #[derive(Deserialize)]
        struct Out {
            canister_id: Principal,
        }

        self.update_("create_canister")
            .build()
            .map(|result: (Out,)| (result.0.canister_id,))
    }

    /// Deletes a canister.
    pub fn delete_canister<'canister: 'agent>(
        &'canister self,
        canister_id: &Principal,
    ) -> impl 'agent + AsyncCall<()> {
        #[derive(CandidType)]
        struct Argument {
            canister_id: Principal,
        }

        self.update_("delete_canister")
            .with_arg(Argument {
                canister_id: canister_id.clone(),
            })
            .build()
    }

    /// Starts a canister.
    pub fn start_canister<'canister: 'agent>(
        &'canister self,
        canister_id: &Principal,
    ) -> impl 'agent + AsyncCall<()> {
        #[derive(CandidType)]
        struct Argument {
            canister_id: Principal,
        }

        self.update_("start_canister")
            .with_arg(Argument {
                canister_id: canister_id.clone(),
            })
            .build()
    }

    /// Stop a canister.
    pub fn stop_canister<'canister: 'agent>(
        &'canister self,
        canister_id: &Principal,
    ) -> impl 'agent + AsyncCall<()> {
        #[derive(CandidType)]
        struct Argument {
            canister_id: Principal,
        }

        self.update_("stop_canister")
            .with_arg(Argument {
                canister_id: canister_id.clone(),
            })
            .build()
    }

    /// Install a canister, with all the arguments necessary for creating the canister.
    pub fn install_code<'canister: 'agent>(
        &'canister self,
        canister_id: &Principal,
        wasm: &'canister [u8],
    ) -> InstallCodeBuilder<'agent, 'canister, ManagementCanister> {
        InstallCodeBuilder::builder(self, canister_id, wasm)
    }
}
