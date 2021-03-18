use crate::call::SyncCall;
use crate::canister::CanisterBuilder;
use crate::Canister;
use candid::parser::value::IDLValue;
use candid::{CandidType, Deserialize};
use ic_agent::export::Principal;
use ic_agent::Agent;
use std::fmt::Debug;

#[derive(Debug, Clone, Copy, Ord, PartialOrd, Eq, PartialEq)]
pub struct HttpRequestCanister;

#[derive(CandidType, Clone, Deserialize)]
pub struct HeaderField(pub String, pub String);

#[derive(CandidType, Deserialize)]
pub struct HttpRequest<'body> {
    pub method: String,
    pub url: String,
    pub headers: Vec<HeaderField>,
    #[serde(with = "serde_bytes")]
    pub body: &'body [u8],
}

#[derive(CandidType, Deserialize)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers: Vec<HeaderField>,
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    pub next_token: Option<IDLValue>,
}

#[derive(CandidType, Deserialize)]
pub struct NextHttpResponse {
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    pub next_token: Option<IDLValue>,
}

impl HttpRequestCanister {
    /// Create an instance of a [Canister] implementing the [HttpRequestCanister] interface
    /// and pointing to the right Canister ID.
    pub fn create(agent: &Agent, canister_id: Principal) -> Canister<HttpRequestCanister> {
        Canister::builder()
            .with_agent(agent)
            .with_canister_id(canister_id)
            .with_interface(HttpRequestCanister)
            .build()
            .unwrap()
    }

    /// Creating a CanisterBuilder with the right interface and Canister Id. This can
    /// be useful, for example, for providing additional Builder information.
    pub fn with_agent(agent: &Agent) -> CanisterBuilder<HttpRequestCanister> {
        Canister::builder()
            .with_agent(agent)
            .with_interface(HttpRequestCanister)
    }
}

impl<'agent> Canister<'agent, HttpRequestCanister> {
    pub fn http_request<'canister: 'agent, M: Into<String>, U: Into<String>, B: AsRef<[u8]>>(
        &'canister self,
        method: M,
        url: U,
        headers: Vec<HeaderField>,
        body: B,
    ) -> impl 'agent + SyncCall<(HttpResponse,)> {
        self.query_("http_request")
            .with_arg(HttpRequest {
                method: method.into(),
                url: url.into(),
                headers,
                body: body.as_ref(),
            })
            .build()
    }

    pub fn http_request_next<
        'canister: 'agent,
    >(
        &'canister self,
        token: IDLValue,
    ) -> impl 'agent + SyncCall<(NextHttpResponse,)> {
        self.query_("http_request_next")
            .with_value_arg(token)
            .build()
    }
}
