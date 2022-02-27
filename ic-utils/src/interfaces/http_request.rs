use crate::{call::AsyncCall, call::SyncCall, canister::CanisterBuilder, Canister};
use candid::{CandidType, Deserialize, Func, Nat};
use ic_agent::{export::Principal, Agent};
use serde_bytes::ByteBuf;
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
pub struct Token {
    key: String,
    content_encoding: String,
    pub index: Nat,
    // The sha ensures that a client doesn't stream part of one version of an asset
    // followed by part of a different asset, even if not checking the certificate.
    sha256: Option<ByteBuf>,
}

#[derive(CandidType, Deserialize)]
pub struct CallbackStrategy {
    pub callback: Func,
    pub token: Token,
}

#[derive(CandidType, Deserialize)]
pub enum StreamingStrategy {
    Callback(CallbackStrategy),
}

#[derive(CandidType, Deserialize)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers: Vec<HeaderField>,
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    pub streaming_strategy: Option<StreamingStrategy>,
    pub upgrade: Option<bool>,
}

#[derive(CandidType, Deserialize)]
pub struct StreamingCallbackHttpResponse {
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    pub token: Option<Token>,
    pub chunk_tree: Option<String>,
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

    pub fn http_request_update<
        'canister: 'agent,
        M: Into<String>,
        U: Into<String>,
        B: AsRef<[u8]>,
    >(
        &'canister self,
        method: M,
        url: U,
        headers: Vec<HeaderField>,
        body: B,
    ) -> impl 'agent + AsyncCall<(HttpResponse,)> {
        self.update_("http_request_update")
            .with_arg(HttpRequest {
                method: method.into(),
                url: url.into(),
                headers,
                body: body.as_ref(),
            })
            .build()
    }

    pub fn http_request_stream_callback<'canister: 'agent, M: Into<String>>(
        &'canister self,
        method: M,
        token: Token,
    ) -> impl 'agent + SyncCall<(StreamingCallbackHttpResponse,)> {
        self.query_(&method.into()).with_arg(token).build()
    }
}

#[cfg(test)]
mod test {
    use super::HttpResponse;
    use candid::{Decode, Encode};

    mod pre_update_legacy {
        use candid::{CandidType, Deserialize, Func, Nat};
        use serde_bytes::ByteBuf;

        #[derive(CandidType, Deserialize)]
        pub struct Token {
            key: String,
            content_encoding: String,
            index: Nat,
            sha256: Option<ByteBuf>,
        }

        #[derive(CandidType, Deserialize)]
        pub struct CallbackStrategy {
            pub callback: Func,
            pub token: Token,
        }

        #[derive(CandidType, Clone, Deserialize)]
        pub struct HeaderField(pub String, pub String);

        #[derive(CandidType, Deserialize)]
        pub enum StreamingStrategy {
            Callback(CallbackStrategy),
        }

        #[derive(CandidType, Deserialize)]
        pub struct HttpResponse {
            pub status_code: u16,
            pub headers: Vec<HeaderField>,
            #[serde(with = "serde_bytes")]
            pub body: Vec<u8>,
            pub streaming_strategy: Option<StreamingStrategy>,
        }
    }

    #[test]
    fn deserialize_legacy_http_response() {
        let bytes: Vec<u8> = Encode!(&pre_update_legacy::HttpResponse {
            status_code: 100,
            headers: Vec::new(),
            body: Vec::new(),
            streaming_strategy: None,
        })
        .unwrap();

        let _response = Decode!(&bytes, HttpResponse).unwrap();
    }
}
