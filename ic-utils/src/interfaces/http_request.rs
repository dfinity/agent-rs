//! The canister interface for canisters that implement HTTP requests.

use crate::{call::AsyncCall, call::SyncCall, canister::CanisterBuilder, Canister};
use candid::{CandidType, Deserialize, Func, Nat};
use ic_agent::{export::Principal, Agent};
use serde_bytes::ByteBuf;
use std::fmt::Debug;

/// A canister that can serve a HTTP request.
#[derive(Debug, Clone, Copy, Ord, PartialOrd, Eq, PartialEq)]
pub struct HttpRequestCanister;

/// A key-value pair for a HTTP header.
#[derive(Debug, CandidType, Clone, Deserialize)]
pub struct HeaderField(pub String, pub String);

/// The important components of an HTTP request.
#[derive(Debug, Clone, CandidType, Deserialize)]
pub struct HttpRequest<'body> {
    /// The HTTP method string.
    pub method: String,
    /// The URL that was visited.
    pub url: String,
    /// The request headers.
    pub headers: Vec<HeaderField>,
    /// The request body.
    #[serde(with = "serde_bytes")]
    pub body: &'body [u8],
}

/// A token for continuing a callback streaming strategy.
#[derive(Debug, Clone, CandidType, Deserialize)]
pub struct Token {
    key: String,
    content_encoding: String,
    index: Nat,
    // The sha ensures that a client doesn't stream part of one version of an asset
    // followed by part of a different asset, even if not checking the certificate.
    sha256: Option<ByteBuf>,
}

/// A callback-token pair for a callback streaming strategy.
#[derive(Debug, Clone, CandidType, Deserialize)]
pub struct CallbackStrategy {
    /// The callback function to be called to continue the stream.
    pub callback: Func,
    /// The token to pass to the function.
    pub token: Token,
}

/// Possible strategies for a streaming response.
#[derive(Debug, Clone, CandidType, Deserialize)]
pub enum StreamingStrategy {
    /// A callback-based streaming strategy, where a callback function is provided for continuing the stream.
    Callback(CallbackStrategy),
}

/// A HTTP response.
#[derive(Debug, Clone, CandidType, Deserialize)]
pub struct HttpResponse {
    /// The HTTP status code.
    pub status_code: u16,
    /// The response header map.
    pub headers: Vec<HeaderField>,
    #[serde(with = "serde_bytes")]
    /// The response body.
    pub body: Vec<u8>,
    /// The strategy for streaming the rest of the data, if the full response is to be streamed.
    pub streaming_strategy: Option<StreamingStrategy>,
    /// Whether the query call should be upgraded to an update call.
    pub upgrade: Option<bool>,
}

/// The next chunk of a streaming HTTP response.
#[derive(Debug, Clone, CandidType, Deserialize)]
pub struct StreamingCallbackHttpResponse {
    /// The body of the stream chunk.
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    /// The new stream continuation token.
    pub token: Option<Token>,
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
    /// Performs a HTTP request, receiving a HTTP response.
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

    /// Performs a HTTP request over an update call. Unlike query calls, update calls must pass consensus
    /// and therefore cannot be tampered with by a malicious node.
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

    /// Retrieves the next chunk of a stream from a streaming callback, using the method from [`CallbackStrategy`].
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
