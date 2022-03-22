//! The canister interface for canisters that implement HTTP requests.

use crate::{
    call::{AsyncCall, SyncCall},
    canister::CanisterBuilder,
    Canister,
};
use candid::{
    parser::{
        types::FuncMode,
        value::{IDLValue, IDLValueVisitor},
    },
    types::{reference::FuncVisitor, Function, Serializer, Type},
    CandidType, Deserialize, Func,
};
use ic_agent::{export::Principal, Agent};
use std::{
    borrow::Cow,
    convert::TryInto,
    fmt::Debug,
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

/// A canister that can serve a HTTP request.
#[derive(Debug, Clone, Copy, Ord, PartialOrd, Eq, PartialEq)]
pub struct HttpRequestCanister;

/// A key-value pair for a HTTP header.
#[derive(Debug, CandidType, Clone, Deserialize)]
pub struct HeaderField<'a>(pub Cow<'a, str>, pub Cow<'a, str>);

/// The important components of an HTTP request.
#[derive(Debug, Clone, CandidType)]
pub struct HttpRequest<'a> {
    /// The HTTP method string.
    pub method: &'a str,
    /// The URL that was visited.
    pub url: &'a str,
    /// The request headers.
    pub headers: &'a [HeaderField<'a>],
    /// The request body.
    pub body: &'a [u8],
}

/// A HTTP response.
#[derive(Debug, Clone, CandidType, Deserialize)]
pub struct HttpResponse<Token = self::Token, Callback = HttpRequestStreamingCallback> {
    /// The HTTP status code.
    pub status_code: u16,
    /// The response header map.
    pub headers: Vec<HeaderField<'static>>,
    /// The response body.
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    /// The strategy for streaming the rest of the data, if the full response is to be streamed.
    pub streaming_strategy: Option<StreamingStrategy<Token, Callback>>,
    /// Whether the query call should be upgraded to an update call.
    pub upgrade: Option<bool>,
}

impl<T1, C1> HttpResponse<T1, C1> {
    /// Convert another streaming strategy
    pub fn from<T2: Into<T1>, C2: Into<C1>>(v: HttpResponse<T2, C2>) -> Self {
        Self {
            status_code: v.status_code,
            headers: v.headers,
            body: v.body,
            streaming_strategy: v.streaming_strategy.map(StreamingStrategy::from),
            upgrade: v.upgrade,
        }
    }
    /// Convert this streaming strategy
    pub fn into<T2, C2>(self) -> HttpResponse<T2, C2>
    where
        T1: Into<T2>,
        C1: Into<C2>,
    {
        HttpResponse::from(self)
    }
    /// Attempt to convert another streaming strategy
    pub fn try_from<T2, C2, E>(v: HttpResponse<T2, C2>) -> Result<Self, E>
    where
        T2: TryInto<T1>,
        C2: TryInto<C1>,
        T2::Error: Into<E>,
        C2::Error: Into<E>,
    {
        Ok(Self {
            status_code: v.status_code,
            headers: v.headers,
            body: v.body,
            streaming_strategy: v
                .streaming_strategy
                .map(StreamingStrategy::try_from)
                .transpose()?,
            upgrade: v.upgrade,
        })
    }
    /// Attempt to convert this streaming strategy
    pub fn try_into<T2, C2, E>(self) -> Result<HttpResponse<T2, C2>, E>
    where
        T1: TryInto<T2>,
        C1: TryInto<C2>,
        T1::Error: Into<E>,
        C1::Error: Into<E>,
    {
        HttpResponse::try_from(self)
    }
}

/// Possible strategies for a streaming response.
#[derive(Debug, Clone, CandidType, Deserialize)]
pub enum StreamingStrategy<Token = self::Token, Callback = HttpRequestStreamingCallback> {
    /// A callback-based streaming strategy, where a callback function is provided for continuing the stream.
    Callback(CallbackStrategy<Token, Callback>),
}

impl<T1, C1> StreamingStrategy<T1, C1> {
    /// Convert another streaming strategy
    pub fn from<T2: Into<T1>, C2: Into<C1>>(v: StreamingStrategy<T2, C2>) -> Self {
        match v {
            StreamingStrategy::Callback(c) => Self::Callback(c.into()),
        }
    }
    /// Convert this streaming strategy
    pub fn into<T2, C2>(self) -> StreamingStrategy<T2, C2>
    where
        T1: Into<T2>,
        C1: Into<C2>,
    {
        StreamingStrategy::from(self)
    }
    /// Attempt to convert another streaming strategy
    pub fn try_from<T2, C2, E>(v: StreamingStrategy<T2, C2>) -> Result<Self, E>
    where
        T2: TryInto<T1>,
        C2: TryInto<C1>,
        T2::Error: Into<E>,
        C2::Error: Into<E>,
    {
        Ok(match v {
            StreamingStrategy::Callback(c) => Self::Callback(c.try_into()?),
        })
    }
    /// Attempt to convert this streaming strategy
    pub fn try_into<T2, C2, E>(self) -> Result<StreamingStrategy<T2, C2>, E>
    where
        T1: TryInto<T2>,
        C1: TryInto<C2>,
        T1::Error: Into<E>,
        C1::Error: Into<E>,
    {
        StreamingStrategy::try_from(self)
    }
}

/// A callback-token pair for a callback streaming strategy.
#[derive(Debug, Clone, CandidType, Deserialize)]
pub struct CallbackStrategy<Token = self::Token, Callback = HttpRequestStreamingCallback> {
    /// The callback function to be called to continue the stream.
    pub callback: Callback,
    /// The token to pass to the function.
    pub token: Token,
}

impl<T1, C1> CallbackStrategy<T1, C1> {
    /// Convert another callback strategy
    pub fn from<T2: Into<T1>, C2: Into<C1>>(v: CallbackStrategy<T2, C2>) -> Self {
        Self {
            callback: v.callback.into(),
            token: v.token.into(),
        }
    }
    /// Convert this callback strategy
    pub fn into<T2, C2>(self) -> CallbackStrategy<T2, C2>
    where
        T1: Into<T2>,
        C1: Into<C2>,
    {
        CallbackStrategy::from(self)
    }
    /// Attempt to convert another callback strategy
    pub fn try_from<T2, C2, E>(v: CallbackStrategy<T2, C2>) -> Result<Self, E>
    where
        T2: TryInto<T1>,
        C2: TryInto<C1>,
        T2::Error: Into<E>,
        C2::Error: Into<E>,
    {
        Ok(Self {
            callback: v.callback.try_into().map_err(Into::into)?,
            token: v.token.try_into().map_err(Into::into)?,
        })
    }
    /// Attempt to convert this callback strategy
    pub fn try_into<T2, C2, E>(self) -> Result<CallbackStrategy<T2, C2>, E>
    where
        T1: TryInto<T2>,
        C1: TryInto<C2>,
        T1::Error: Into<E>,
        C1::Error: Into<E>,
    {
        CallbackStrategy::try_from(self)
    }
}

/// A callback of any type, extremely permissive
#[derive(Debug, Clone)]
pub struct HttpRequestStreamingCallbackAny(pub Func);

impl CandidType for HttpRequestStreamingCallbackAny {
    fn _ty() -> Type {
        Type::Reserved
    }
    fn idl_serialize<S: Serializer>(&self, _serializer: S) -> Result<(), S::Error> {
        // We cannot implement serialize, since our type must be `Reserved` in order to accept anything.
        // Attempting to serialize this type is always an error and should be regarded as a compile time error.
        unimplemented!("Callback is not serializable")
    }
}

impl<'de> Deserialize<'de> for HttpRequestStreamingCallbackAny {
    fn deserialize<D: serde::de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Ya know it says `ignored`, but what if we just didn't ignore it.
        deserializer.deserialize_ignored_any(FuncVisitor).map(Self)
    }
}

impl From<Func> for HttpRequestStreamingCallbackAny {
    fn from(f: Func) -> Self {
        Self(f)
    }
}
impl From<HttpRequestStreamingCallbackAny> for Func {
    fn from(c: HttpRequestStreamingCallbackAny) -> Self {
        c.0
    }
}

/// A callback of type `shared query (Token) -> async StreamingCallbackHttpResponse`
#[derive(Debug, Clone)]
pub struct HttpRequestStreamingCallback<ArgToken = self::ArgToken>(
    pub Func,
    pub PhantomData<ArgToken>,
);

impl<ArgToken: CandidType> CandidType for HttpRequestStreamingCallback<ArgToken> {
    fn _ty() -> Type {
        Type::Func(Function {
            modes: vec![FuncMode::Query],
            args: vec![ArgToken::ty()],
            rets: vec![StreamingCallbackHttpResponse::<ArgToken>::ty()],
        })
    }
    fn idl_serialize<S: Serializer>(&self, serializer: S) -> Result<(), S::Error> {
        self.0.idl_serialize(serializer)
    }
}

impl<'de, ArgToken> Deserialize<'de> for HttpRequestStreamingCallback<ArgToken> {
    fn deserialize<D: serde::de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Func::deserialize(deserializer).map(Self::from)
    }
}

impl<ArgToken> From<Func> for HttpRequestStreamingCallback<ArgToken> {
    fn from(f: Func) -> Self {
        Self(f, PhantomData)
    }
}

impl<ArgToken> From<HttpRequestStreamingCallback<ArgToken>> for Func {
    fn from(c: HttpRequestStreamingCallback<ArgToken>) -> Self {
        c.0
    }
}

impl<ArgToken> Deref for HttpRequestStreamingCallback<ArgToken> {
    type Target = Func;
    fn deref(&self) -> &Func {
        &self.0
    }
}

impl<ArgToken> DerefMut for HttpRequestStreamingCallback<ArgToken> {
    fn deref_mut(&mut self) -> &mut Func {
        &mut self.0
    }
}

/// The next chunk of a streaming HTTP response.
#[derive(Debug, Clone, CandidType, Deserialize)]
pub struct StreamingCallbackHttpResponse<Token = self::Token> {
    /// The body of the stream chunk.
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    /// The new stream continuation token.
    pub token: Option<Token>,
}

/// A token for continuing a callback streaming strategy.
#[derive(Debug, Clone, PartialEq)]
pub struct Token(pub IDLValue);

impl CandidType for Token {
    fn _ty() -> Type {
        Type::Reserved
    }
    fn idl_serialize<S: Serializer>(&self, _serializer: S) -> Result<(), S::Error> {
        // We cannot implement serialize, since our type must be `Reserved` in order to accept anything.
        // Attempting to serialize this type is always an error and should be regarded as a compile time error.
        unimplemented!("Token is not serializable")
    }
}

impl<'de> Deserialize<'de> for Token {
    fn deserialize<D: serde::de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Ya know it says `ignored`, but what if we just didn't ignore it.
        deserializer
            .deserialize_ignored_any(IDLValueVisitor)
            .map(Token)
    }
}

/// A marker type to match unconstrained callback arguments
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
pub struct ArgToken;

impl CandidType for ArgToken {
    fn _ty() -> Type {
        Type::Empty
    }
    fn idl_serialize<S: Serializer>(&self, _serializer: S) -> Result<(), S::Error> {
        // We cannot implement serialize, since our type must be `Empty` in order to accept anything.
        // Attempting to serialize this type is always an error and should be regarded as a compile time error.
        unimplemented!("Token is not serializable")
    }
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
    pub fn http_request<'canister: 'agent>(
        &'canister self,
        method: impl AsRef<str>,
        url: impl AsRef<str>,
        headers: &[HeaderField],
        body: impl AsRef<[u8]>,
    ) -> impl 'agent + SyncCall<(HttpResponse,)> {
        self.http_request_custom(method.as_ref(), url.as_ref(), headers.as_ref(), body.as_ref())
    }

    /// Performs a HTTP request, receiving a HTTP response.
    pub fn http_request_custom<'canister: 'agent, T, C>(
        &'canister self,
        method: &str,
        url: &str,
        headers: &[HeaderField],
        body: &[u8],
    ) -> impl 'agent + SyncCall<(HttpResponse<T, C>,)>
    where
        T: 'agent + Send + Sync + CandidType + for<'de> Deserialize<'de>,
        C: 'agent + Send + Sync + CandidType + for<'de> Deserialize<'de>,
    {
        self.query_("http_request")
            .with_arg(HttpRequest {
                method: method.into(),
                url: url.into(),
                headers: headers.into(),
                body: body.into(),
            })
            .build()
    }

    /// Performs a HTTP request over an update call. Unlike query calls, update calls must pass consensus
    /// and therefore cannot be tampered with by a malicious node.
    pub fn http_request_update<'canister: 'agent>(
        &'canister self,
        method: impl AsRef<str>,
        url: impl AsRef<str>,
        headers: &[HeaderField],
        body: impl AsRef<[u8]>,
    ) -> impl 'agent + AsyncCall<(HttpResponse,)>  {
        self.http_request_update_custom(method.as_ref(), url.as_ref(), headers, body.as_ref())
    }

    /// Performs a HTTP request over an update call. Unlike query calls, update calls must pass consensus
    /// and therefore cannot be tampered with by a malicious node.
    pub fn http_request_update_custom<'canister: 'agent, T, C>(
        &'canister self,
        method: &str,
        url: &str,
        headers: &[HeaderField],
        body: &[u8],
    ) -> impl 'agent + AsyncCall<(HttpResponse<T, C>,)> 
    where
        T: 'agent + Send + Sync + CandidType + for<'de> Deserialize<'de>,
        C: 'agent + Send + Sync + CandidType + for<'de> Deserialize<'de>, {
        self.update_("http_request_update")
            .with_arg(HttpRequest {
                method: method.into(),
                url: url.into(),
                headers: headers.into(),
                body: body.into(),
            })
            .build()
    }

    /// Retrieves the next chunk of a stream from a streaming callback, using the method from [`CallbackStrategy`].
    pub fn http_request_stream_callback<'canister: 'agent>(
        &'canister self,
        method: impl AsRef<str>,
        token: Token,
    ) -> impl 'agent + SyncCall<(StreamingCallbackHttpResponse,)> {
        self.query_(method.as_ref()).with_value_arg(token.0).build()
    }

    /// Retrieves the next chunk of a stream from a streaming callback, using the method from [`CallbackStrategy`].
    pub fn http_request_stream_callback_custom<'canister: 'agent, T>(
        &'canister self,
        method: impl AsRef<str>,
        token: T,
    ) -> impl 'agent + SyncCall<(StreamingCallbackHttpResponse<T>,)>
    where T: 'agent + Send + Sync + CandidType + for<'de> Deserialize<'de>, {
        self.query_(method.as_ref()).with_arg(token).build()
    }
}

#[cfg(test)]
mod test {
    use crate::interfaces::http_request::HttpRequestStreamingCallbackAny;

    use super::{
        CallbackStrategy, HttpRequestStreamingCallback, HttpResponse,
        StreamingCallbackHttpResponse, StreamingStrategy, Token,
    };
    use candid::{
        parser::value::{IDLField, IDLValue},
        CandidType, Decode, Encode,
    };
    use serde::de::DeserializeOwned;

    mod pre_update_legacy {
        use candid::{CandidType, Deserialize, Func, Nat};
        use serde_bytes::ByteBuf;

        #[derive(CandidType, Deserialize)]
        pub struct Token {
            pub key: String,
            pub content_encoding: String,
            pub index: Nat,
            pub sha256: Option<ByteBuf>,
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

    #[test]
    fn deserialize_response_with_token() {
        use candid::{types::Label, Func, Principal};

        fn decode<C: CandidType + DeserializeOwned>(bytes: &[u8]) {
            let response = Decode!(&bytes, HttpResponse::<_, C>).unwrap();
            assert_eq!(response.status_code, 100);
            let token = match response.streaming_strategy {
                Some(StreamingStrategy::Callback(CallbackStrategy { token, .. })) => token,
                _ => panic!("streaming_strategy was missing"),
            };
            let fields = match token {
                Token(IDLValue::Record(fields)) => fields,
                _ => panic!("token type mismatched {:?}", token),
            };
            assert!(fields.contains(&IDLField {
                id: Label::Named("key".into()),
                val: IDLValue::Text("foo".into())
            }));
            assert!(fields.contains(&IDLField {
                id: Label::Named("content_encoding".into()),
                val: IDLValue::Text("bar".into())
            }));
            assert!(fields.contains(&IDLField {
                id: Label::Named("index".into()),
                val: IDLValue::Nat(42.into())
            }));
            assert!(fields.contains(&IDLField {
                id: Label::Named("sha256".into()),
                val: IDLValue::None
            }));
        }

        // Test if we can load legacy responses that use the `Func` workaround hack
        let bytes = Encode!(&HttpResponse {
            status_code: 100,
            headers: Vec::new(),
            body: Vec::new(),
            streaming_strategy: Some(StreamingStrategy::Callback(CallbackStrategy {
                callback: Func {
                    principal: Principal::from_text("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap(),
                    method: "callback".into()
                },
                token: pre_update_legacy::Token {
                    key: "foo".into(),
                    content_encoding: "bar".into(),
                    index: 42.into(),
                    sha256: None,
                },
            })),
            upgrade: None,
        })
        .unwrap();
        decode::<Func>(&bytes);
        decode::<HttpRequestStreamingCallbackAny>(&bytes);

        let bytes = Encode!(&HttpResponse {
            status_code: 100,
            headers: Vec::new(),
            body: Vec::new(),
            streaming_strategy: Some(StreamingStrategy::Callback(CallbackStrategy::<
                _,
                HttpRequestStreamingCallback,
            > {
                callback: Func {
                    principal: Principal::from_text("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap(),
                    method: "callback".into()
                }
                .into(),
                token: pre_update_legacy::Token {
                    key: "foo".into(),
                    content_encoding: "bar".into(),
                    index: 42.into(),
                    sha256: None,
                },
            })),
            upgrade: None,
        })
        .unwrap();
        decode::<HttpRequestStreamingCallback>(&bytes);
        decode::<HttpRequestStreamingCallbackAny>(&bytes);
    }

    #[test]
    fn deserialize_streaming_response_with_token() {
        use candid::types::Label;

        let bytes: Vec<u8> = Encode!(&StreamingCallbackHttpResponse {
            body: b"this is a body".as_ref().into(),
            token: Some(pre_update_legacy::Token {
                key: "foo".into(),
                content_encoding: "bar".into(),
                index: 42.into(),
                sha256: None,
            }),
        })
        .unwrap();

        let response = Decode!(&bytes, StreamingCallbackHttpResponse).unwrap();
        assert_eq!(response.body, b"this is a body");
        let fields = match response.token {
            Some(Token(IDLValue::Record(fields))) => fields,
            _ => panic!("token type mismatched {:?}", response.token),
        };
        assert!(fields.contains(&IDLField {
            id: Label::Named("key".into()),
            val: IDLValue::Text("foo".into())
        }));
        assert!(fields.contains(&IDLField {
            id: Label::Named("content_encoding".into()),
            val: IDLValue::Text("bar".into())
        }));
        assert!(fields.contains(&IDLField {
            id: Label::Named("index".into()),
            val: IDLValue::Nat(42.into())
        }));
        assert!(fields.contains(&IDLField {
            id: Label::Named("sha256".into()),
            val: IDLValue::None
        }));
    }

    #[test]
    fn deserialize_streaming_response_without_token() {
        mod missing_token {
            use candid::{CandidType, Deserialize};
            /// The next chunk of a streaming HTTP response.
            #[derive(Debug, Clone, CandidType, Deserialize)]
            pub struct StreamingCallbackHttpResponse {
                /// The body of the stream chunk.
                #[serde(with = "serde_bytes")]
                pub body: Vec<u8>,
            }
        }
        let bytes: Vec<u8> = Encode!(&missing_token::StreamingCallbackHttpResponse {
            body: b"this is a body".as_ref().into(),
        })
        .unwrap();

        let response = Decode!(&bytes, StreamingCallbackHttpResponse).unwrap();
        assert_eq!(response.body, b"this is a body");
        assert_eq!(response.token, None);

        let bytes: Vec<u8> = Encode!(&StreamingCallbackHttpResponse {
            body: b"this is a body".as_ref().into(),
            token: Option::<pre_update_legacy::Token>::None,
        })
        .unwrap();

        let response = Decode!(&bytes, StreamingCallbackHttpResponse).unwrap();
        assert_eq!(response.body, b"this is a body");
        assert_eq!(response.token, None);
    }
}
