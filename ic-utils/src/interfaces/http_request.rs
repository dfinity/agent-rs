//! The canister interface for canisters that implement HTTP requests.

use crate::{
    call::{AsyncCall, SyncCall},
    canister::CanisterBuilder,
    Canister,
};
use candid::{
    parser::value::IDLValue,
    types::{Serializer, Type},
    CandidType, Deserialize, Func, Nat,
};
use ic_agent::{export::Principal, Agent};
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

/// A HTTP response.
#[derive(Debug, Clone, CandidType, Deserialize)]
pub struct HttpResponse<Token = self::Token> {
    /// The HTTP status code.
    pub status_code: u16,
    /// The response header map.
    pub headers: Vec<HeaderField>,
    /// The response body.
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    /// The strategy for streaming the rest of the data, if the full response is to be streamed.
    pub streaming_strategy: Option<StreamingStrategy<Token>>,
    /// Whether the query call should be upgraded to an update call.
    pub upgrade: Option<bool>,
}

/// Possible strategies for a streaming response.
#[derive(Debug, Clone, CandidType, Deserialize)]
pub enum StreamingStrategy<Token = self::Token> {
    /// A callback-based streaming strategy, where a callback function is provided for continuing the stream.
    Callback(CallbackStrategy<Token>),
}

/// A callback-token pair for a callback streaming strategy.
#[derive(Debug, Clone, CandidType, Deserialize)]
pub struct CallbackStrategy<Token = self::Token> {
    /// The callback function to be called to continue the stream.
    pub callback: Func,
    /// The token to pass to the function.
    pub token: Token,
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
#[derive(Debug, Clone)]
//#[serde(transparent)]
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
        use candid::{
            parser::value::{IDLField, VariantValue},
            types::{number::Int, Label},
        };
        use serde::de::{self, Visitor};
        use std::fmt;
        type DResult<E> = std::result::Result<IDLValue, E>;

        macro_rules! visit_prim {
            ($name:ident, $ty:ty) => {
                paste::item! {
                    fn [<visit_ $ty>]<E>(self, value: $ty) -> DResult<E> {
                        Ok(IDLValue::$name(value))
                    }
                }
            };
        }
        struct IDLValueVisitor;

        impl<'de> Visitor<'de> for IDLValueVisitor {
            type Value = IDLValue;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("any valid Candid value")
            }
            visit_prim!(Bool, bool);
            visit_prim!(Nat8, u8);
            visit_prim!(Nat16, u16);
            visit_prim!(Nat32, u32);
            visit_prim!(Nat64, u64);
            visit_prim!(Int8, i8);
            visit_prim!(Int16, i16);
            visit_prim!(Int32, i32);
            visit_prim!(Int64, i64);
            visit_prim!(Float32, f32);
            visit_prim!(Float64, f64);
            // Deserialize Candid specific types: Bignumber, principal, reversed, service, function
            fn visit_byte_buf<E: de::Error>(self, value: Vec<u8>) -> DResult<E> {
                use std::convert::TryFrom;
                let (tag, mut bytes) = value.split_at(1);
                match tag[0] {
                    0u8 => {
                        let v = Int(num_bigint::BigInt::from_signed_bytes_le(bytes));
                        Ok(IDLValue::Int(v))
                    }
                    1u8 => {
                        let v = Nat(num_bigint::BigUint::from_bytes_le(bytes));
                        Ok(IDLValue::Nat(v))
                    }
                    2u8 => {
                        let v = Principal::try_from(bytes).map_err(E::custom)?;
                        Ok(IDLValue::Principal(v))
                    }
                    4u8 => {
                        let v = Principal::try_from(bytes).map_err(E::custom)?;
                        Ok(IDLValue::Service(v))
                    }
                    5u8 => {
                        use std::io::Read;
                        let len = leb128::read::unsigned(&mut bytes).map_err(E::custom)? as usize;
                        let mut buf = Vec::new();
                        buf.resize(len, 0);
                        bytes.read_exact(&mut buf).map_err(E::custom)?;
                        let meth = String::from_utf8(buf).map_err(E::custom)?;
                        let id = Principal::try_from(bytes).map_err(E::custom)?;
                        Ok(IDLValue::Func(id, meth))
                    }
                    3u8 => Ok(IDLValue::Reserved),
                    _ => Err(de::Error::custom("unknown tag in visit_byte_buf")),
                }
            }
            fn visit_string<E>(self, value: String) -> DResult<E> {
                Ok(IDLValue::Text(value))
            }
            fn visit_str<E>(self, value: &str) -> DResult<E>
            where
                E: serde::de::Error,
            {
                self.visit_string(String::from(value))
            }
            fn visit_none<E>(self) -> DResult<E> {
                Ok(IDLValue::None)
            }
            fn visit_some<D>(self, deserializer: D) -> DResult<D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let v = Deserialize::deserialize(deserializer)?;
                Ok(IDLValue::Opt(Box::new(v)))
            }
            fn visit_unit<E>(self) -> DResult<E> {
                Ok(IDLValue::Null)
            }
            fn visit_seq<V>(self, mut visitor: V) -> DResult<V::Error>
            where
                V: de::SeqAccess<'de>,
            {
                let mut vec = Vec::new();
                while let Some(elem) = visitor.next_element()? {
                    vec.push(elem);
                }
                Ok(IDLValue::Vec(vec))
            }
            fn visit_map<V>(self, mut visitor: V) -> DResult<V::Error>
            where
                V: de::MapAccess<'de>,
            {
                let mut vec = Vec::new();
                while let Some((key, value)) = visitor.next_entry()? {
                    let id = match key {
                        IDLValue::Nat32(hash) => Label::Id(hash),
                        IDLValue::Text(name) if name == "_" => continue,
                        IDLValue::Text(name) => Label::Named(name),
                        _ => unreachable!(),
                    };
                    let f = IDLField { id, val: value };
                    vec.push(f);
                }
                Ok(IDLValue::Record(vec))
            }
            fn visit_enum<V>(self, data: V) -> DResult<V::Error>
            where
                V: de::EnumAccess<'de>,
            {
                use serde::de::VariantAccess;
                let (variant, visitor) = data.variant::<IDLValue>()?;
                if let IDLValue::Text(v) = variant {
                    let v: Vec<_> = v.split(',').collect();
                    let (id, style) = match v.as_slice() {
                        [name, "name", style] => (Label::Named(name.to_string()), style),
                        [hash, "id", style] => (Label::Id(hash.parse::<u32>().unwrap()), style),
                        _ => unreachable!(),
                    };
                    let val = match *style {
                        "unit" => {
                            visitor.unit_variant()?;
                            IDLValue::Null
                        }
                        "struct" => visitor.struct_variant(&[], self)?,
                        "newtype" => visitor.newtype_variant()?,
                        _ => unreachable!(),
                    };
                    let f = IDLField { id, val };
                    // Deserialized variant always has 0 index to ensure untyped
                    // serialization is correct.
                    Ok(IDLValue::Variant(VariantValue(Box::new(f), 0)))
                } else {
                    unreachable!()
                }
            }
        }

        // Ya know it says `ignored`, but what if we just didn't ignore it.
        deserializer
            .deserialize_ignored_any(IDLValueVisitor)
            .map(Token)
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
        self.query_(&method.into()).with_value_arg(token.0).build()
    }
}

#[cfg(test)]
mod test {
    use super::{CallbackStrategy, HttpResponse, StreamingStrategy, Token};
    use candid::{
        parser::value::{IDLField, IDLValue},
        Decode, Encode,
    };

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
    fn deserialize_token() {
        use candid::{types::Label, Func, Principal};

        let bytes: Vec<u8> = Encode!(&HttpResponse {
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

        let response = Decode!(&bytes, HttpResponse).unwrap();
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
}
