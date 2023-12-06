//! Types for interacting with the status endpoint of a replica. See [`Status`] for details.

use candid::{CandidType, Deserialize};
use serde::Serialize;
use std::{collections::BTreeMap, fmt::Debug};

/// Value returned by the status endpoint of a replica. This is a loose mapping to CBOR values.
/// Because the agent should not return [`serde_cbor::Value`] directly across API boundaries,
/// we reimplement it as [`Value`] here.
#[derive(
    Debug, Ord, PartialOrd, Eq, PartialEq, Clone, Hash, CandidType, Serialize, Deserialize,
)]
pub enum Value {
    /// See [`Null`](serde_cbor::Value::Null).
    Null,
    /// See [`String`](serde_cbor::Value::Text).
    String(String),
    /// See [`Integer`](serde_cbor::Value::Integer).
    Integer(i64),
    /// See [`Bool`](serde_cbor::Value::Bool).
    Bool(bool),
    /// See [`Bytes`](serde_cbor::Value::Bytes).
    Bytes(Vec<u8>),
    /// See [`Vec`](serde_cbor::Value::Array).
    Vec(Vec<Value>),
    /// See [`Map`](serde_cbor::Value::Map).
    Map(BTreeMap<String, Box<Value>>),
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Null => f.write_str("null"),
            Value::String(s) => f.write_fmt(format_args!(r#""{}""#, s.escape_debug())),
            Value::Integer(i) => f.write_str(&i.to_string()),
            Value::Bool(true) => f.write_str("true"),
            Value::Bool(false) => f.write_str("false"),
            Value::Bytes(b) => f.debug_list().entries(b).finish(),
            Value::Vec(v) => f.debug_list().entries(v).finish(),
            Value::Map(m) => f.debug_map().entries(m).finish(),
        }
    }
}

/// The structure returned by [`super::Agent::status`], containing the information returned
/// by the status endpoint of a replica.
#[derive(Debug, Ord, PartialOrd, PartialEq, Eq, CandidType, Deserialize, Serialize)]
pub struct Status {
    /// Optional. The precise git revision of the Internet Computer Protocol implementation.
    pub impl_version: Option<String>,

    /// Optional.  The health status of the replica.  One hopes it's "healthy".
    pub replica_health_status: Option<String>,

    /// Optional.  The root (public) key used to verify certificates.
    pub root_key: Option<Vec<u8>>,

    /// Contains any additional values that the replica gave as status.
    pub values: BTreeMap<String, Box<Value>>,
}

#[test]
fn can_serilaize_status_as_json() {
    let status = Status {
        impl_version: None,
        replica_health_status: None,
        root_key: None,
        values: BTreeMap::new(),
    };
    let expected_json =
        r#"{"impl_version":null,"replica_health_status":null,"root_key":null,"values":{}}"#;
    let actual_json = serde_json::to_string(&status).expect("Failed to serialize as JSON");
    assert_eq!(expected_json, actual_json);
}
#[test]
fn can_serialize_status_as_idl() {
    use candid::{Decode, Encode, IDLValue};
    let status = Status {
        impl_version: Some("Foo".to_string()),
        replica_health_status: None,
        root_key: None,
        values: BTreeMap::new(),
    };
    let expected_idl = r#"record {\n  values = vec {};\n  root_key = null;\n  replica_health_status = null;\n  impl_version = opt "Foo";\n}"#;
    let actual_idl = {
        let blob = Encode!(&status).expect("Failed to serialize");
        let v = Decode!(&blob, IDLValue).expect("Failed to seserialize");
        format!("{}", v)
    };
    assert_eq!(expected_idl, actual_idl);
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("{\n")?;
        for (key, value) in &self.values {
            f.write_fmt(format_args!(r#"  "{}": "#, key.escape_debug()))?;
            std::fmt::Display::fmt(&value, f)?;
        }
        f.write_str("\n}")
    }
}

fn cbor_value_to_value(value: &serde_cbor::Value) -> Result<Value, ()> {
    match value {
        serde_cbor::Value::Null => Ok(Value::Null),
        serde_cbor::Value::Bool(b) => Ok(Value::Bool(*b)),
        serde_cbor::Value::Integer(i) => Ok(Value::Integer(*i as i64)),
        serde_cbor::Value::Bytes(b) => Ok(Value::Bytes(b.to_owned())),
        serde_cbor::Value::Text(s) => Ok(Value::String(s.to_owned())),
        serde_cbor::Value::Array(a) => Ok(Value::Vec(
            a.iter()
                .map(cbor_value_to_value)
                .collect::<Result<Vec<Value>, ()>>()
                .map_err(|_| ())?,
        )),
        serde_cbor::Value::Map(m) => {
            let mut map = BTreeMap::new();
            for (key, value) in m.iter() {
                let k = match key {
                    serde_cbor::Value::Text(t) => t.to_owned(),
                    serde_cbor::Value::Integer(i) => i.to_string(),
                    _ => return Err(()),
                };
                let v = Box::new(cbor_value_to_value(value)?);

                map.insert(k, v);
            }
            Ok(Value::Map(map))
        }
        serde_cbor::Value::Tag(_, v) => cbor_value_to_value(v.as_ref()),
        _ => Err(()),
    }
}

impl std::convert::TryFrom<&serde_cbor::Value> for Status {
    type Error = ();

    fn try_from(value: &serde_cbor::Value) -> Result<Self, ()> {
        let v = cbor_value_to_value(value)?;

        match v {
            Value::Map(map) => {
                let impl_version: Option<String> = map.get("impl_version").and_then(|v| {
                    if let Value::String(s) = v.as_ref() {
                        Some(s.to_owned())
                    } else {
                        None
                    }
                });
                let replica_health_status: Option<String> =
                    map.get("replica_health_status").and_then(|v| {
                        if let Value::String(s) = v.as_ref() {
                            Some(s.to_owned())
                        } else {
                            None
                        }
                    });
                let root_key: Option<Vec<u8>> = map.get("root_key").and_then(|v| {
                    if let Value::Bytes(bytes) = v.as_ref() {
                        Some(bytes.to_owned())
                    } else {
                        None
                    }
                });

                Ok(Status {
                    impl_version,
                    replica_health_status,
                    root_key,
                    values: map,
                })
            }
            _ => Err(()),
        }
    }
}
