use std::collections::BTreeMap;
use std::fmt::Debug;

/// Value returned by the status endpoint of a replica. This is a loose mapping to CBOR values.
/// Because the agent should not return [`serde_cbor::Value`] directly across API boundaries,
/// we reimplement it as [`Value`] here.
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone, Hash)]
pub enum Value {
    Null,
    String(String),
    Integer(i64),
    Bool(bool),
    Bytes(Vec<u8>),
    Vec(Vec<Value>),
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

/// The structure returned by [`ic_agent::Agent::status`], containing the information returned
/// by the status endpoint of a replica.
#[derive(Debug, Ord, PartialOrd, PartialEq, Eq)]
pub struct Status {
    /// Identifies the interface version supported, i.e. the version of the present document that
    /// the internet computer aims to support, e.g. 0.8.1. The implementation may also return
    /// unversioned to indicate that it does not comply to a particular version, e.g. in between
    /// releases.
    pub ic_api_version: String,

    /// Optional. Identifies the implementation of the Internet Computer, by convention with the
    /// canonical location of the source code.
    pub impl_source: Option<String>,

    /// Optional. If the user is talking to a released version of an Internet Computer
    /// implementation, this is the version number. For non-released versions, output of
    /// `git describe` like 0.1.13-13-g2414721 would also be very suitable.
    pub impl_version: Option<String>,

    /// Optional. The precise git revision of the Internet Computer implementation.
    pub impl_revision: Option<String>,

    /// Optional.  The root key
    pub root_key: Option<Vec<u8>>,

    /// Contains any additional values that the replica gave as status.
    pub values: BTreeMap<String, Box<Value>>,
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
                    serde_cbor::Value::Text(t) => (t.to_owned()),
                    serde_cbor::Value::Integer(i) => (i.to_string()),
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
        let v = cbor_value_to_value(&value)?;

        match v {
            Value::Map(map) => {
                // This field is not optional.
                let ic_api_version = map.get("ic_api_version").ok_or(()).and_then(|v| {
                    if let Value::String(s) = v.as_ref() {
                        Ok(s.to_owned())
                    } else {
                        Err(())
                    }
                })?;
                let impl_source = map.get("impl_source").and_then(|v| {
                    if let Value::String(s) = v.as_ref() {
                        Some(s.to_owned())
                    } else {
                        None
                    }
                });
                let impl_version: Option<String> = map.get("impl_version").and_then(|v| {
                    if let Value::String(s) = v.as_ref() {
                        Some(s.to_owned())
                    } else {
                        None
                    }
                });
                let impl_revision: Option<String> = map.get("impl_revision").and_then(|v| {
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
                    ic_api_version,
                    impl_source,
                    impl_version,
                    impl_revision,
                    root_key,
                    values: map,
                })
            }
            _ => Err(()),
        }
    }
}
