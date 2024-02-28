use std::fmt::Formatter;

use super::ChunkInfo;
use candid::types::{CandidType, Type, TypeInner};
use serde::de::{Deserialize, Deserializer, Error, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_bytes::ByteArray;
// ChunkInfo can be deserialized from both `blob` and `record { hash: blob }`.
// This impl can be removed when both mainnet and dfx no longer return `blob`.
impl CandidType for ChunkInfo {
    fn _ty() -> Type {
        Type(<_>::from(TypeInner::Unknown))
    }
    fn idl_serialize<S>(&self, _serializer: S) -> Result<(), S::Error>
    where
        S: candid::types::Serializer,
    {
        unimplemented!()
    }
}
impl<'de> Deserialize<'de> for ChunkInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(ChunkInfoVisitor)
    }
}
struct ChunkInfoVisitor;
impl<'de> Visitor<'de> for ChunkInfoVisitor {
    type Value = ChunkInfo;
    fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("blob or record {hash: blob}")
    }
    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: Error,
    {
        // deserialize_any combined with visit_bytes produces an extra 6 byte for difficult reasons
        let v = if v.len() == 33 && v[0] == 6 {
            &v[1..]
        } else {
            v
        };
        Ok(ChunkInfo {
            hash: v
                .try_into()
                .map_err(|_| E::invalid_length(v.len(), &"32 bytes"))?,
        })
    }
    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut hash = [0; 32];
        for (i, n) in hash.iter_mut().enumerate() {
            *n = seq
                .next_element()?
                .ok_or_else(|| A::Error::invalid_length(i, &"32 bytes"))?;
        }
        if seq.next_element::<IgnoredAny>()?.is_some() {
            Err(A::Error::invalid_length(
                seq.size_hint().unwrap_or(33),
                &"32 bytes",
            ))
        } else {
            Ok(ChunkInfo { hash })
        }
    }
    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(k) = map.next_key::<Field>()? {
            eprintln!("here");
            if matches!(k, Field::Hash) {
                return Ok(ChunkInfo {
                    hash: map.next_value::<ByteArray<32>>()?.into_array(),
                });
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Err(A::Error::missing_field("hash"))
    }
}
// Needed because candid cannot infer field names without specifying them in _ty()
enum Field {
    Hash,
    Other,
}
impl<'de> Deserialize<'de> for Field {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_identifier(FieldVisitor)
    }
}
struct FieldVisitor;
impl<'de> Visitor<'de> for FieldVisitor {
    type Value = Field;
    fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a field name")
    }
    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        if v == "hash" {
            Ok(Field::Hash)
        } else {
            Ok(Field::Other)
        }
    }
    fn visit_u32<E>(self, v: u32) -> Result<Self::Value, E>
    where
        E: Error,
    {
        if v == 1158164430 {
            Ok(Field::Hash)
        } else {
            Ok(Field::Other)
        }
    }
}
