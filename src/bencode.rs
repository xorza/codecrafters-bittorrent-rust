use std::fmt;

use serde::ser::{SerializeMap, SerializeSeq};
use serde::{de, ser};
use serde_bytes::ByteBuf;

#[derive(PartialEq, Eq, Clone, Debug)]
pub enum Value {
    String(String),
    Int(i64),
    List(Vec<Value>),
    Dict(Vec<(String, Value)>),
}

impl ser::Serialize for Value {
    #[inline]
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        match *self {
            Value::String(ref v) => s.serialize_str(v.as_str()),
            Value::Int(v) => s.serialize_i64(v),
            Value::List(ref v) => {
                let mut seq = s.serialize_seq(Some(v.len()))?;
                for e in v {
                    seq.serialize_element(e)?;
                }
                seq.end()
            }
            Value::Dict(ref vs) => {
                let mut map = s.serialize_map(Some(vs.len()))?;
                for (k, v) in vs {
                    map.serialize_entry(k, v)?;
                }
                map.end()
            }
        }
    }
}

struct ValueVisitor;

impl<'de> de::Visitor<'de> for ValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("any valid BEncode value")
    }

    #[inline]
    fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Int(value))
    }

    #[inline]
    fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Int(value as i64))
    }

    #[inline]
    fn visit_str<E>(self, value: &str) -> Result<Value, E>
    where
        E: de::Error,
    {
        Ok(Value::String(value.into()))
    }

    #[inline]
    fn visit_string<E>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    #[inline]
    fn visit_bytes<E>(self, value: &[u8]) -> Result<Value, E> {
        Ok(Value::String(String::from_utf8_lossy(value).to_string()))
    }

    #[inline]
    fn visit_seq<V>(self, mut access: V) -> Result<Value, V::Error>
    where
        V: de::SeqAccess<'de>,
    {
        let mut seq = Vec::new();
        while let Some(e) = access.next_element()? {
            seq.push(e);
        }
        Ok(Value::List(seq))
    }

    #[inline]
    fn visit_map<V>(self, mut access: V) -> Result<Value, V::Error>
    where
        V: de::MapAccess<'de>,
    {
        let mut map: Vec<(String, Value)> = Vec::new();
        while let Some((k, v)) = access.next_entry::<ByteBuf, _>()? {
            // map.insert(k.into_vec(), v);
            let key = String::from_utf8_lossy(&k).to_string();
            map.push((key, v))
        }
        Ok(Value::Dict(map))
    }
}

impl<'de> de::Deserialize<'de> for Value {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_any(ValueVisitor)
    }
}
