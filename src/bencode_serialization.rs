use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct Value(serde_bencode::value::Value);

impl Serialize for Value {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match &self.0 {
            serde_bencode::value::Value::Bytes(s) => {
                let s = String::from_utf8_lossy(s);
                serializer.serialize_str(&s)
            }
            serde_bencode::value::Value::Int(i) => serializer.serialize_i64(*i),
            serde_bencode::value::Value::List(l) => {
                let mut seq = serializer.serialize_seq(Some(l.len()))?;
                for elem in l {
                    seq.serialize_element(&Value(elem.clone()))?;
                }
                seq.end()
            }
            serde_bencode::value::Value::Dict(d) => {
                let mut map = serializer.serialize_map(Some(d.len()))?;
                for (k, v) in d {
                    let key_str = std::str::from_utf8(k)
                        .map_err(|_| serde::ser::Error::custom("Invalid UTF-8"))?;

                    map.serialize_entry(key_str, &Value(v.clone()))?;
                }
                map.end()
            }
        }
    }
}
