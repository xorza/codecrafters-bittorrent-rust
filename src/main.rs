#![allow(dead_code)]

use serde_json;
use std::env;
use std::error::Error;
use std::fmt::Display;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
enum Value {
    Data(Vec<u8>),
    Integer(i64),
    List(Vec<Value>),
    Dictionary(Vec<(String, Value)>),
}

impl Value {
    fn get_by_name(&self, name: &str) -> Option<&Value> {
        match self {
            Value::Dictionary(dict) => {
                dict.iter()
                    .find(|(key, _)| key == name)
                    .map(|(_, value)| value)
            }
            _ => None,
        }
    }
    fn get_by_index(&self, index: usize) -> Option<&Value> {
        match self {
            Value::List(list) => list.get(index),
            _ => None,
        }
    }
    fn get_string(&self) -> Option<String> {
        match self {
            Value::Data(s) => Some(String::from_utf8_lossy(s).to_string()),
            _ => None,
        }
    }
    fn get_i64(&self) -> Option<i64> {
        match self {
            Value::Integer(i) => Some(*i),
            _ => None,
        }
    }
}

impl Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            Value::Data(_) => self.get_string().unwrap(),
            Value::Integer(i) => i.to_string(),
            Value::List(list) => {
                let list: Vec<String> = list.iter()
                    .map(|v| v.to_string())
                    .collect();
                format!("[{}]", list.join(", "))
            }
            Value::Dictionary(dict) => {
                let dict: Vec<String> = dict.iter()
                    .map(|(k, v)| format!("{}: {}", k, v.to_string()))
                    .collect();
                format!("{{{}}}", dict.join(", "))
            }
        };
        write!(f, "{}", str)
    }
}

enum ReadToken {
    Data(Vec<u8>),
    Integer(i64),
    List,
    Dictionary,
    End,
}

impl TryFrom<ReadToken> for Value {
    type Error = Box<dyn Error>;

    fn try_from(token: ReadToken) -> Result<Self, Box<dyn Error>> {
        match token {
            ReadToken::Data(s) => Ok(Value::Data(s)),
            ReadToken::Integer(i) => Ok(Value::Integer(i)),
            ReadToken::List => Ok(Value::List(Vec::new())),
            ReadToken::Dictionary => Ok(Value::Dictionary(Vec::new())),
            ReadToken::End => Err("Invalid value".into()),
        }
    }
}


fn decode_bencoded_value(mut value_to_decode: &[u8]) -> Result<Value, Box<dyn Error>> {
    let (root_value, left_to_decode) = read_value(&mut value_to_decode)?;
    value_to_decode = left_to_decode;

    let mut stack: Vec<(Option<String>, Value)> = Vec::new();

    match root_value {
        ReadToken::Data(s) => {
            return Ok(Value::Data(s));
        }
        ReadToken::Integer(i) => {
            return Ok(Value::Integer(i));
        }
        ReadToken::List => {
            stack.push((None, Value::List(Vec::new())));
        }
        ReadToken::Dictionary => {
            stack.push((None, Value::Dictionary(Vec::new())));
        }
        _ => return Err("Invalid value".into()),
    }

    loop {
        if value_to_decode.is_empty() {
            return Err("Invalid value".into());
        }

        let token = loop {
            let (token, left_to_decode) = read_value(value_to_decode)?;
            value_to_decode = left_to_decode;

            if matches!(token, ReadToken::End) {
                let (key, value) = stack.pop()
                    .ok_or("Invalid value")?;
                match stack.last_mut() {
                    Some((None, Value::List(list))) => {
                        list.push(value);
                    }
                    Some((_, Value::Dictionary(dict))) => {
                        dict.push((
                            key.expect("Invalid key"),
                            value
                        ));
                    }
                    None => return Ok(value),
                    _ => return Err("Invalid value".into()),
                }
            } else {
                break token;
            }
        };

        let (_, prev_value) = stack.last_mut().expect("Invalid state");
        let (key, value_token) = match prev_value {
            Value::List(_) => (None, token),
            Value::Dictionary(_) => {
                let (value_token, left_to_decode) = read_value(value_to_decode)?;
                value_to_decode = left_to_decode;

                match token {
                    ReadToken::Data(s) => {
                        let string_key = String::from_utf8(s)?;
                        (Some(string_key), value_token)
                    }
                    _ => return Err("Invalid key".into()),
                }
            }
            _ => panic!("Invalid state"),
        };

        let value = Value::try_from(value_token)?;

        match value {
            Value::List(_) |
            Value::Dictionary(_) => {
                stack.push((key, value));
            }
            Value::Data(_) |
            Value::Integer(_) => {
                match prev_value {
                    Value::List(list) => {
                        list.push(value);
                    }
                    Value::Dictionary(dict) => {
                        dict.push((key.expect("Invalid state, key expected"), value));
                    }
                    _ => panic!("Invalid state")
                }
            }
        }
    }
}

fn split_once(slice: &[u8], byte: u8) -> Option<(&[u8], &[u8])> {
    for (index, &item) in slice.iter().enumerate() {
        if item == byte {
            return Some((&slice[..index], &slice[index + 1..]));
        }
    }
    None
}

fn read_value(mut value_to_decode: &[u8]) -> Result<(ReadToken, &[u8]), Box<dyn Error>> {
    let first_char = value_to_decode[0] as char;

    let new_value = match first_char {
        '0'..='9' => {
            let (len, rest) = split_once(value_to_decode, b':')
                .ok_or("Invalid string format")?;
            let len_str = std::str::from_utf8(len)?;
            let len = len_str.parse::<usize>()?;
            if rest.len() < len {
                return Err("Invalid string format".into());
            }
            let (value, rest) = rest.split_at(len);
            value_to_decode = rest;

            ReadToken::Data(value.into())
        }
        'i' => {
            let (value, rest) = split_once(&value_to_decode[1..], b'e')
                .ok_or("Invalid integer format")?;
            let str_value = std::str::from_utf8(value)?;
            let value = str_value.parse::<i64>()?;
            value_to_decode = rest;

            ReadToken::Integer(value)
        }
        'l' => {
            value_to_decode = &value_to_decode[1..];

            ReadToken::List
        }
        'd' => {
            value_to_decode = &value_to_decode[1..];

            ReadToken::Dictionary
        }
        'e' => {
            value_to_decode = &value_to_decode[1..];

            ReadToken::End
        }

        _ => {
            return Err("Invalid value".into());
        }
    };

    Ok((new_value, value_to_decode))
}

fn value_to_json(value: &Value) -> serde_json::Value {
    match value {
        Value::Data(s) => String::from_utf8_lossy(s).into(),
        Value::Integer(i) => i.clone().into(),
        Value::List(list) => {
            let list: Vec<serde_json::Value> = list.iter()
                .map(|v| value_to_json(v))
                .collect();

            list.into()
        }
        Value::Dictionary(dict) => {
            let dict: serde_json::Map<String, serde_json::Value> = dict.iter()
                .map(|(k, v)| (k.clone(), value_to_json(v)))
                .collect();

            dict.into()
        }
    }
}

fn read_torrent_info(torrent_file: &str) -> Result<Value, Box<dyn Error>> {
    let bytes = std::fs::read(torrent_file)?;
    let value = decode_bencoded_value(&bytes)?;

    Ok(value)
}

// Usage: your_bittorrent.sh decode "<encoded_value>"
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    let command = args[1].as_str();
    match command {
        "decode" => {
            let encoded_value = args[2].as_bytes();
            let decoded_value = decode_bencoded_value(encoded_value)?;
            println!("{}", value_to_json(&decoded_value).to_string());
        }
        "info" => {
            let torrent_file = &args[2].as_str();
            let decoded_value = read_torrent_info(torrent_file)?;

            // Tracker URL: http://bittorrent-test-tracker.codecrafters.io/announce
            // Length: 92063
            let tracker_url = decoded_value
                .get_by_name("announce").unwrap()
                .to_string();
            println!("Tracker URL: {}", tracker_url);
            
            let file_length = decoded_value
                .get_by_name("info").unwrap()
                .get_by_name("length").unwrap()
                .get_i64().unwrap();
            
            println!("Length: {}", file_length);
        }
        _ => {
            println!("unknown command: {}", command);
        }
    }

    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_torrent_file() {
        let torrent_file = "sample2.torrent";
        let decoded_value = read_torrent_info(torrent_file).unwrap();

        let json_decoded_value = value_to_json(&decoded_value);

        assert_eq!(json_decoded_value, serde_json::json!({
            "announce": "http://bittorrent-test-tracker.codecrafters.io/announce",
            "created by": "mktorrent 1.1",
            "info": {
                "length": 92063,
                "name": "sample.txt",
                "piece length": 32768,
                "pieces": "p"
            }
        }));

        let tracker_url = decoded_value.get_by_name("announce").unwrap().to_string();
        assert_eq!(tracker_url, "http://bittorrent-test-tracker.codecrafters.io/announce");

        let file_length = decoded_value
            .get_by_name("info").unwrap()
            .get_by_name("length").unwrap()
            .get_i64().unwrap();
        assert_eq!(file_length, 92063);
    }

    #[test]
    fn test_decode_bencoded_value_string() {
        let encoded_value = "4:spam";
        let decoded_value = decode_bencoded_value(encoded_value.as_bytes()).unwrap();
        let json_decoded_value = value_to_json(&decoded_value);
        assert_eq!(json_decoded_value, serde_json::json!("spam"));
    }

    #[test]
    fn test_decode_bencoded_value_integer() {
        let encoded_value = "i52e";
        let decoded_value = decode_bencoded_value(encoded_value.as_bytes()).unwrap();
        let json_decoded_value = value_to_json(&decoded_value);
        assert_eq!(json_decoded_value, serde_json::json!(52));
    }

    #[test]
    fn test_decode_bencoded_list() {
        let encoded_value = "l5:helloi52ee";
        let decoded_value = decode_bencoded_value(encoded_value.as_bytes()).unwrap();
        let json_decoded_value = value_to_json(&decoded_value);
        assert_eq!(json_decoded_value, serde_json::json!(["hello", 52]));
    }

    #[test]
    fn test_decode_bencoded_list_in_dict() {
        let encoded_value = "d4:spaml1:a1:bee";
        let decoded_value = decode_bencoded_value(encoded_value.as_bytes()).unwrap();
        let json_decoded_value = value_to_json(&decoded_value);
        assert_eq!(json_decoded_value, serde_json::json!({
            "spam": ["a", "b"]
        }));
    }
}