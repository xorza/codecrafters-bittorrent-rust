use serde_json;
use std::env;
use std::error::Error;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
enum Value {
    String(String),
    Integer(i64),
    List(Vec<Value>),
    Dictionary(Vec<(String, Value)>),
}

enum ReadToken {
    String(String),
    Integer(i64),
    List,
    Dictionary,
    End,
}

impl TryFrom<ReadToken> for Value {
    type Error = Box<dyn Error>;

    fn try_from(token: ReadToken) -> Result<Self, Box<dyn Error>> {
        match token {
            ReadToken::String(s) => Ok(Value::String(s)),
            ReadToken::Integer(i) => Ok(Value::Integer(i)),
            ReadToken::List => Ok(Value::List(Vec::new())),
            ReadToken::Dictionary => Ok(Value::Dictionary(Vec::new())),
            ReadToken::End => Err("Invalid value".into()),
        }
    }
}


#[allow(dead_code)]
fn decode_bencoded_value(mut value_to_decode: &str) -> Result<Value, Box<dyn Error>> {
    let (root_value, left_to_decode) = read_value(&mut value_to_decode)?;
    value_to_decode = left_to_decode;

    let mut stack: Vec<(Option<String>, Value)> = Vec::new();

    match root_value {
        ReadToken::String(s) => {
            return Ok(Value::String(s));
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
                    ReadToken::String(s) => (Some(s), value_token),
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
            Value::String(_) |
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

fn read_value(mut value_to_decode: &str) -> Result<(ReadToken, &str), Box<dyn Error>> {
    let first_char = value_to_decode.chars().nth(0).unwrap();

    let new_value = match first_char {
        '0'..='9' => {
            let (len, rest) = value_to_decode.split_once(':')
                .ok_or("Invalid string format")?;
            let len = len.parse::<usize>()?;
            if rest.len() < len {
                return Err("Invalid string format".into());
            }
            let (value, rest) = rest.split_at(len);
            value_to_decode = rest;

            ReadToken::String(value.to_string())
        }
        'i' => {
            let (value, rest) = value_to_decode[1..].split_once('e')
                .ok_or("Invalid integer format")?;
            let value = value.parse::<i64>()?;
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
        Value::String(s) => s.clone().into(),
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

// Usage: your_bittorrent.sh decode "<encoded_value>"
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    let command = args[1].as_str();
    match command {
        "decode" => {
            let encoded_value = &args[2];
            let decoded_value = decode_bencoded_value(encoded_value)?;
            println!("{}", value_to_json(&decoded_value).to_string());
        }
        "info" => {
            // Tracker URL: http://bittorrent-test-tracker.codecrafters.io/announce
            // Length: 92063
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
    fn test_decode_bencoded_value_string() {
        let encoded_value = "4:spam";
        let decoded_value = decode_bencoded_value(encoded_value).unwrap();
        let json_decoded_value = value_to_json(&decoded_value);
        assert_eq!(json_decoded_value, serde_json::json!("spam"));
    }

    #[test]
    fn test_decode_bencoded_value_integer() {
        let encoded_value = "i52e";
        let decoded_value = decode_bencoded_value(encoded_value).unwrap();
        let json_decoded_value = value_to_json(&decoded_value);
        assert_eq!(json_decoded_value, serde_json::json!(52));
    }

    #[test]
    fn test_decode_bencoded_list() {
        let encoded_value = "l5:helloi52ee";
        let decoded_value = decode_bencoded_value(encoded_value).unwrap();
        let json_decoded_value = value_to_json(&decoded_value);
        assert_eq!(json_decoded_value, serde_json::json!(["hello", 52]));
    }

    #[test]
    fn test_decode_bencoded_value() {
        let encoded_value = "d4:spaml1:a1:bee";
        let decoded_value = decode_bencoded_value(encoded_value).unwrap();
        let json_decoded_value = value_to_json(&decoded_value);
        assert_eq!(json_decoded_value, serde_json::json!({
            "spam": ["a", "b"]
        }));
    }
}