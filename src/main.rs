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

// enum StackFrame {
//     Root(Value),
//     List(Vec<Value>),
//     Dictionary(Vec<(String, Value)>),
// }

#[allow(dead_code)]
fn decode_bencoded_value(mut value_to_decode: &str) -> Result<serde_json::Value, Box<dyn Error>> {
    let (root_value, left_to_decode) = read_value(&mut value_to_decode)?;
    value_to_decode = left_to_decode;

    let mut value_stack: Vec<Value> = Vec::new();
    let root_value = root_value.ok_or("Invalid value")?;

    match root_value {
        Value::String(s) => {
            return Ok(s.into());
        }
        Value::Integer(i) => {
            return Ok(i.into());
        }
        Value::List(_) |
        Value::Dictionary(_) => {
            value_stack.push(root_value);
        }
    }

    let mut key_stack: Vec<String> = Vec::new();
    let mut key: Option<String> = None;

    let result: Option<Value> =
        loop {
            if value_to_decode.is_empty() {
                break None;
            }

            let (new_value, left_to_decode) = read_value(value_to_decode)?;
            value_to_decode = left_to_decode;

            if let Some(new_value) = new_value {
                match new_value {
                    Value::List(_) |
                    Value::Dictionary(_) => {
                        if let Some(key) = key.take() {
                            key_stack.push(key);
                        }
                        value_stack.push(new_value);
                    }
                    Value::String(s) => {
                        match value_stack.last_mut() {
                            Some(Value::List(list)) => {
                                list.push(Value::String(s));
                            }
                            Some(Value::Dictionary(dict)) => {
                                if let Some(key) = key.take() {
                                    dict.push((key, Value::String(s)));
                                } else {
                                    key = Some(s);
                                }
                            }
                            _ => return Err("Invalid value".into()),
                        }
                    }
                    Value::Integer(i) => {
                        match value_stack.last_mut() {
                            Some(Value::List(list)) => {
                                list.push(Value::Integer(i));
                            }
                            Some(Value::Dictionary(dict)) => {
                                if let Some(key) = key.take() {
                                    dict.push((key, Value::Integer(i)));
                                } else {
                                    return Err("Invalid value".into());
                                }
                            }
                            _ => return Err("Invalid value".into()),
                        }
                    }
                }
            } else {
                let value = value_stack.pop()
                    .ok_or("Invalid value")?;
                match value_stack.last_mut() {
                    Some(Value::List(list)) => {
                        list.push(value);
                    }
                    Some(Value::Dictionary(dict)) => {
                        let key = key_stack.pop()
                            .ok_or("Invalid value")?;
                        dict.push((key, value));
                    }
                    None => break Some(value),
                    _ => return Err("Invalid value".into()),
                }
            }
        };

    Ok(value_to_json(&result.ok_or("Invalid value")?))
}

fn read_value(mut value_to_decode: &str) -> Result<(Option<Value>, &str), Box<dyn Error>> {
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

            Some(Value::String(value.to_string()))
        }
        'i' => {
            let (value, rest) = value_to_decode[1..].split_once('e')
                .ok_or("Invalid integer format")?;
            let value = value.parse::<i64>()?;
            value_to_decode = rest;

            Some(Value::Integer(value))
        }
        'l' => {
            value_to_decode = &value_to_decode[1..];
            Some(Value::List(Vec::new()))
        }
        'd' => {
            value_to_decode = &value_to_decode[1..];
            Some(Value::Dictionary(Vec::new()))
        }
        'e' => {
            value_to_decode = &value_to_decode[1..];
            None
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
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let command = &args[1];

    if command == "decode" {
        // Uncomment this block to pass the first stage
        let encoded_value = &args[2];
        let decoded_value = decode_bencoded_value(encoded_value)?;
        println!("{}", decoded_value.to_string());
    } else {
        println!("unknown command: {}", args[1])
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
        assert_eq!(decoded_value, serde_json::json!("spam"));
    }

    #[test]
    fn test_decode_bencoded_value_integer() {
        let encoded_value = "i52e";
        let decoded_value = decode_bencoded_value(encoded_value).unwrap();
        assert_eq!(decoded_value, serde_json::json!(52));
    }

    #[test]
    fn test_decode_bencoded_list() {
        let encoded_value = "l5:helloi52ee";
        let decoded_value = decode_bencoded_value(encoded_value).unwrap();
        assert_eq!(decoded_value, serde_json::json!(["hello", 52]));
    }

    #[test]
    fn test_decode_bencoded_value() {
        let encoded_value = "d4:spaml1:a1:bee";
        let decoded_value = decode_bencoded_value(encoded_value).unwrap();
        assert_eq!(decoded_value, serde_json::json!({
            "spam": ["a", "b"]
        }));
    }
}