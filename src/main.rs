use serde_json;
use std::env;

// Available if you need it!
// use serde_bencode

#[allow(dead_code)]
fn decode_bencoded_value(encoded_value: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let mut value_to_decode = encoded_value;
    // let json: serde_json:: = serde_json::Value::Null;

    while value_to_decode.len() >= 2 {
        let first_char = value_to_decode.chars().nth(0).unwrap();


        match first_char {
            'i' => {
                let (value, rest) = value_to_decode[1..].split_once('e')
                    .ok_or("Invalid integer format")?;
                let value = value.parse::<i64>()?;
                value_to_decode = rest;

                return Ok(serde_json::Value::Number(value.into()));
            }
            'l' => {}
            '0'..='9' => {
                let (len, rest) = value_to_decode.split_once(':')
                    .ok_or("Invalid string format")?;
                let len = len.parse::<usize>()?;
                if rest.len() < len {
                    return Err("Invalid string format".into());
                }
                let (value, rest) = rest.split_at(len);
                value_to_decode = rest;

                return Ok(value.into());
            }

            _ => {}
        }
    }

    Ok(serde_json::Value::Null)
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
