#![allow(dead_code)]

use serde_json;
use std::env;
use std::error::Error;
use std::fmt::Display;
use bytes::{BufMut, BytesMut};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PEER_ID: &str = "01234567890123456789";

#[derive(Debug, PartialEq, Serialize, Deserialize)]
enum BencodeValue {
    Data(Vec<u8>),
    Integer(i64),
    List(Vec<BencodeValue>),
    Dict(Vec<(String, BencodeValue)>),
}

impl BencodeValue {
    fn get_by_name(&self, name: &str) -> Option<&BencodeValue> {
        match self {
            BencodeValue::Dict(dict) => {
                dict.iter()
                    .find(|(key, _)| key == name)
                    .map(|(_, value)| value)
            }
            _ => None,
        }
    }
    fn get_by_index(&self, index: usize) -> Option<&BencodeValue> {
        match self {
            BencodeValue::List(list) => list.get(index),
            _ => None,
        }
    }
    fn get_string(&self) -> Option<String> {
        match self {
            BencodeValue::Data(s) => Some(String::from_utf8_lossy(s).to_string()),
            _ => None,
        }
    }
    fn get_i64(&self) -> Option<i64> {
        match self {
            BencodeValue::Integer(i) => Some(*i),
            _ => None,
        }
    }
    fn get_bytes(&self) -> Option<&[u8]> {
        match self {
            BencodeValue::Data(s) => Some(s),
            _ => None,
        }
    }

    fn from_bytes(mut value_to_decode: &[u8]) -> Result<BencodeValue, Box<dyn Error>> {
        let (root_value, left_to_decode) = read_value(&mut value_to_decode)?;
        value_to_decode = left_to_decode;

        let mut stack: Vec<(Option<String>, BencodeValue)> = Vec::new();

        match root_value {
            ReadToken::Data(s) => {
                return Ok(BencodeValue::Data(s));
            }
            ReadToken::Integer(i) => {
                return Ok(BencodeValue::Integer(i));
            }
            ReadToken::List => {
                stack.push((None, BencodeValue::List(Vec::new())));
            }
            ReadToken::Dictionary => {
                stack.push((None, BencodeValue::Dict(Vec::new())));
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
                        Some((None, BencodeValue::List(list))) => {
                            list.push(value);
                        }
                        Some((_, BencodeValue::Dict(dict))) => {
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
                BencodeValue::List(_) => (None, token),
                BencodeValue::Dict(_) => {
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

            let value = BencodeValue::try_from(value_token)?;

            match value {
                BencodeValue::List(_) |
                BencodeValue::Dict(_) => {
                    stack.push((key, value));
                }
                BencodeValue::Data(_) |
                BencodeValue::Integer(_) => {
                    match prev_value {
                        BencodeValue::List(list) => {
                            list.push(value);
                        }
                        BencodeValue::Dict(dict) => {
                            dict.push((key.expect("Invalid state, key expected"), value));
                        }
                        _ => panic!("Invalid state")
                    }
                }
            }
        }
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        let (root, len) = match self {
            BencodeValue::Data(s) => {
                bytes.extend(format!("{}:", s.len()).bytes());
                bytes.extend(s);
                return bytes;
            }
            BencodeValue::Integer(i) => {
                bytes.extend(format!("i{}e", i).bytes());
                return bytes;
            }
            BencodeValue::List(list) => {
                bytes.push(b'l');
                (self, list.len())
            }
            BencodeValue::Dict(dict) => {
                bytes.push(b'd');
                (self, dict.len())
            }
        };

        let mut stack: Vec<(usize, usize, &BencodeValue)> = Vec::new();
        stack.push((0, len, root));

        while let Some((index, len, value)) = stack.last_mut() {
            if *index >= *len {
                bytes.push(b'e');
                stack.pop();
                continue;
            }

            let (key, value) = match value {
                BencodeValue::List(list) => (None, &list[*index]),
                BencodeValue::Dict(dict) => (Some(&dict[*index].0), &dict[*index].1),
                _ => panic!("Invalid state")
            };
            *index += 1;

            if let Some(key) = key {
                bytes.extend(format!("{}:", key.len()).bytes());
                bytes.extend(key.bytes());
            }
            match value {
                BencodeValue::Data(s) => {
                    bytes.extend(format!("{}:", s.len()).bytes());
                    bytes.extend(s);
                }
                BencodeValue::Integer(i) => {
                    bytes.extend(format!("i{}e", i).bytes());
                }
                BencodeValue::List(list) => {
                    bytes.push(b'l');
                    stack.push((0, list.len(), value));
                }
                BencodeValue::Dict(dict) => {
                    bytes.push(b'd');
                    stack.push((0, dict.len(), value));
                }
            }
        }

        bytes
    }

    fn get_sha1(&self) -> Vec<u8> {
        let info_bytes = self.to_bytes();

        let mut hasher = Sha1::new();
        hasher.update(info_bytes);
        let result = hasher.finalize();

        result.to_vec()
    }
}

impl Display for BencodeValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            BencodeValue::Data(_) => self.get_string().unwrap(),
            BencodeValue::Integer(i) => i.to_string(),
            BencodeValue::List(list) => {
                let list: Vec<String> = list.iter()
                    .map(|v| v.to_string())
                    .collect();
                format!("[{}]", list.join(", "))
            }
            BencodeValue::Dict(dict) => {
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

impl TryFrom<ReadToken> for BencodeValue {
    type Error = Box<dyn Error>;

    fn try_from(token: ReadToken) -> Result<Self, Box<dyn Error>> {
        match token {
            ReadToken::Data(s) => Ok(BencodeValue::Data(s)),
            ReadToken::Integer(i) => Ok(BencodeValue::Integer(i)),
            ReadToken::List => Ok(BencodeValue::List(Vec::new())),
            ReadToken::Dictionary => Ok(BencodeValue::Dict(Vec::new())),
            ReadToken::End => Err("Invalid value".into()),
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

fn value_to_json(value: &BencodeValue) -> serde_json::Value {
    match value {
        BencodeValue::Data(s) => String::from_utf8_lossy(s).into(),
        BencodeValue::Integer(i) => i.clone().into(),
        BencodeValue::List(list) => {
            let list: Vec<serde_json::Value> = list.iter()
                .map(|v| value_to_json(v))
                .collect();

            list.into()
        }
        BencodeValue::Dict(dict) => {
            let dict: serde_json::Map<String, serde_json::Value> = dict.iter()
                .map(|(k, v)| (k.clone(), value_to_json(v)))
                .collect();

            dict.into()
        }
    }
}

fn read_torrent_info(torrent_file: &str) -> Result<BencodeValue, Box<dyn Error>> {
    let bytes = std::fs::read(torrent_file)?;
    let value = BencodeValue::from_bytes(&bytes)?;

    Ok(value)
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    let command = args[1].as_str();
    match command {
        "decode" => {
            let encoded_value = args[2].as_bytes();
            let decoded_value = BencodeValue::from_bytes(encoded_value)?;
            println!("{}", value_to_json(&decoded_value).to_string());
        }
        "info" => {
            let torrent_file = &args[2].as_str();
            let decoded_value = read_torrent_info(torrent_file)?;

            let tracker_url = decoded_value
                .get_by_name("announce").unwrap()
                .to_string();
            println!("Tracker URL: {}", tracker_url);

            let file_length = decoded_value
                .get_by_name("info").unwrap()
                .get_by_name("length").unwrap()
                .get_i64().unwrap();

            println!("Length: {}", file_length);

            let info = decoded_value
                .get_by_name("info").unwrap();

            let sha1 = info
                .get_sha1();
            println!("Info Hash: {}", hex::encode(sha1));

            let piece_length = info
                .get_by_name("piece length").unwrap()
                .get_i64().unwrap();
            println!("Piece Length: {}", piece_length);

            let piece_hashes = info
                .get_by_name("pieces").unwrap()
                .get_bytes().unwrap();
            let piece_hashes_count = piece_hashes.len() / 20;
            let piece_hashes: Vec<&[u8]> = piece_hashes.chunks(20).collect();
            println!("Piece Hashes:");
            for i in 0..piece_hashes_count {
                println!("{}", hex::encode(piece_hashes[i]));
            }
        }
        "peers" => {
            let torrent_file = &args[2].as_str();
            let decoded_value = read_torrent_info(torrent_file)?;

            let tracker_url = decoded_value
                .get_by_name("announce").unwrap()
                .to_string();

            let info = decoded_value
                .get_by_name("info").unwrap();

            let length = info.get_by_name("length").unwrap()
                .to_string();
            let info_sha1 = info.get_sha1();
            let info_sha1_url = info_sha1.iter().map(|b| format!("%{:02x}", b)).collect::<String>();

            let request_url = format!(
                "{}?info_hash={}&{}",
                tracker_url.as_str(),
                info_sha1_url,
                serde_urlencoded::to_string(&[
                    ("peer_id", PEER_ID),
                    ("port", "6881"),
                    ("uploaded", "0"),
                    ("downloaded", "0"),
                    ("left", length.as_str()),
                    ("compact", "1"),
                ])?
            );
            let client = reqwest::Client::new();
            let response = client.get(request_url)
                .send()
                .await?;

            if !response.status().is_success() {
                return Err("Failed to get peers".into());
            }

            let body = response.bytes().await?;
            let tracker_response = BencodeValue::from_bytes(&body)?;
            let interval = tracker_response
                .get_by_name("interval").unwrap()
                .get_i64().unwrap();
            let peers: Vec<(String, u16)> = tracker_response
                .get_by_name("peers").unwrap()
                .get_bytes().unwrap()
                .chunks(6)
                .map(|chunk| {
                    let ip = format!("{}.{}.{}.{}", chunk[0], chunk[1], chunk[2], chunk[3]);
                    let port = ((chunk[4] as u16) << 8) | chunk[5] as u16;
                    (ip, port)
                })
                .collect();

            println!("Interval: {}", interval);
            println!("Peers:");
            for (ip, port) in peers {
                println!("  {}:{}", ip, port);
            }
        }
        "handshake" => {
            let torrent_file = args[2].as_str();
            let peer_address = args[3].as_str();
            let decoded_value = read_torrent_info(torrent_file)?;
            let info_sha1 = decoded_value
                .get_by_name("info").unwrap()
                .get_sha1();

            let mut buf = BytesMut::with_capacity(68);
            buf.put_u8(19);
            buf.put_slice(b"BitTorrent protocol");
            buf.put_slice(&[0u8; 8]); // reserved
            buf.put_slice(&info_sha1);
            buf.put_slice(PEER_ID.as_bytes());

            let mut stream = tokio::net::TcpStream::connect(peer_address).await?;
            stream.write_all(&buf.split()).await?;

            buf.resize(68, 0);
            let proto_str_len = stream.read_u8().await? as usize;
            stream.read_exact(&mut buf[..proto_str_len]).await?;
            let proto_name_str = String::from_utf8(buf[..proto_str_len].to_vec()).unwrap();
            if proto_name_str != "BitTorrent protocol" {
                return Err("Invalid protocol name".into());
            }
            stream.read_exact(&mut buf[..8]).await?; // reserved
            stream.read_exact(&mut buf[..20]).await?;
            let info_sha1 = hex::encode(&buf[..20]);
            println!("Info Hash: {}", info_sha1);

            stream.read_exact(&mut buf[..20]).await?;
            let peer_id = hex::encode(&buf[..20]);
            println!("Peer ID: {}", peer_id);
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
    fn test_info_hash() {
        let torrent_file = "sample.torrent";
        let decoded_value = read_torrent_info(torrent_file).unwrap();
        let info = decoded_value
            .get_by_name("info").unwrap();

        let sha1 = info.get_sha1();
        let sha1_str = hex::encode(sha1);

        assert_eq!(sha1_str, "d69f91e6b2ae4c542468d1073a71d4ea13879a7f");
    }

    #[test]
    fn test_encode_bencoded_string() {
        let source_value = "d4:spaml1:a1:bee";
        let decoded_value = BencodeValue::from_bytes(source_value.as_bytes()).unwrap();
        let encoded_value = decoded_value.to_bytes();
        let encoded_value_str = String::from_utf8_lossy(&encoded_value);
        assert_eq!(encoded_value_str, source_value);
    }

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
        let decoded_value = BencodeValue::from_bytes(encoded_value.as_bytes()).unwrap();
        let json_decoded_value = value_to_json(&decoded_value);
        assert_eq!(json_decoded_value, serde_json::json!("spam"));
    }

    #[test]
    fn test_decode_bencoded_value_integer() {
        let encoded_value = "i52e";
        let decoded_value = BencodeValue::from_bytes(encoded_value.as_bytes()).unwrap();
        let json_decoded_value = value_to_json(&decoded_value);
        assert_eq!(json_decoded_value, serde_json::json!(52));
    }

    #[test]
    fn test_decode_bencoded_list() {
        let encoded_value = "l5:helloi52ee";
        let decoded_value = BencodeValue::from_bytes(encoded_value.as_bytes()).unwrap();
        let json_decoded_value = value_to_json(&decoded_value);
        assert_eq!(json_decoded_value, serde_json::json!(["hello", 52]));
    }

    #[test]
    fn test_decode_bencoded_list_in_dict() {
        let encoded_value = "d4:spaml1:a1:bee";
        let decoded_value = BencodeValue::from_bytes(encoded_value.as_bytes()).unwrap();
        let json_decoded_value = value_to_json(&decoded_value);
        assert_eq!(json_decoded_value, serde_json::json!({
            "spam": ["a", "b"]
        }));
    }
}