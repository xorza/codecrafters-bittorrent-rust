#![allow(dead_code)]

use std::env;
use std::error::Error;

use bytes::{BufMut, BytesMut};
use serde_json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::torrent_data::TorrentFile;
use crate::tracker::TrackerResponse;
use crate::utils::get_bytes_sha1;

mod torrent_data;
mod tracker;
mod utils;

const PEER_ID: &str = "01234567890123456789";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    let command = args[1].as_str();
    match command {
        "decode" => {
            let encoded_value = args[2].as_bytes();
            let decoded_value = serde_bencode::from_bytes(encoded_value)?;
            println!("{}", serde_json::to_string(&decoded_value)?);
        }
        "info" => {
            let torrent_filename = &args[2].as_str();
            let torrent_file = TorrentFile::from_file(torrent_filename)?;

            println!("Tracker URL: {}", torrent_file.announce);
            println!("Length: {}", torrent_file.info.length);

            let info_bencode = serde_bencode::to_bytes(&torrent_file.info)?;
            let info_sha1 = get_bytes_sha1(&info_bencode);

            println!("Info Hash: {}", hex::encode(info_sha1));
            println!("Piece Length: {}", torrent_file.info.piece_length);

            println!("Piece Hashes:");
            for piece in torrent_file.info.pieces {
                println!("  {}", hex::encode(piece));
            }
        }
        "peers" => {
            let torrent_filename = &args[2].as_str();
            let torrent_file = TorrentFile::from_file(torrent_filename)?;

            let info_sha1 = torrent_file.info.get_sha1();
            let info_sha1_url = info_sha1
                .iter()
                .map(|b| format!("%{:02x}", b))
                .collect::<String>();

            let request_url = format!(
                "{}?info_hash={}&{}",
                torrent_file.announce.as_str(),
                info_sha1_url,
                serde_urlencoded::to_string(&[
                    ("peer_id", PEER_ID),
                    ("port", "6881"),
                    ("uploaded", "0"),
                    ("downloaded", "0"),
                    ("left", torrent_file.info.length.to_string().as_str()),
                    ("compact", "1"),
                ])?
            );
            let client = reqwest::Client::new();
            let response = client.get(request_url).send().await?;

            if !response.status().is_success() {
                return Err("Failed to get peers".into());
            }

            let bytes = response.bytes().await?;
            let tracker_response: TrackerResponse = serde_bencode::from_bytes(&bytes)?;

            println!("Interval: {}", tracker_response.interval);
            println!("Peers:");
            for (ip, port) in tracker_response.peers {
                println!("  {}:{}", ip, port);
            }
        }
        "handshake" => {
            let torrent_filename = args[2].as_str();
            let peer_address = args[3].as_str();

            let torrent_file = TorrentFile::from_file(torrent_filename)?;
            let info_sha1 = torrent_file.info.get_sha1();

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
        let torrent_filename = "sample.torrent";
        let torrent_file = TorrentFile::from_file(torrent_filename).unwrap();
        let info_sha1_str = hex::encode(torrent_file.info.get_sha1());

        assert_eq!(info_sha1_str, "d69f91e6b2ae4c542468d1073a71d4ea13879a7f");
    }

    #[test]
    fn test_decode_torrent_file() {
        let torrent_filename = "sample.torrent";
        let mut torrent_file = TorrentFile::from_file(torrent_filename).unwrap();
        torrent_file.info.pieces.clear();

        let json_decoded_value = serde_json::to_value(&torrent_file).unwrap();

        assert_eq!(
            json_decoded_value,
            serde_json::json!({
                "announce": "http://bittorrent-test-tracker.codecrafters.io/announce",
                "created by": "mktorrent 1.1",
                "info": {
                    "length": 92063,
                    "name": "sample.txt",
                    "piece length": 32768,
                    "pieces": []
                }
            })
        );

        assert_eq!(
            torrent_file.announce,
            "http://bittorrent-test-tracker.codecrafters.io/announce"
        );
        assert_eq!(torrent_file.info.length, 92063);
    }

    #[test]
    fn test_decode_bencoded_value_string() {
        let encoded_value = "4:spam";
        let decoded_value: String = serde_bencode::from_bytes(encoded_value.as_bytes()).unwrap();
        let json_decoded_value = serde_json::to_value(&decoded_value).unwrap();
        assert_eq!(json_decoded_value, serde_json::json!("spam"));
    }

    #[test]
    fn test_decode_bencoded_value_integer() {
        let encoded_value = "i52e";
        let decoded_value: i64 = serde_bencode::from_bytes(encoded_value.as_bytes()).unwrap();
        let json_decoded_value = serde_json::to_value(&decoded_value).unwrap();
        assert_eq!(json_decoded_value, serde_json::json!(52));
    }

    // #[test]
    // fn test_decode_bencoded_list() {
    //     let encoded_value = "l5:helloi52ee";
    //     let decoded_value = serde_bencode::from_bytes(encoded_value.as_bytes()).unwrap();
    //     let json_decoded_value = serde_json::to_value(&decoded_value).unwrap();
    //     assert_eq!(json_decoded_value, serde_json::json!(["hello", 52]));
    // }
    //
    // #[test]
    // fn test_decode_bencoded_list_in_dict() {
    //     let encoded_value = "d4:spaml1:a1:bee";
    //     let decoded_value = serde_bencode::from_bytes(encoded_value.as_bytes()).unwrap();
    //     let json_decoded_value = serde_json::to_value(&decoded_value).unwrap();
    //     assert_eq!(json_decoded_value, serde_json::json!({
    //         "spam": ["a", "b"]
    //     }));
    // }
}
