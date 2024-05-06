#![allow(dead_code)]

use std::env;
use std::error::Error;

use bytes::BytesMut;
use serde_json;
use tokio::io::AsyncWriteExt;

use crate::peer::HandShake;
use crate::torrent_data::TorrentFile;
use crate::tracker::{send_request, TrackerRequest};

mod bencode_serialization;
mod peer;
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
            let decoded_value: bencode_serialization::Value =
                serde_bencode::from_bytes(encoded_value)?;
            println!("{}", serde_json::to_string(&decoded_value)?);
        }
        "info" => {
            let torrent_filename = &args[2].as_str();
            let torrent_file = TorrentFile::from_file(torrent_filename)?;
            let info_sha1 = torrent_file.info.get_sha1();

            println!("Tracker URL: {}", torrent_file.announce);
            println!("Length: {}", torrent_file.info.length);
            println!("Info Hash: {}", info_sha1);
            println!("Piece Length: {}", torrent_file.info.piece_length);

            println!("Piece Hashes:");
            for piece in torrent_file.info.pieces {
                println!("  {}", piece);
            }
        }
        "peers" => {
            let torrent_filename = &args[2].as_str();
            let torrent_file = TorrentFile::from_file(torrent_filename)?;
            let tracker_request = TrackerRequest {
                info_hash: torrent_file.info.get_sha1(),
                peer_id: PEER_ID.to_string(),
                port: 6881,
                uploaded: 0,
                downloaded: 0,
                left: torrent_file.info.length as u64,
            };
            let tracker_response =
                send_request(tracker_request, torrent_file.announce.as_str()).await?;

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
            let mut buf = BytesMut::with_capacity(256);
            let request = HandShake::new(torrent_file.info.get_sha1(), PEER_ID.as_bytes().into());
            let mut stream = tokio::net::TcpStream::connect(peer_address).await?;

            request.write(&mut buf);
            stream.write_all(&buf.split()).await?;

            let response = HandShake::read_async(&mut stream, &mut buf).await?;
            println!("Peer ID: {}", response.peer_id);
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
        let info_sha1_str = torrent_file.info.get_sha1().to_string();

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

    #[test]
    fn test_decode_bencoded_list() {
        let encoded_value = "l5:helloi52ee";
        let decoded_value: bencode_serialization::Value =
            serde_bencode::from_str(encoded_value).unwrap();
        let json_decoded_value = serde_json::to_value(&decoded_value).unwrap();
        assert_eq!(json_decoded_value, serde_json::json!(["hello", 52]));
    }

    #[test]
    fn test_decode_bencoded_list_in_dict() {
        let encoded_value = "d4:spaml1:a1:bee";
        let decoded_value: bencode_serialization::Value =
            serde_bencode::from_str(encoded_value).unwrap();
        let json_decoded_value = serde_json::to_value(&decoded_value).unwrap();
        assert_eq!(
            json_decoded_value,
            serde_json::json!({
                "spam": ["a", "b"]
            })
        );
    }
}
